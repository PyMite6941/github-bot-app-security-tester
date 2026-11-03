"""Expanded, multi-language vulnerability detector.

Adds rules for insecure deserialization, weak crypto, insecure random,
path traversal, XXE, insecure cookies, SQLi in more forms, and
JavaScript/TypeScript issues (innerHTML, eval, dangerous URL handling).
"""
from __future__ import annotations

import ast
import os
import re
from typing import Optional

from .detector import Finding, SEVERITY_ORDER, SKIP_DIRS

# (rule_id, title, severity, compiled_regex, fix_hint)
REGEX_RULES = [
    (
        "SEC-HARDCODED-SECRET",
        "Hardcoded secret or credential",
        "high",
        re.compile(
            r"(?i)(api[_-]?key|secret|secret_key|password|passwd|private_key|access_token|auth_token)\s*[:=]\s*['\"][^'\"]{3,}['\"]"
        ),
        "Move the value into an environment variable or secret manager; never commit it to source control.",
    ),
    (
        "SEC-EVAL-USAGE",
        "Use of eval() / exec()",
        "critical",
        re.compile(r"\b(eval|exec)\s*\("),
        "Avoid eval/exec. Use ast.literal_eval() for trusted literals or a safe expression parser.",
    ),
    (
        "SEC-SHELL-TRUE",
        "subprocess called with shell=True",
        "high",
        re.compile(r"\bshell\s*=\s*True"),
        "Use a list of arguments with shell=False; sanitize inputs with shlex.quote() if a shell is required.",
    ),
    (
        "SEC-DYNAMIC-SQL",
        "SQL statement built with string concatenation",
        "critical",
        re.compile(
            r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|MERGE)\b[^;]*\s*\+\s*|['\"]\s*\+\s*[^;]*\b(SELECT|INSERT|UPDATE|DELETE)\b"
        ),
        "Use parameterised queries with placeholders (? / %s) instead of building SQL with + or f-strings.",
    ),
    (
        "SEC-INNERHTML-CONCAT",
        "innerHTML assigned from a concatenated string",
        "high",
        re.compile(r"\.innerHTML\s*=\s*.*['\"].*\s*\+\s*"),
        "Use textContent or an auto-escaping template engine; sanitise user-controlled input.",
    ),
    (
        "SEC-PICKLE-LOAD",
        "Insecure deserialization with pickle.load",
        "critical",
        re.compile(r"\bpickle\.load\s*\("),
        "Never unpickle untrusted data. Use JSON or a safe serialization format.",
    ),
    (
        "SEC-WEAK-CRYPTO",
        "Use of weak cryptographic algorithm",
        "high",
        re.compile(r"\b(md5|sha1|des|rc4)\b", re.IGNORECASE),
        "Use SHA-256+ or bcrypt/argon2 for passwords; avoid MD5/SHA1/DES/RC4.",
    ),
    (
        "SEC-INSECURE-RANDOM",
        "Use of non-cryptographic random()",
        "medium",
        re.compile(r"\brandom\.(random|randint|choice|seed)\s*\("),
        "Use secrets module (secrets.token_*, secrets.choice) for security-sensitive randomness.",
    ),
    (
        "SEC-PATH-TRAVERSAL",
        "Potential path traversal via user input",
        "high",
        re.compile(r"\b(open|os\.path\.join|Path)\s*\(.*\+\s*|f[\"'].*\{.*\}.*[\"']\s*\)", re.IGNORECASE),
        "Validate and canonicalize paths; ensure resolved path stays inside the intended directory.",
    ),
    (
        "SEC-XXE",
        "XML parsing without disabling external entities",
        "high",
        re.compile(r"\b(etree\.parse|xml\.etree|minidom\.parse|sax\.parse)\s*\("),
        "Disable DTD/external entities (defusedxml) or use a defused XML parser.",
    ),
    (
        "SEC-INSECURE-COOKIE",
        "Cookie set without Secure/HttpOnly flags",
        "medium",
        re.compile(r"\bset_cookie\s*\(|response\.set_header\s*\(\s*['\"]Set-Cookie['\"]", re.IGNORECASE),
        "Set Secure, HttpOnly, and SameSite=Strict/Lax on all session cookies.",
    ),
    (
        "SEC-DANGEROUS-EVAL-JS",
        "JavaScript eval() / setTimeout(string)",
        "critical",
        re.compile(r"\b(eval|setTimeout|setInterval)\s*\(\s*['\"]"),
        "Never evaluate strings as code in JavaScript; use JSON.parse or function references.",
    ),
    (
        "SEC-INNERHTML-ASSIGN",
        "innerHTML assigned from potentially unsanitized source",
        "high",
        re.compile(r"\.innerHTML\s*="),
        "Use textContent or sanitize HTML with DOMPurify before assigning to innerHTML.",
    ),
]


class _PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, src: str) -> None:
        self.filename = filename
        self.lines = src.splitlines()
        self.findings: list[Finding] = []
        self.tainted: dict[str, bool] = {}

    def _snip(self, node) -> str:
        if 0 < node.lineno <= len(self.lines):
            return self.lines[node.lineno - 1].strip()
        return ""

    def visit_Assign(self, node: ast.Assign) -> None:
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and self._is_tainted_value(node.value)
        ):
            self.tainted[node.targets[0].id] = True
        self.generic_visit(node)

    @staticmethod
    def _is_tainted_value(node) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and any(
            isinstance(n, ast.FormattedValue) for n in ast.walk(node)
        ):
            return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            self.findings.append(
                Finding(
                    "SEC-EVAL-USAGE",
                    f"Use of {node.func.id}()",
                    "critical",
                    self.filename,
                    node.lineno,
                    self._snip(node),
                    f"Replace {node.func.id}() with ast.literal_eval() or a validated parser.",
                )
            )
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "execute",
            "executemany",
        }:
            for arg in node.args:
                if isinstance(arg, ast.Name) and self.tainted.get(arg.id):
                    self.findings.append(
                        Finding(
                            "SEC-SQLI-FSTRING",
                            "SQL query built with an f-string",
                            "critical",
                            self.filename,
                            node.lineno,
                            self._snip(node),
                            "Use parameterised queries (placeholders) instead of f-strings in SQL.",
                        )
                    )
                    break
                if isinstance(arg, ast.JoinedStr):
                    self.findings.append(
                        Finding(
                            "SEC-SQLI-FSTRING",
                            "SQL query built with an f-string",
                            "critical",
                            self.filename,
                            node.lineno,
                            self._snip(node),
                            "Use parameterised queries (placeholders) instead of f-strings in SQL.",
                        )
                    )
                    break
        self.generic_visit(node)


class AdvancedDetector:
    def __init__(self, extra_rules: Optional[list] = None) -> None:
        self.regex_rules = list(REGEX_RULES) + list(extra_rules or [])

    def scan_path(self, root: str) -> list[Finding]:
        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                if not self._is_scannable(name):
                    continue
                findings.extend(self.scan_file(os.path.join(dirpath, name)))
        findings.sort(
            key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line)
        )
        return findings

    def scan_file(self, path: str) -> list[Finding]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                src = fh.read()
        except OSError:
            return []

        findings: list[Finding] = []
        lines = src.splitlines()

        for rule_id, title, severity, pattern, hint in self.regex_rules:
            for idx, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append(Finding(rule_id, title, severity, path, idx, line.strip(), hint))

        if path.endswith(".py"):
            try:
                tree = ast.parse(src, filename=path)
            except SyntaxError:
                pass
            else:
                visitor = _PythonASTVisitor(path, src)
                visitor.visit(tree)
                findings.extend(visitor.findings)

        # Deduplicate identical findings.
        seen: set[tuple[str, str, int]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.file, f.line)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        return unique

    @staticmethod
    def _is_scannable(name: str) -> bool:
        skip_ext = {".md", ".rst", ".txt", ".html", ".htm", ".css", ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".lock"}
        return not name.endswith(tuple(skip_ext))
