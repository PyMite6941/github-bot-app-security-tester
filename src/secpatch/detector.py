"""Static vulnerability detector.

Combines language-agnostic regex rules with Python AST rules to find
security flaws.  Produces :class:`Finding` objects consumed by the CLI,
the patcher, and CI.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from typing import Optional

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
    "dist", "build", ".tox",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    fix_hint: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "fix_hint": self.fix_hint,
        }


# (rule_id, title, severity, compiled_regex, fix_hint)
REGEX_RULES = [
    (
        "SEC-HARDCODED-SECRET",
        "Hardcoded secret or credential",
        "high",
        __import__("re").compile(
            r"(?i)(api[_-]?key|secret|secret_key|password|passwd|private_key|access_token)\s*[:=]\s*['\"][^'\"]{3,}['\"]"
        ),
        "Move the value into an environment variable or secret manager; never commit it to source control.",
    ),
    (
        "SEC-EVAL-USAGE",
        "Use of eval() / exec()",
        "critical",
        __import__("re").compile(r"\b(eval|exec)\s*\("),
        "Avoid eval/exec. Use ast.literal_eval() for trusted literals or a safe expression parser.",
    ),
    (
        "SEC-SHELL-TRUE",
        "subprocess called with shell=True",
        "high",
        __import__("re").compile(r"\bshell\s*=\s*True"),
        "Use a list of arguments with shell=False; sanitize inputs with shlex.quote() if a shell is required.",
    ),
    (
        "SEC-DYNAMIC-SQL",
        "SQL statement built with string concatenation",
        "critical",
        __import__("re").compile(
            r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|MERGE)\b[^;]*\s*\+\s*|['\"]\s*\+\s*[^;]*\b(SELECT|INSERT|UPDATE|DELETE)\b"
        ),
        "Use parameterised queries with placeholders (? / %s) instead of building SQL with + or f-strings.",
    ),
    (
        "SEC-INNERHTML-CONCAT",
        "innerHTML assigned from a concatenated string",
        "high",
        __import__("re").compile(r"\.innerHTML\s*=\s*.*['\"].*\s*\+\s*"),
        "Use textContent or an auto-escaping template engine; sanitise user-controlled input.",
    ),
]


class _PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, src: str) -> None:
        self.filename = filename
        self.lines = src.splitlines()
        self.findings: list[Finding] = []
        self.tainted: dict[str, bool] = {}

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
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.BinOp) and any(
            isinstance(n, ast.FormattedValue) for n in ast.walk(node)
        ):
            return True
        return False

    def _snip(self, node) -> str:
        if 0 < node.lineno <= len(self.lines):
            return self.lines[node.lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        # eval(...) / exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            self.findings.append(Finding(
                "SEC-EVAL-USAGE",
                f"Use of {node.func.id}()",
                "critical",
                self.filename,
                node.lineno,
                self._snip(node),
                f"Replace {node.func.id}() with ast.literal_eval() or a validated parser.",
            ))
        # db.execute("...f-string...") -> SQL injection
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"}:
            for arg in node.args:
                if isinstance(arg, ast.Name) and self.tainted.get(arg.id):
                    self.findings.append(Finding(
                        "SEC-SQLI-FSTRING",
                        "SQL query built with an f-string",
                        "critical",
                        self.filename,
                        node.lineno,
                        self._snip(node),
                        "Use parameterised queries (placeholders) instead of f-strings in SQL.",
                    ))
                    break
                if isinstance(arg, ast.JoinedStr):  # f-string passed to execute
                    self.findings.append(Finding(
                        "SEC-SQLI-FSTRING",
                        "SQL query built with an f-string",
                        "critical",
                        self.filename,
                        node.lineno,
                        self._snip(node),
                        "Use parameterised queries (placeholders) instead of f-strings in SQL.",
                    ))
                    break
                if isinstance(arg, ast.BinOp) and any(
                    isinstance(n, ast.FormattedValue) for n in ast.walk(arg)
                ):
                    self.findings.append(Finding(
                        "SEC-SQLI-CONCAT",
                        "SQL query built with string concatenation",
                        "critical",
                        self.filename,
                        node.lineno,
                        self._snip(node),
                        "Use parameterised queries (placeholders) instead of string concatenation in SQL.",
                    ))
                    break
        self.generic_visit(node)


class Detector:
    """Scan files or directories for security vulnerabilities."""

    def __init__(self, extra_rules: Optional[list] = None) -> None:
        self.regex_rules = list(REGEX_RULES) + list(extra_rules or [])

    def scan_path(self, root: str) -> list[Finding]:
        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(
                d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")
            )
            for name in sorted(filenames):
                if name.endswith((".md", ".rst", ".txt", ".html", ".htm", ".css")):
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

        # Regex rules, evaluated line by line.
        for rule_id, title, severity, pattern, hint in self.regex_rules:
            for idx, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append(Finding(rule_id, title, severity, path, idx, line.strip(), hint))

        # Python AST rules (deeper, context-aware analysis).
        if path.endswith(".py"):
            try:
                tree = ast.parse(src, filename=path)
            except SyntaxError:
                pass
            else:
                visitor = _PythonASTVisitor(path, src)
                visitor.visit(tree)
                findings.extend(visitor.findings)

        # Deduplicate identical findings (regex and AST can both flag eval()).
        seen: set[tuple[str, str, int]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.file, f.line)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        return unique
