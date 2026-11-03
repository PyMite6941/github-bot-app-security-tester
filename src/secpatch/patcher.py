"""Minimal unified-diff applier and patch validator.

Patches are applied in an isolated copy of the repository; the original
working tree is never modified until validation succeeds.
"""
from __future__ import annotations

import compileall
import difflib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ValidationResult:
    applied: bool
    tests_passed: Optional[bool]
    message: str


class DiffError(Exception):
    pass


def _parse_diff(diff_text: str) -> dict[str, list[tuple]]:
    """Parse a unified diff into {file_path: [hunks]}.

    Each hunk: (old_start, old_count, new_start, new_count, [lines])
    where lines keep their leading ' ', '-', '+' markers.
    """
    files: dict[str, list[tuple]] = {}
    current_file: Optional[str] = None
    hunks: list[tuple] = []
    lines = diff_text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("--- "):
            if current_file is not None and hunks:
                files.setdefault(current_file, []).extend(hunks)
                hunks = []
            current_file = line[4:].strip()
            i += 1
            continue
        if line.startswith("@@") and current_file is not None:
            # @@ -old_start[,old_count] +new_start[,new_count] @@
            header = line[3:].split(" @@", 1)[0]
            old_part = header.split(" ", 1)[0]
            old_start = int(old_part.split(",")[0][1:])
            hunk_lines: list[str] = []
            i += 1
            while i < len(lines) and lines[i][:1] in (" ", "-", "+", "\\"):
                hunk_lines.append(lines[i])
                i += 1
            hunks.append((old_start, len(hunk_lines), 0, 0, hunk_lines))
            continue
        i += 1
    if current_file is not None and hunks:
        files.setdefault(current_file, []).extend(hunks)
    return files


def apply_diff_to_file(file_path: str, diff_text: str) -> None:
    """Apply a unified diff to a single file in place. Raises DiffError on mismatch."""
    path = Path(file_path)
    text = path.read_text(encoding="utf-8", errors="ignore")
    had_trailing_newline = text.endswith("\n")
    original = text.splitlines()
    parsed = _parse_diff(diff_text)
    name = path.name
    target = None
    for key in parsed.keys():
        if key == name or key.split("/")[-1] == name or key.split("\\")[-1] == name:
            target = key
            break
    if target is None:
        raise DiffError(f"diff does not contain file {name}")
    new_lines: list[str] = []
    cursor = 0
    for (old_start, _old_count, _new_start, _new_count, hunk_lines) in parsed[target]:
        start = max(0, old_start - 1)
        start = min(start, len(original))
        new_lines.extend(original[cursor:start])
        cursor = start
        for hline in hunk_lines:
            code = (hline[1:] if len(hline) > 1 else "").rstrip("\n")
            if hline.startswith(" "):
                if cursor >= len(original) or original[cursor] != code:
                    raise DiffError(
                        f"context mismatch at line {cursor + 1}: expected {code!r}, "
                        f"got {original[cursor] if cursor < len(original) else 'EOF'}!r"
                    )
                new_lines.append(code)
                cursor += 1
            elif hline.startswith("-"):
                if cursor >= len(original) or original[cursor] != code:
                    raise DiffError(
                        f"removal mismatch at line {cursor + 1}: expected {code!r}, "
                        f"got {original[cursor] if cursor < len(original) else 'EOF'}!r"
                    )
                cursor += 1
            elif hline.startswith("+"):
                new_lines.append(code)
            elif hline.startswith("\\"):
                continue  # no newline at end of file marker
    new_lines.extend(original[cursor:])
    path.write_text(
        "\n".join(new_lines) + ("\n" if had_trailing_newline else ""),
        encoding="utf-8",
    )


@dataclass
class PatchResult:
    file_path: str
    diff: str
    applied: bool
    validated: bool
    message: str


class Patcher:
    """Draft a fix for a finding (AI or template), validate it, then apply."""

    def __init__(self, ai_client=None) -> None:
        self.ai = ai_client

    def draft(self, file_path: str, finding) -> Optional[str]:
        if self.ai is not None and self.ai.available():
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                code = fh.read()
            draft = self.ai.draft_patch(file_path, code, finding)
            return draft.diff if draft else None
        return self._template_patch(file_path, finding)

    def _template_patch(self, file_path: str, finding) -> Optional[str]:
        """Deterministic fixes for a small safe subset of rules (no AI)."""
        import re

        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()

        old_lines = content.splitlines()
        new_lines = list(old_lines)
        idx = finding.line - 1
        applied_fix = False

        if finding.rule_id == "SEC-EVAL-USAGE" and 0 <= idx < len(new_lines):
            line = new_lines[idx]
            new_line = re.sub(r"\beval\s*\(", "ast.literal_eval(", line)
            if new_line != line:
                new_lines[idx] = new_line
                if not any("import ast" in l for l in new_lines):
                    new_lines.insert(0, "import ast")
                applied_fix = True

        if finding.rule_id == "SEC-HARDCODED-SECRET" and 0 <= idx < len(new_lines):
            line = new_lines[idx]
            m = re.match(r"(\s*)([A-Za-z_]\w*)\s*=\s*['\"].+['\"]\s*(#.*)?$", line)
            if m:
                indent, var, comment = m.group(1), m.group(2), m.group(3) or ""
                new_lines[idx] = f'{indent}{var} = os.environ.get("{var.upper()}"){comment}'
                if not any("import os" in l for l in new_lines):
                    new_lines.insert(0, "import os")
                applied_fix = True

        if not applied_fix:
            return None  # no safe template for this rule

        new_text = "\n".join(new_lines)
        if new_text == content:
            return None
        diff = "\n".join(
            difflib.unified_diff(
                old_lines,
                new_text.splitlines(),
                fromfile=f"a/{Path(file_path).name}",
                tofile=f"b/{Path(file_path).name}",
                lineterm="",
            )
        )
        return diff or None

    def validate(self, repo_root: str, file_path: str, diff: str,
                 test_cmd: Optional[str] = None) -> ValidationResult:
        """Copy repo to a temp dir, apply the diff, run compileall + tests."""
        tmp = tempfile.mkdtemp(prefix="secpatch-validate-")
        try:
            # Copy the repo (skip caches / git internals to keep it light).
            for entry in os.listdir(repo_root):
                src = os.path.join(repo_root, entry)
                dst = os.path.join(tmp, entry)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
                        ".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", "dist", "build"
                    ))
                else:
                    shutil.copy2(src, dst)
            target = os.path.join(tmp, file_path)
            if not os.path.exists(target):
                return ValidationResult(False, None, f"file {file_path} not found in repo copy")
            apply_diff_to_file(target, diff)
            # Syntax check.
            ok = compileall.compile_file(target, quiet=1)
            if not ok:
                return ValidationResult(True, None, f"patched file {file_path} has syntax errors")
            tests_passed = None
            if test_cmd:
                result = subprocess.run(
                    test_cmd, shell=True, cwd=tmp,
                    capture_output=True, text=True, timeout=300,
                )
                tests_passed = result.returncode == 0
                msg = f"tests {'passed' if tests_passed else 'failed'} ({test_cmd})"
                if not tests_passed and result.stderr:
                    msg += f"\n{result.stderr[-800:]}"
                return ValidationResult(True, tests_passed, msg)
            return ValidationResult(True, None, "patched file compiles cleanly")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def apply_to_working_tree(self, file_path: str, diff: str) -> None:
        apply_diff_to_file(file_path, diff)
