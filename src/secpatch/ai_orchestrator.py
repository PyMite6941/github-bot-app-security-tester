"""AI-powered patch orchestration with context gathering and iteration.

Instead of a one-shot diff request, the orchestrator:

1. Locates the vulnerable function/class and its imports (context).
2. Asks the AI for a minimal unified diff plus an explanation.
3. Applies the diff in a sandbox and runs the test command.
4. If validation fails, feeds the error back to the AI and retries
   (up to max_iterations), producing an increasingly informed fix.

Requires SECPATCH_AI_API_KEY (and optionally SECPATCH_AI_BASE_URL,
SECPATCH_AI_MODEL). Falls back to the deterministic template patcher.
"""
from __future__ import annotations

import ast
import os
import re
from typing import Optional

from .ai_client import AIClient, PatchDraft
from .advanced_detector import Finding
from .method_analyzer import analyze_file
from .patcher import Patcher, apply_diff_to_file
from .sandbox import Sandbox, SandboxResult


class AIOrchestrator:
    def __init__(
        self,
        ai_client: Optional[AIClient] = None,
        patcher: Optional[Patcher] = None,
        max_iterations: int = 3,
        timeout: int = 120,
    ) -> None:
        self.ai = ai_client or AIClient()
        self.patcher = patcher or Patcher(ai_client=self.ai)
        self.max_iterations = max_iterations
        self.timeout = timeout

    def available(self) -> bool:
        return self.ai.available()

    def _gather_context(self, file_path: str, line: int) -> dict:
        """Extract the enclosing function/class and imports around a finding."""
        module = analyze_file(file_path)
        context: dict = {"imports": module.imports, "enclosing": None, "source": ""}
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return context

        # Find enclosing function/class for the finding line.
        enclosing_start = 0
        enclosing_end = len(lines)
        for cls in module.classes:
            if cls.line <= line <= cls.end_line:
                context["enclosing"] = f"class {cls.name}"
                enclosing_start = cls.line - 1
                enclosing_end = cls.end_line
                for m in cls.methods:
                    if m.line <= line <= m.end_line:
                        context["enclosing"] = f"method {cls.name}.{m.name}"
                        enclosing_start = m.line - 1
                        enclosing_end = m.end_line
                        break
                break
        for fn in module.functions:
            if fn.line <= line <= fn.end_line:
                context["enclosing"] = f"function {fn.name}"
                enclosing_start = fn.line - 1
                enclosing_end = fn.end_line
                break

        context["source"] = "".join(lines[enclosing_start:enclosing_end])
        return context

    def _build_prompt(
        self, file_path: str, finding: Finding, context: dict, previous_error: Optional[str] = None
    ) -> str:
        lines = [
            "You are a senior security engineer. Produce ONE unified diff that fixes the "
            "vulnerability below. Output ONLY the diff - no markdown fences, no explanation.",
            "Rules:",
            "  - Header: --- a/<file> then +++ b/<file>",
            "  - One hunk, three lines of context, exact line numbers.",
            "  - Fix ONLY the reported vulnerability; do not refactor unrelated code.",
            "  - Prefer parameterised queries, input validation, escaping, or removing dangerous calls.",
            "",
            f"File: {file_path}",
            f"Vulnerability: {finding.title} ({finding.rule_id})",
            f"Severity: {finding.severity}",
            f"Location: line {finding.line}",
            f"Fix hint: {finding.fix_hint}",
            f"Enclosing code: {context.get('enclosing', 'module level')}",
            "",
            "Enclosing source context:",
            context.get("source", ""),
            "",
            "Imports available:",
            ", ".join(context.get("imports", [])) or "(none)",
        ]
        if previous_error:
            lines += [
                "",
                "PREVIOUS ATTEMPT FAILED:",
                previous_error,
                "Revise the diff to address the failure above.",
            ]
        lines += ["", "Return the unified diff now:"]
        return "\n".join(lines)

    def draft_with_context(
        self, file_path: str, finding: Finding, previous_error: Optional[str] = None
    ) -> Optional[PatchDraft]:
        if not self.available():
            return None
        context = self._gather_context(file_path, finding.line)
        prompt = self._build_prompt(file_path, finding, context, previous_error)
        body = {
            "model": self.ai.model,
            "messages": [
                {"role": "system", "content": "You output only valid unified diffs."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1500,
        }
        import json
        import urllib.error
        import urllib.request

        url = f"{self.ai.base_url}/chat/completions"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.ai.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.ai.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"[secpatch-ai] request failed: {exc}")
            return None
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            print(f"[secpatch-ai] unexpected response: {payload!r}")
            return None
        diff = self._extract_diff(content)
        return PatchDraft(file_path=file_path, diff=diff, model=self.ai.model)

    @staticmethod
    def _extract_diff(content: str) -> str:
        text = content.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else ""
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
        return text.strip()

    def patch_with_validation(
        self, repo_root: str, file_path: str, finding: Finding, test_cmd: Optional[str] = None
    ) -> dict:
        """Try template patch first, then AI with iteration + sandbox validation."""
        result: dict = {
            "file": file_path,
            "finding": finding.rule_id,
            "applied": False,
            "validated": False,
            "iterations": 0,
            "message": "",
            "diff": None,
        }

        abs_file = os.path.abspath(file_path)

        # 1) Deterministic template patch (safe subset of rules).
        template_diff = self.patcher._template_patch(abs_file, finding)
        if template_diff:
            sandbox = Sandbox(repo_root, timeout=self.timeout)
            validation = sandbox_copy_validate(sandbox, abs_file, template_diff, test_cmd)
            result["iterations"] = 1
            result["diff"] = template_diff
            if validation["applied"] and validation["validated"]:
                apply_diff_to_file(abs_file, template_diff)
                result["applied"] = True
                result["validated"] = True
                result["message"] = "template patch applied and validated"
                return result
            result["message"] = f"template patch failed validation: {validation['message']}"

        # 2) AI-powered patch with iteration.
        if not self.available():
            result["message"] += "; no AI key configured (set SECPATCH_AI_API_KEY)"
            return result

        previous_error: Optional[str] = None
        for i in range(1, self.max_iterations + 1):
            draft = self.draft_with_context(abs_file, finding, previous_error)
            if not draft or not draft.diff:
                result["message"] = "AI produced no usable diff"
                return result
            result["diff"] = draft.diff
            result["iterations"] = i
            sandbox = Sandbox(repo_root, timeout=self.timeout)
            validation = sandbox_copy_validate(sandbox, abs_file, draft.diff, test_cmd)
            if validation["applied"] and validation["validated"]:
                apply_diff_to_file(abs_file, draft.diff)
                result["applied"] = True
                result["validated"] = True
                result["message"] = f"AI patch validated after {i} iteration(s)"
                return result
            previous_error = validation["message"]

        result["message"] = f"AI patch failed validation after {self.max_iterations} iteration(s): {previous_error}"
        return result


def sandbox_copy_validate(
    sandbox: Sandbox, abs_file: str, diff: str, test_cmd: Optional[str]
) -> dict:
    """Copy repo, apply diff in sandbox, run syntax + tests."""
    import tempfile
    from pathlib import Path

    tmp = sandbox.copy_to_temp()
    try:
        target = os.path.join(tmp, os.path.relpath(abs_file, sandbox.repo_root))
        if not os.path.exists(target):
            return {"applied": False, "validated": False, "message": f"file not found in copy: {target}"}
        apply_diff_to_file(target, diff)
        import compileall

        if not compileall.compile_file(target, quiet=1):
            return {"applied": True, "validated": False, "message": "syntax error after patch"}
        if test_cmd:
            res = sandbox.run(test_cmd, cwd=tmp, timeout=180)
            if res.timed_out:
                return {"applied": True, "validated": False, "message": "test command timed out"}
            if res.exit_code != 0:
                return {
                    "applied": True,
                    "validated": False,
                    "message": f"tests failed: {res.stderr[-600:] or res.stdout[-600:]}",
                }
        return {"applied": True, "validated": True, "message": "patched file compiles and tests pass"}
    finally:
        sandbox.cleanup(tmp)
