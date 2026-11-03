"""Optional AI client that drafts patches via an OpenAI-compatible chat API.

Works with GitHub Models (https://github.com/marketplace/models), Azure OpenAI,
OpenAI, or any local OpenAI-compatible endpoint (Ollama, LM Studio, ...).
Configure with the SECPATCH_AI_API_KEY, SECPATCH_AI_BASE_URL and
SECPATCH_AI_MODEL environment variables (or pass them explicitly).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


DEFAULT_BASE_URL = "https://models.inference.ai.azure.com"
DEFAULT_MODEL = "gpt-4o"


@dataclass
class PatchDraft:
    file_path: str
    diff: str
    model: str


class AIClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self.api_key = api_key or os.getenv("SECPATCH_AI_API_KEY")
        self.base_url = (base_url or os.getenv("SECPATCH_AI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.model = model or os.getenv("SECPATCH_AI_MODEL") or DEFAULT_MODEL
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.api_key)

    def draft_patch(self, file_path: str, original_code: str, finding) -> Optional[PatchDraft]:
        """Ask the AI for a unified diff that fixes the finding.

        Returns None when no API key is configured or the request fails.
        """
        if not self.available():
            return None

        prompt = (
            "You are a senior security engineer. Produce ONE unified diff that fixes the "
            "vulnerability described below. Output ONLY the diff - no markdown fences, no "
            "explanation, no extra text.\n"
            "Rules:\n"
            "  - Header: --- a/<file_path>  then  +++ b/<file_path>\n"
            "  - One hunk, three lines of context, exact line numbers.\n"
            "  - Fix ONLY the reported vulnerability; do not refactor unrelated code.\n"
            "  - Prefer parameterised queries, input validation, escaping, or removing dangerous calls.\n\n"
            f"File: {file_path}\n"
            f"Vulnerability: {finding.title} ({finding.rule_id})\n"
            f"Severity: {finding.severity}\n"
            f"Location: line {finding.line}\n"
            f"Fix hint: {finding.fix_hint}\n\n"
            "Current file content:\n"
            f"{original_code}\n"
            "Return the unified diff now:\n"
        )

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You output only valid unified diffs."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 1500,
        }

        url = f"{self.base_url}/chat/completions"
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"[secpatch] AI request failed: {exc}")
            return None

        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            print(f"[secpatch] Unexpected AI response: {payload!r}")
            return None

        return PatchDraft(file_path=file_path, diff=self._extract_diff(content), model=self.model)

    @staticmethod
    def _extract_diff(content: str) -> str:
        """Strip any accidental markdown fences around the diff."""
        text = content.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else ""
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
        return text.strip()
