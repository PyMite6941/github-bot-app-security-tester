"""Analyse git commit history for security-relevant changes.

Looks for commits whose messages or diffs mention security fixes
(CVE, patch, vuln, sql injection, xss, hardcoded secret, ...) and lists
the files they touched, so reviewers can spot where vulnerabilities
were introduced or fixed over time.
"""
from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timedelta, timezone


SECURITY_KEYWORDS = [
    "cve", "vuln", "security", "patch", "fix", "sql injection", "xss",
    "cross-site", "hardcod", "secret", "credential", "token", "ssrf",
    "path traversal", "rce", "remote code", "auth", "bypass",
]


class CommitAnalyzer:
    def __init__(self, repo_root: str = ".") -> None:
        self.repo_root = os.path.abspath(repo_root)

    def _run(self, args: list[str]) -> str:
        result = subprocess.run(
            ["git"] + args, cwd=self.repo_root,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return ""
        return result.stdout

    def report(self, since_days: int = 30) -> str:
        since = datetime.now(timezone.utc) - timedelta(days=since_days)
        since_iso = since.strftime("%Y-%m-%d")

        log = self._run([
            "log", f"--since={since_iso}",
            "--pretty=format:%H%x09%s%x09%ad", "--date=short", "--all",
        ])
        if not log:
            return "No git history found (or not a git repository)."

        lines = []
        lines.append(f"Security-relevant commits (last {since_days} days):")
        lines.append("-" * 70)
        count = 0
        for entry in log.splitlines():
            parts = entry.split("\t")
            if len(parts) < 3:
                continue
            commit_hash, subject, date = parts[0], parts[1], parts[2]
            blob = f"{commit_hash} {subject}".lower()
            if not any(kw in blob for kw in SECURITY_KEYWORDS):
                continue
            count += 1
            lines.append(f"{date}  {commit_hash[:10]}  {subject}")
            # Show which files changed and any added/removed dangerous calls.
            diff = self._run(["show", "--stat", "--format=", commit_hash])
            for stat_line in diff.splitlines():
                stat_line = stat_line.strip()
                if stat_line and "|" in stat_line:
                    lines.append(f"      {stat_line}")
            lines.append("")

        if count == 0:
            lines.append("None found.")
        return "\n".join(lines)
