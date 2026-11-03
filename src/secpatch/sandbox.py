"""Isolated sandbox execution for validating patches and running tests.

Every potentially untrusted operation (applying an AI-generated diff,
running pytest, importing patched modules) happens inside a disposable
temp-directory copy of the repo with strict timeouts. The host working
tree is never modified.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional


@dataclass
class SandboxResult:
    command: str
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


class Sandbox:
    """Run commands in an isolated copy of a repository."""

    def __init__(self, repo_root: str, timeout: int = 120) -> None:
        self.repo_root = os.path.abspath(repo_root)
        self.timeout = timeout

    def copy_to_temp(self, ignore: Optional[list[str]] = None) -> str:
        """Copy the repo (minus caches/venvs) into a fresh temp dir."""
        tmp = tempfile.mkdtemp(prefix="secpatch-sandbox-")
        ignore_patterns = ignore or [
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".env",
            "node_modules",
            ".tox",
            "dist",
            "build",
            ".egg-info",
        ]
        for entry in os.listdir(self.repo_root):
            src = os.path.join(self.repo_root, entry)
            dst = os.path.join(tmp, entry)
            if os.path.isdir(src):
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*ignore_patterns))
            else:
                shutil.copy2(src, dst)
        return tmp

    def run(
        self,
        command: str,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> SandboxResult:
        """Execute a shell command inside the sandbox."""
        workdir = cwd or self.repo_root
        merged_env = dict(os.environ)
        if env:
            merged_env.update(env)
        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                env=merged_env,
            )
            return SandboxResult(
                command=command,
                cwd=workdir,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                command=command,
                cwd=workdir,
                exit_code=-1,
                stdout=exc.stdout or "",
                stderr=(exc.stderr or "") + f"\n[timeout after {timeout or self.timeout}s]",
                timed_out=True,
            )

    def cleanup(self, path: str) -> None:
        shutil.rmtree(path, ignore_errors=True)
