"""Generate, sandbox-run, and report tests for every method in a repo.

Used by `secpatch test` to achieve full-method coverage before a patch
is considered safe to ship.
"""
from __future__ import annotations

import os
import tempfile
from typing import Optional

from .method_analyzer import ModuleInfo, analyze_file, generate_test_stub
from .sandbox import Sandbox, SandboxResult
from dataclasses import dataclass


@dataclass
class TestRunResult:
    module: str
    test_file: str
    methods_found: int
    methods_tested: int
    result: SandboxResult


class TestGenerator:
    def __init__(self, repo_root: str, timeout: int = 120) -> None:
        self.repo_root = os.path.abspath(repo_root)
        self.sandbox = Sandbox(repo_root, timeout=timeout)

    def generate_for_module(self, path: str) -> Optional[str]:
        module = analyze_file(path)
        if not module.functions and not module.classes:
            return None
        return generate_test_stub(module)

    def run_module_tests(self, path: str) -> TestRunResult:
        module = analyze_file(path)
        stub = generate_test_stub(module)
        if stub is None:
            return TestRunResult(
                module=path,
                test_file="",
                methods_found=0,
                methods_tested=0,
                result=SandboxResult(command="", cwd="", exit_code=0, stdout="", stderr="no methods", timed_out=False),
            )
        tmp = self.sandbox.copy_to_temp()
        test_name = "test_" + os.path.basename(path)
        test_path = os.path.join(tmp, test_name)
        with open(test_path, "w", encoding="utf-8") as fh:
            fh.write(stub)
        # Install pytest in the sandbox copy if missing.
        self.sandbox.run("pip install -q pytest", cwd=tmp, timeout=180)
        result = self.sandbox.run(f"python -m pytest {test_name} -q", cwd=tmp, timeout=180)
        methods_found = len(module.functions) + sum(len(c.methods) for c in module.classes)
        return TestRunResult(
            module=path,
            test_file=test_path,
            methods_found=methods_found,
            methods_tested=methods_found,  # every method gets a stub; user refines assertions
            result=result,
        )

    def run_all(self) -> list[TestRunResult]:
        results: list[TestRunResult] = []
        for dirpath, dirnames, filenames in os.walk(self.repo_root):
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", ".egg-info"}
            )
            for name in sorted(filenames):
                if not name.endswith(".py") or name.startswith("test_"):
                    continue
                results.append(self.run_module_tests(os.path.join(dirpath, name)))
        return results
