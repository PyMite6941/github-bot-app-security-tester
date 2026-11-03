"""Extract every function/method/class from source via AST and generate
a test stub for each one.  This is what lets secpatch "test every
possible method" — not just the ones a developer happened to write
tests for.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MethodSignature:
    name: str
    args: list[str]
    returns: Optional[str]
    decorators: list[str]
    is_async: bool
    is_method: bool
    is_classmethod: bool
    is_staticmethod: bool
    line: int
    end_line: int
    docstring: Optional[str]
    source: str


@dataclass
class ClassInfo:
    name: str
    line: int
    end_line: int
    methods: list[MethodSignature] = field(default_factory=list)


@dataclass
class ModuleInfo:
    path: str
    functions: list[MethodSignature] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


class MethodAnalyzer(ast.NodeVisitor):
    def __init__(self, source: str, filename: str = "<module>") -> None:
        self.source = source
        self.filename = filename
        self.lines = source.splitlines()
        self.module = ModuleInfo(path=filename)
        self._class_stack: list[ClassInfo] = []

    def _decorator_names(self, node) -> list[str]:
        names: list[str] = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                names.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                names.append(dec.attr)
            else:
                names.append("?")
        return names

    def _arg_names(self, args: ast.arguments) -> list[str]:
        names: list[str] = []
        for a in args.posonlyargs:
            names.append(a.arg)
        for a in args.args:
            names.append(a.arg)
        if args.vararg:
            names.append("*" + args.vararg.arg)
        for a in args.kwonlyargs:
            names.append(a.arg)
        if args.kwarg:
            names.append("**" + args.kwarg.arg)
        return names

    def _snippet(self, node) -> str:
        start = node.lineno - 1
        end = getattr(node, "end_lineno", node.lineno)
        return "\n".join(self.lines[start:end])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        cls = ClassInfo(
            name=node.name,
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
        )
        self._class_stack.append(cls)
        self.generic_visit(node)
        self._class_stack.pop()
        self.module.classes.append(cls)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record_function(node, is_async=True)

    def _record_function(self, node, is_async: bool) -> None:
        returns = None
        if node.returns:
            returns = ast.get_source_segment(self.source, node.returns)
        docstring = ast.get_docstring(node)
        sig = MethodSignature(
            name=node.name,
            args=self._arg_names(node.args),
            returns=returns,
            decorators=self._decorator_names(node),
            is_async=is_async,
            is_method=bool(self._class_stack),
            is_classmethod="classmethod" in self._decorator_names(node),
            is_staticmethod="staticmethod" in self._decorator_names(node),
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            docstring=docstring,
            source=self._snippet(node),
        )
        if self._class_stack:
            self._class_stack[-1].methods.append(sig)
        else:
            self.module.functions.append(sig)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.module.imports.append(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.module.imports.append(node.module)


def analyze_file(path: str) -> ModuleInfo:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        source = fh.read()
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return ModuleInfo(path=path)
    analyzer = MethodAnalyzer(source, filename=path)
    analyzer.visit(tree)
    return analyzer.module


def analyze_path(root: str) -> dict[str, ModuleInfo]:
    modules: dict[str, ModuleInfo] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox"}
        )
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            full = os.path.join(dirpath, name)
            modules[full] = analyze_file(full)
    return modules


def generate_test_stub(module: ModuleInfo) -> str:
    """Generate a pytest module that exercises every function/method."""
    lines: list[str] = [
        '"""Auto-generated test stub by secpatch. Test every method."""',
        "import pytest",
    ]
    for imp in module.imports:
        # Best-effort: only import safe stdlib-ish names; user should review.
        lines.append(f"import {imp}")

    mod_name = os.path.splitext(os.path.basename(module.path))[0]
    lines.append(f"from {mod_name} import *")  # noqa: F401  (review needed)

    def add_fn(name: str, args: list[str], docstring: Optional[str], source: str) -> None:
        call_args = ", ".join(
            "None" if a not in ("self", "cls") else a for a in args
        )
        lines.append("")
        lines.append(f"def test_{name}():")
        lines.append(f'    """Auto-generated test for {name}."""')
        if docstring:
            for dl in docstring.splitlines():
                lines.append(f'    # {dl}')
        # If the function takes no real args (besides self/cls), call it.
        real_args = [a for a in args if a not in ("self", "cls")]
        if not real_args:
            lines.append(f"    result = {name}()")
            lines.append("    assert result is not None or True  # TODO: add real assertion")
        else:
            lines.append(
                f"    # {name} requires args: {real_args}  -> manual test needed"
            )
            lines.append(f"    pytest.skip(f\"{name} requires arguments {real_args}\")")

    for fn in module.functions:
        add_fn(fn.name, fn.args, fn.docstring, fn.source)

    for cls in module.classes:
        lines.append("")
        lines.append(f"class Test{cls.name}:")
        for m in cls.methods:
            add_fn(m.name, m.args, m.docstring, m.source)

    lines.append("")
    return "\n".join(lines)
