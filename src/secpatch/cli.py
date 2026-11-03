"""CLI entry point: secpatch scan | patch | commits | ci"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .ai_client import AIClient
from .commit_analyzer import CommitAnalyzer
from .detector import Detector, SEVERITY_ORDER
from .patcher import Patcher


def _print_findings(findings) -> str:
    lines = [
        f"{'SEVERITY':<9} {'RULE':<24} {'FILE':<40} LINE TITLE",
        "-" * 100,
    ]
    for f in findings:
        lines.append(
            f"{f.severity:<9} {f.rule_id:<24} {f.file}:{f.line:<36} {f.title}"
        )
    return "\n".join(lines)


def _scan(detector: Detector, path: str):
    """Scan a file or directory, returning findings with stable paths."""
    if os.path.isfile(path):
        return detector.scan_file(path)
    return detector.scan_path(path)


def _abs_file(scan_path_arg: str, finding_file: str) -> str:
    if os.path.normpath(finding_file) == os.path.normpath(scan_path_arg):
        return os.path.abspath(finding_file)
    if os.path.isabs(finding_file):
        return os.path.abspath(finding_file)
    return os.path.abspath(os.path.join(scan_path_arg, finding_file))


def cmd_scan(args) -> int:
    detector = Detector()
    findings = _scan(detector, args.path)
    min_sev = SEVERITY_ORDER.get(args.severity, 0)
    findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_sev]

    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No vulnerabilities found in {args.path}")
        else:
            print(_print_findings(findings))
            print(
                f"\n{len(findings)} finding(s) in {len({f.file for f in findings})} file(s)"
            )
    return 1 if findings else 0


def cmd_patch(args) -> int:
    ai = AIClient() if args.ai else None
    patcher = Patcher(ai_client=ai)
    detector = Detector()
    findings = _scan(detector, args.path)
    if not findings:
        print("No vulnerabilities found - nothing to patch.")
        return 0

    applied = 0
    for f in findings:
        abs_file = _abs_file(args.path, f.file)
        if not os.path.exists(abs_file):
            print(f"[skip] {f.file}:{f.line} - file not found")
            continue

        diff = patcher.draft(abs_file, f)
        if not diff:
            print(f"[skip] {f.file}:{f.line} [{f.rule_id}] - no draft available "
                  f"(set SECPATCH_AI_API_KEY for AI drafting)")
            continue

        if args.draft_only:
            print(f"--- DRAFT for {f.file}:{f.line} [{f.rule_id}] ---")
            print(diff)
            print("--- end ---")
            continue

        root = args.path if os.path.isdir(args.path) else os.path.dirname(args.path)
        rel_file = os.path.relpath(abs_file, root)
        result = patcher.validate(root, rel_file, diff, test_cmd=args.test_cmd)
        if not result.applied:
            print(f"[fail] {f.file}:{f.line} [{f.rule_id}] - {result.message}")
            continue
        if result.tests_passed is False:
            print(f"[revert] {f.file}:{f.line} [{f.rule_id}] - validation failed: {result.message}")
            continue

        patcher.apply_to_working_tree(abs_file, diff)
        applied += 1
        print(f"[patched] {f.file}:{f.line} [{f.rule_id}] - {result.message}")

    if args.draft_only:
        return 0
    print(f"\n{applied} patch(es) applied and validated.")
    return 0


def cmd_commits(args) -> int:
    analyzer = CommitAnalyzer(args.path)
    report = analyzer.report(since_days=args.since)
    print(report)
    return 0


def cmd_ci(args) -> int:
    detector = Detector()
    findings = _scan(detector, args.path)
    min_sev = SEVERITY_ORDER.get(args.severity, 0)
    findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= min_sev]
    if findings:
        print(f"CI: {len(findings)} vulnerability(s) at {args.severity}+ severity:")
        print(_print_findings(findings))
        return 1
    print("CI: no vulnerabilities found.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secpatch")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a path for vulnerabilities")
    p_scan.add_argument("path")
    p_scan.add_argument("--severity", default="info",
                        choices=["info", "low", "medium", "high", "critical"])
    p_scan.add_argument("--format", default="text", choices=["text", "json"])
    p_scan.set_defaults(func=cmd_scan)

    p_patch = sub.add_parser("patch", help="draft and validate patches for findings")
    p_patch.add_argument("path")
    p_patch.add_argument("--ai", action="store_true",
                         help="use AI API (requires SECPATCH_AI_API_KEY)")
    p_patch.add_argument("--test-cmd", default=None,
                         help="command to run tests after applying (e.g. 'pytest -q')")
    p_patch.add_argument("--draft-only", action="store_true",
                         help="print draft diffs without applying")
    p_patch.set_defaults(func=cmd_patch)

    p_commits = sub.add_parser("commits", help="analyse git history for security fixes")
    p_commits.add_argument("path", default=".")
    p_commits.add_argument("--since", type=int, default=30,
                           help="days of history to scan")
    p_commits.set_defaults(func=cmd_commits)

    p_ci = sub.add_parser("ci", help="CI mode: exit 1 if vulnerabilities found")
    p_ci.add_argument("path")
    p_ci.add_argument("--severity", default="high",
                      choices=["info", "low", "medium", "high", "critical"])
    p_ci.set_defaults(func=cmd_ci)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    import os  # noqa: imported late for abs path handling in patcher
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
