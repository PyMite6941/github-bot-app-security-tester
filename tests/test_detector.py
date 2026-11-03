import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from secpatch.detector import Detector, Finding

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "vuln_app", "app.py")


def test_detector_finds_sql_injection():
    detector = Detector()
    findings = detector.scan_file(FIXTURE)
    rules = {f.rule_id for f in findings}
    assert "SEC-SQLI-FSTRING" in rules, f"expected SQLi f-string finding, got {rules}"
    sqli = [f for f in findings if "SQL" in f.rule_id]
    assert all(f.severity == "critical" for f in sqli)


def test_detector_finds_hardcoded_secret():
    detector = Detector()
    findings = detector.scan_file(FIXTURE)
    assert any(f.rule_id == "SEC-HARDCODED-SECRET" for f in findings)
    secret = [f for f in findings if f.rule_id == "SEC-HARDCODED-SECRET"][0]
    assert secret.severity == "high"


def test_detector_finds_eval():
    detector = Detector()
    findings = detector.scan_file(FIXTURE)
    assert any(f.rule_id == "SEC-EVAL-USAGE" for f in findings)


def test_scan_path_reports_sorted_findings():
    detector = Detector()
    root = os.path.join(os.path.dirname(__file__), "fixtures")
    findings = detector.scan_path(root)
    assert findings
    severities = [f.severity for f in findings]
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    assert all(order[severities[i]] >= order[severities[i + 1]] for i in range(len(severities) - 1))
