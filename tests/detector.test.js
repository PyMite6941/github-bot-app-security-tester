const { Detector, Finding, SEVERITY_ORDER } = require("../src/detector");
const fs = require("fs");
const os = require("os");
const path = require("path");

const VULN_CODE = `
const API_KEY = "sk-1234567890abcdef";

function getUser(db, userId) {
  const query = \`SELECT * FROM users WHERE id = \${userId}\`;
  return db.query(query);
}

function configValue(raw) {
  return eval(raw);
}
`;

describe("Detector", () => {
  let tmpDir;
  let filePath;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "secpatch-test-"));
    filePath = path.join(tmpDir, "app.js");
    fs.writeFileSync(filePath, VULN_CODE, "utf8");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("finds hardcoded secret", () => {
    const detector = new Detector();
    const findings = detector.scanFile(filePath);
    expect(
      findings.some((f) => f.ruleId === "SEC-HARDCODED-SECRET")
    ).toBe(true);
    const secret = findings.find((f) => f.ruleId === "SEC-HARDCODED-SECRET");
    expect(secret.severity).toBe("high");
  });

  test("finds SQL injection via template literal", () => {
    const detector = new Detector();
    const findings = detector.scanFile(filePath);
    expect(
      findings.some((f) => f.ruleId === "SEC-SQLI-FSTRING")
    ).toBe(true);
    const sqli = findings.find((f) => f.ruleId === "SEC-SQLI-FSTRING");
    expect(sqli.severity).toBe("critical");
  });

  test("finds eval() usage", () => {
    const detector = new Detector();
    const findings = detector.scanFile(filePath);
    expect(
      findings.some((f) => f.ruleId === "SEC-EVAL-USAGE")
    ).toBe(true);
  });

  test("scanPath sorts by severity descending", () => {
    const detector = new Detector();
    const findings = detector.scanPath(tmpDir);
    const severities = findings.map((f) => f.severity);
    const order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    for (let i = 0; i < severities.length - 1; i++) {
      expect(order[severities[i]]).toBeGreaterThanOrEqual(order[severities[i + 1]]);
    }
  });

  test("Finding.toDict returns expected keys", () => {
    const f = new Finding("SEC-TEST", "Test finding", "low", "test.js", 1, "snippet", "fix");
    const d = f.toDict();
    expect(d.rule_id).toBe("SEC-TEST");
    expect(d.title).toBe("Test finding");
    expect(d.severity).toBe("low");
    expect(d.file).toBe("test.js");
    expect(d.line).toBe(1);
    expect(d.snippet).toBe("snippet");
    expect(d.fix_hint).toBe("fix");
  });
});
