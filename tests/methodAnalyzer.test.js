const { analyzeFile, analyzePath, generateTestStub } = require("../src/methodAnalyzer");
const fs = require("fs");
const os = require("os");
const path = require("path");

describe("MethodAnalyzer", () => {
  let tmpDir;
  let filePath;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "secpatch-test-"));
    filePath = path.join(tmpDir, "math.js");
    fs.writeFileSync(
      filePath,
      `
function add(a, b) {
  return a + b;
}

class Calculator {
  multiply(a, b) {
    return a * b;
  }
}
      `,
      "utf8"
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("enumerates top-level functions", () => {
    const module = analyzeFile(filePath);
    expect(module.functions.some((f) => f.name === "add")).toBe(true);
    const add = module.functions.find((f) => f.name === "add");
    expect(add.args).toEqual(["a", "b"]);
    expect(add.isMethod).toBe(false);
  });

  test("enumerates class methods", () => {
    const module = analyzeFile(filePath);
    expect(module.classes.length).toBe(1);
    expect(module.classes[0].name).toBe("Calculator");
    expect(module.classes[0].methods.some((m) => m.name === "multiply")).toBe(true);
    expect(module.classes[0].methods[0].isMethod).toBe(true);
  });

  test("generateTestStub produces a test file", () => {
    const module = analyzeFile(filePath);
    const stub = generateTestStub(module);
    expect(stub).toContain("add");
    expect(stub).toContain("multiply");
    expect(stub).toContain("describe");
    expect(stub).toContain("it(");
  });

  test("analyzePath returns modules keyed by path", () => {
    const modules = analyzePath(tmpDir);
    expect(Object.keys(modules)).toContain(filePath);
  });
});
