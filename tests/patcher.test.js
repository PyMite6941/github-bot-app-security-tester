const { applyDiffToFile, DiffError } = require("../src/patcher");
const fs = require("fs");
const os = require("os");
const path = require("path");

describe("Patcher", () => {
  let tmpDir;
  let filePath;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "secpatch-test-"));
    filePath = path.join(tmpDir, "app.js");
    fs.writeFileSync(
      filePath,
      `const x = 1;\nconst y = 2;\nconsole.log(x + y);\n`,
      "utf8"
    );
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("applies a unified diff", () => {
    const diff = `--- a/app.js\n+++ b/app.js\n@@ -1,3 +1,3 @@\n const x = 1;\n-const y = 2;\n+const y = 3;\n console.log(x + y);\n`;
    applyDiffToFile(filePath, diff);
    const content = fs.readFileSync(filePath, "utf8");
    expect(content).toContain("const y = 3;");
    expect(content).not.toContain("const y = 2;");
  });

  test("throws on context mismatch", () => {
    const diff = `--- a/app.js\n+++ b/app.js\n@@ -1,3 +1,3 @@\n const x = 99;\n-const y = 2;\n+const y = 3;\n console.log(x + y);\n`;
    expect(() => applyDiffToFile(filePath, diff)).toThrow(DiffError);
  });

  test("throws when file not in diff", () => {
    const diff = `--- b/other.js\n+++ b/other.js\n@@ -1 +1 @@\n-x\n+y\n`;
    expect(() => applyDiffToFile(filePath, diff)).toThrow(DiffError);
  });
});
