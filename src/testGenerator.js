"use strict";

const fs = require("fs");
const path = require("path");
const { analyzeFile, generateTestStub } = require("./methodAnalyzer");
const { Sandbox } = require("./sandbox");
const { applyDiffToFile } = require("./patcher");

class TestRunResult {
  constructor(module, testFile, methodsFound, methodsTested, result) {
    this.module = module;
    this.testFile = testFile;
    this.methodsFound = methodsFound;
    this.methodsTested = methodsTested;
    this.result = result;
  }
}

class TestGenerator {
  constructor(repoRoot, timeout = 120) {
    this.repoRoot = path.resolve(repoRoot);
    this.sandbox = new Sandbox(repoRoot, timeout);
  }

  generateForModule(filePath) {
    const module = analyzeFile(filePath);
    if (module.functions.length === 0 && module.classes.length === 0) return null;
    return generateTestStub(module);
  }

  runModuleTests(filePath) {
    const module = analyzeFile(filePath);
    const stub = generateTestStub(module);
    const emptyResult = {
      command: "", cwd: "", exitCode: 0, stdout: "", stderr: "no methods", timedOut: false,
    };
    if (!stub) {
      return new TestRunResult(filePath, "", 0, 0, emptyResult);
    }

    const tmp = this.sandbox.copyToTemp();
    try {
      const testName = "test_" + path.basename(filePath);
      const testPath = path.join(tmp, testName);
      fs.writeFileSync(testPath, stub, "utf8");

      // Install jest in the sandbox.
      this.sandbox.run("npm install --no-save jest @jest/globals", tmp, {}, 180);

      const result = this.sandbox.run(`npx jest ${testName} --silent`, tmp, {}, 180);
      const methodsFound =
        module.functions.length +
        module.classes.reduce((sum, c) => sum + c.methods.length, 0);
      return new TestRunResult(filePath, testPath, methodsFound, methodsFound, result);
    } finally {
      this.sandbox.cleanup(tmp);
    }
  }

  runAll() {
    const results = [];
    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (e) {
        return;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          const skip = [".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".egg-info", ".next", ".cache"];
          if (skip.includes(entry.name)) continue;
          walk(full);
        } else if (entry.name.endsWith(".js") && !entry.name.startsWith("test_")) {
          results.push(this.runModuleTests(full));
        }
      }
    };
    walk(this.repoRoot);
    return results;
  }
}

module.exports = { TestRunResult, TestGenerator };
