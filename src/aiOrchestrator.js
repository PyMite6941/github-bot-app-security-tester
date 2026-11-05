"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { compile } = require("acorn");
const { AIClient } = require("./aiClient");
const { analyzeFile } = require("./methodAnalyzer");
const { Sandbox } = require("./sandbox");
const { applyDiffToFile } = require("./patcher");

class AIOrchestrator {
  constructor(aiClient, maxIterations = 3, timeout = 120) {
    this.ai = aiClient || new AIClient();
    this.maxIterations = maxIterations;
    this.timeout = timeout;
  }

  available() {
    return this.ai.available();
  }

  _gatherContext(filePath, line) {
    const module = analyzeFile(filePath);
    const context = { imports: module.imports, enclosing: null, source: "" };

    let lines = [];
    try {
      lines = fs.readFileSync(filePath, "utf8").split("\n");
    } catch (e) {
      return context;
    }

    let enclosingStart = 0;
    let enclosingEnd = lines.length;

    for (const cls of module.classes) {
      if (cls.line <= line && line <= cls.endLine) {
        context.enclosing = `class ${cls.name}`;
        enclosingStart = cls.line - 1;
        enclosingEnd = cls.endLine;
        for (const m of cls.methods) {
          if (m.line <= line && line <= m.endLine) {
            context.enclosing = `method ${cls.name}.${m.name}`;
            enclosingStart = m.line - 1;
            enclosingEnd = m.endLine;
            break;
          }
        }
        break;
      }
    }
    for (const fn of module.functions) {
      if (fn.line <= line && line <= fn.endLine && !fn.isMethod) {
        context.enclosing = `function ${fn.name}`;
        enclosingStart = fn.line - 1;
        enclosingEnd = fn.endLine;
        break;
      }
    }

    context.source = lines.slice(enclosingStart, enclosingEnd).join("\n");
    return context;
  }

  _buildPrompt(filePath, finding, context, previousError) {
    const lines = [
      "You are a senior security engineer. Produce ONE unified diff that fixes the vulnerability below.",
      "Output ONLY the diff - no markdown fences, no explanation.",
      "Rules:",
      "  - Header: --- a/<file> then +++ b/<file>",
      "  - One hunk, three lines of context, exact line numbers.",
      "  - Fix ONLY the reported vulnerability; do not refactor unrelated code.",
      "  - Prefer parameterised queries, input validation, escaping, or removing dangerous calls.",
      "",
      `File: ${filePath}`,
      `Vulnerability: ${finding.title} (${finding.ruleId})`,
      `Severity: ${finding.severity}`,
      `Location: line ${finding.line}`,
      `Fix hint: ${finding.fixHint}`,
      `Enclosing code: ${context.enclosing || "module level"}`,
      "",
      "Enclosing source context:",
      context.source || "",
      "",
      "Imports available:",
      (context.imports || []).join(", ") || "(none)",
    ];
    if (previousError) {
      lines.push("", "PREVIOUS ATTEMPT FAILED:", previousError, "Revise the diff to address the failure above.");
    }
    lines.push("", "Return the unified diff now:");
    return lines.join("\n");
  }

  async _draftWithContext(filePath, finding, previousError) {
    if (!this.ai.available()) return null;
    const context = this._gatherContext(filePath, finding.line);
    const prompt = this._buildPrompt(filePath, finding, context, previousError);
    const body = {
      model: this.ai.model,
      messages: [
        { role: "system", content: "You output only valid unified diffs." },
        { role: "user", content: prompt },
      ],
      temperature: 0.1,
      max_tokens: 1500,
    };

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.ai.timeout * 1000);
      const resp = await fetch(`${this.ai.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.ai.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!resp.ok) {
        console.error(`[secpatch-ai] request failed: ${resp.status} ${resp.statusText}`);
        return null;
      }
      const payload = await resp.json();
      const content = payload.choices?.[0]?.message?.content;
      if (!content) return null;
      return { filePath, diff: this._extractDiff(content), model: this.ai.model };
    } catch (e) {
      console.error(`[secpatch-ai] request failed: ${e.message}`);
      return null;
    }
  }

  _extractDiff(content) {
    let text = content.trim();
    if (text.startsWith("```")) {
      text = text.split("\n").slice(1).join("\n");
      if (text.endsWith("```")) text = text.slice(0, -3).trim();
    }
    return text.trim();
  }

  async patchWithValidation(repoRoot, filePath, finding, testCmd) {
    const result = {
      file: filePath,
      finding: finding.ruleId,
      applied: false,
      validated: false,
      iterations: 0,
      message: "",
      diff: null,
    };

    const absFile = path.resolve(filePath);
    const rootDir = fs.statSync(absFile).isDirectory() ? absFile : path.dirname(absFile);
    const relFile = path.relative(rootDir, absFile);

    // 1) Deterministic template patch (safe subset).
    const templateDiff = this._templatePatch(absFile, finding);
    if (templateDiff) {
      result.iterations = 1;
      result.diff = templateDiff;
      const validation = await this._sandboxCopyValidate(rootDir, relFile, templateDiff, testCmd);
      if (validation.applied && validation.validated) {
        applyDiffToFile(absFile, templateDiff);
        result.applied = true;
        result.validated = true;
        result.message = "template patch applied and validated";
        return result;
      }
      result.message = `template patch failed validation: ${validation.message}`;
    }

    // 2) AI-powered patch with iteration.
    if (!this.ai.available()) {
      result.message += "; no AI key configured (set SECPATCH_AI_API_KEY)";
      return result;
    }

    let previousError = null;
    for (let i = 1; i <= this.maxIterations; i++) {
      const draft = await this._draftWithContext(absFile, finding, previousError);
      if (!draft || !draft.diff) {
        result.message = "AI produced no usable diff";
        return result;
      }
      result.diff = draft.diff;
      result.iterations = i;
      const validation = await this._sandboxCopyValidate(rootDir, relFile, draft.diff, testCmd);
      if (validation.applied && validation.validated) {
        applyDiffToFile(absFile, draft.diff);
        result.applied = true;
        result.validated = true;
        result.message = `AI patch validated after ${i} iteration(s)`;
        return result;
      }
      previousError = validation.message;
    }
    result.message = `AI patch failed validation after ${this.maxIterations} iteration(s): ${previousError}`;
    return result;
  }

  _templatePatch(filePath, finding) {
    let content;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch (e) {
      return null;
    }
    const lines = content.split("\n");
    const idx = finding.line - 1;
    if (idx < 0 || idx >= lines.length) return null;

    const newLines = [...lines];
    let applied = false;

    if (finding.ruleId === "SEC-EVAL-USAGE") {
      const newLine = lines[idx].replace(/\beval\s*\(/g, "safeEval(");
      if (newLine !== lines[idx]) {
        newLines[idx] = newLine;
        if (!newLines.some((l) => l.includes("function safeEval"))) {
          newLines.unshift("function safeEval(input) { return JSON.parse(input); }");
        }
        applied = true;
      }
    }

    if (finding.ruleId === "SEC-HARDCODED-SECRET") {
      const m = lines[idx].match(/^(\s*)([A-Za-z_]\w*)\s*=\s*['"].+['"]\s*(#.*)?$/);
      if (m) {
        const [, indent, varName, comment] = m;
        newLines[idx] = `${indent}${varName} = process.env.${varName.toUpperCase()}${comment || ""}`;
        if (!newLines.some((l) => l.includes("process.env"))) {
          // require dotenv? keep simple — just use process.env directly.
        }
        applied = true;
      }
    }

    if (!applied) return null;
    const newText = newLines.join("\n");
    if (newText === content) return null;
    return this._unifiedDiff(lines, newText.split("\n"), path.basename(filePath));
  }

  _unifiedDiff(oldLines, newLines, fileName) {
    const diff = [];
    diff.push(`--- a/${fileName}`);
    diff.push(`+++ b/${fileName}`);
    diff.push(`@@ -1,${oldLines.length} +1,${newLines.length} @@`);
    // Simple: remove all old, add all new (valid but not minimal).
    for (const l of oldLines) diff.push(`-${l}`);
    for (const l of newLines) diff.push(`+${l}`);
    return diff.join("\n");
  }

  async _sandboxCopyValidate(rootDir, filePath, diff, testCmd) {
    const sandbox = new Sandbox(rootDir, this.timeout);
    const tmp = sandbox.copyToTemp();
    try {
      const target = path.join(tmp, filePath);
      if (!fs.existsSync(target)) {
        return { applied: false, validated: false, message: `file not found in copy: ${target}` };
      }
      applyDiffToFile(target, diff);

      // Syntax check with acorn.
      try {
        const src = fs.readFileSync(target, "utf8");
        const ast = require("acorn").parse(src, { ecmaVersion: 2022, sourceType: "module" });
      } catch (e) {
        return { applied: true, validated: false, message: `syntax error after patch: ${e.message}` };
      }

      if (testCmd) {
        const res = sandbox.run(testCmd, tmp, {}, 180);
        if (res.timedOut) {
          return { applied: true, validated: false, message: "test command timed out" };
        }
        if (res.exitCode !== 0) {
          return {
            applied: true,
            validated: false,
            message: `tests failed: ${(res.stderr || res.stdout || "").slice(-600)}`,
          };
        }
      }
      return { applied: true, validated: true, message: "patched file compiles and tests pass" };
    } finally {
      sandbox.cleanup(tmp);
    }
  }
}

module.exports = { AIOrchestrator };
