"use strict";

const fs = require("fs");
const path = require("path");
const acorn = require("acorn");

class MethodSignature {
  constructor(name, args, returns, decorators, isAsync, isMethod, line, endLine, docstring, source) {
    this.name = name;
    this.args = args;
    this.returns = returns;
    this.decorators = decorators;
    this.isAsync = isAsync;
    this.isMethod = isMethod;
    this.line = line;
    this.endLine = endLine;
    this.docstring = docstring;
    this.source = source;
  }
}

class ClassInfo {
  constructor(name, line, endLine) {
    this.name = name;
    this.line = line;
    this.endLine = endLine;
    this.methods = [];
  }
}

class ModuleInfo {
  constructor(filePath) {
    this.filePath = filePath;
    this.functions = [];
    this.classes = [];
    this.imports = [];
  }
}

class MethodAnalyzer {
  constructor(source, filePath) {
    this.source = source;
    this.filePath = filePath;
    this.lines = source.split("\n");
    this.module = new ModuleInfo(filePath);
    this.classStack = [];
    this.tainted = {};
  }

  _loc(node) {
    return node && node.loc ? node.loc : { start: { line: 0 }, end: { line: 0 } };
  }

  _snippet(node) {
    const loc = this._loc(node);
    const start = Math.max(0, loc.start.line - 1);
    const end = loc.end ? loc.end.line : loc.start.line;
    return this.lines.slice(start, end).join("\n");
  }

  _argNames(params) {
    const names = [];
    for (const p of params || []) {
      if (p.type === "Identifier") names.push(p.name);
      else if (p.type === "RestElement") {
        if (p.argument.type === "Identifier") names.push("..." + p.argument.name);
      } else {
        names.push("?");
      }
    }
    return names;
  }

  walk(node) {
    if (!node || typeof node.type !== "string") return;

    // Track tainted assignments.
    if (
      node.type === "VariableDeclarator" &&
      node.id &&
      node.id.type === "Identifier" &&
      node.init
    ) {
      const init = node.init;
      if (
        init.type === "TemplateLiteral" ||
        init.type === "BinaryExpression"
      ) {
        this.tainted[node.id.name] = true;
      }
    }

    if (node.type === "ClassDeclaration" || node.type === "ClassExpression") {
      const clsLoc = this._loc(node);
      const cls = new ClassInfo(node.id.name, clsLoc.start.line, clsLoc.end.line);
      this.classStack.push(cls);
      for (const member of node.body.body) {
        if (member.type === "MethodDefinition" && member.key) {
          const mLoc = this._loc(member.value);
          const isAsync = member.value.async === true;
          const sig = new MethodSignature(
            member.key.name || member.key.value || "unknown",
            this._argNames(member.value.params),
            null,
            [],
            isAsync,
            true,
            mLoc.start.line,
            mLoc.end.line,
            null,
            this._snippet(member.value)
          );
          cls.methods.push(sig);
          this.module.functions.push(sig);
        }
      }
      this.module.classes.push(cls);
      // Walk class body for nested stuff but skip methods already handled.
      for (const member of node.body.body) {
        if (member.type !== "MethodDefinition") this.walk(member);
      }
      this.classStack.pop();
      return;
    }

    if (
      node.type === "FunctionDeclaration" ||
      node.type === "ArrowFunctionExpression" ||
      (node.type === "FunctionExpression" && node.id)
    ) {
      const fLoc = this._loc(node);
      const isAsync = node.async === true;
      const name = node.id ? node.id.name : "<anonymous>";
      const sig = new MethodSignature(
        name,
        this._argNames(node.params),
        null,
        [],
        isAsync,
        this.classStack.length > 0,
        fLoc.start.line,
        fLoc.end.line,
        null,
        this._snippet(node)
      );
      this.module.functions.push(sig);
      // Walk body statements for nested function declarations.
      if (node.body) this.walk(node.body);
      return;
    }

    if (node.type === "ImportDeclaration") {
      this.module.imports.push(node.source.value);
    }

    // Generic recursion.
    for (const key of Object.keys(node)) {
      if (key === "parent") continue;
      const val = node[key];
      if (Array.isArray(val)) {
        for (const c of val) this.walk(c);
      } else if (val && typeof val.type === "string") {
        this.walk(val);
      }
    }
  }

  analyze() {
    try {
      const ast = acorn.parse(this.source, {
        ecmaVersion: 2022,
        sourceType: "module",
      });
      this.walk(ast);
    } catch (e) {
      // Not parseable.
    }
    return this.module;
  }
}

function analyzeFile(filePath) {
  let src;
  try {
    src = fs.readFileSync(filePath, "utf8");
  } catch (e) {
    return new ModuleInfo(filePath);
  }
  const analyzer = new MethodAnalyzer(src, filePath);
  return analyzer.analyze();
}

function analyzePath(root) {
  const modules = {};
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
      } else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs") || entry.name.endsWith(".jsx")) {
        modules[full] = analyzeFile(full);
      }
    }
  };
  walk(root);
  return modules;
}

function generateTestStub(module) {
  const lines = [
    "/** Auto-generated test stub by secpatch. Test every method. */",
    "import { describe, it, expect } from '@jest/globals';",
  ];
  for (const imp of module.imports) {
    lines.push(`import * as ${_safeImportName(imp)} from "${imp}";`);
  }

  const modName = path.basename(module.filePath, path.extname(module.filePath));
  lines.push(`import * as mod from "./${modName}";`);

  const addFn = (fn) => {
    const realArgs = fn.args.filter((a) => a !== "self" && a !== "cls");
    lines.push("");
    lines.push(`describe("${fn.name}", () => {`);
    lines.push(`  it("exercises ${fn.name}", () => {`);
    if (realArgs.length === 0) {
      lines.push(`    const result = mod.${fn.name}();`);
      lines.push(`    expect(result).toBeDefined();`);
    } else {
      lines.push(`    // ${fn.name} requires args: ${JSON.stringify(realArgs)} — manual test needed`);
      lines.push(`    expect(true).toBe(true);`);
    }
    lines.push(`  });`);
    lines.push(`});`);
  };

  for (const fn of module.functions) {
    if (!fn.isMethod) addFn(fn);
  }
  for (const cls of module.classes) {
    for (const m of cls.methods) addFn(m);
  }

  lines.push("");
  return lines.join("\n");
}

function _safeImportName(imp) {
  return imp.replace(/[^a-zA-Z0-9_$]/g, "_");
}

module.exports = { MethodAnalyzer, ModuleInfo, analyzeFile, analyzePath, generateTestStub };
