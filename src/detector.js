/*
secpatch - Automated Vulnerability Patching / DevSecOps AI (npm edition)

Finds security flaws in source code, drafts fixes (deterministic templates or via an
AI API such as GitHub Models / OpenAI-compatible endpoints), applies them in a
sandbox, validates that tests still pass, and generates a test for every method.
*/
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync, execSync } = require("child_process");
const acorn = require("acorn");

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const SKIP_DIRS = new Set([
  ".git", ".svn", ".hg",
  "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
  "dist", "build", ".tox", ".egg-info", ".next", ".cache",
]);

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

class Finding {
  constructor(ruleId, title, severity, file, line, snippet, fixHint) {
    this.ruleId = ruleId;
    this.title = title;
    this.severity = severity;
    this.file = file;
    this.line = line;
    this.snippet = snippet;
    this.fixHint = fixHint;
  }

  toDict() {
    return {
      rule_id: this.ruleId,
      title: this.title,
      severity: this.severity,
      file: this.file,
      line: this.line,
      snippet: this.snippet,
      fix_hint: this.fixHint,
    };
  }
}

// ---------------------------------------------------------------------------
// Detector  (regex rules + acorn AST rules)
// ---------------------------------------------------------------------------

// (ruleId, title, severity, regex, fixHint)
const REGEX_RULES = [
  [
    "SEC-HARDCODED-SECRET",
    "Hardcoded secret or credential",
    "high",
    /(api[_-]?key|secret|secret_key|password|passwd|private_key|access_token|auth_token)\s*[:=]\s*['"][^'"]{3,}['"]/i,
    "Move the value into an environment variable or secret manager; never commit it to source control.",
  ],
  [
    "SEC-EVAL-USAGE",
    "Use of eval() / exec()",
    "critical",
    /\b(eval|exec)\s*\(/,
    "Avoid eval/exec. Use a safe expression parser or validated input.",
  ],
  [
    "SEC-SHELL-TRUE",
    "subprocess / child_process called with shell=True / shell: true",
    "high",
    /\bshell\s*[:=]\s*true\b/i,
    "Use a list of arguments with shell=false; sanitize inputs if a shell is required.",
  ],
  [
    "SEC-DYNAMIC-SQL",
    "SQL statement built with string concatenation",
    "critical",
    /\b(SELECT|INSERT|UPDATE|DELETE|MERGE)\b[^;]*\s*\+\s*|['"]\s*\+\s*[^;]*\b(SELECT|INSERT|UPDATE|DELETE)\b/i,
    "Use parameterised queries with placeholders (? / $1) instead of building SQL with + or template literals.",
  ],
  [
    "SEC-INNERHTML-CONCAT",
    "innerHTML assigned from a concatenated string",
    "high",
    /\.innerHTML\s*=\s*.*['"].*\s*\+\s*/,
    "Use textContent or an auto-escaping template engine; sanitise user-controlled input.",
  ],
  [
    "SEC-PICKLE-LOAD",
    "Insecure deserialization with pickle.load",
    "critical",
    /\bpickle\.load\s*\(/,
    "Never unpickle untrusted data. Use JSON or a safe serialization format.",
  ],
  [
    "SEC-WEAK-CRYPTO",
    "Use of weak cryptographic algorithm",
    "high",
    /\b(md5|sha1|des|rc4)\b/i,
    "Use SHA-256+ or bcrypt/argon2 for passwords; avoid MD5/SHA1/DES/RC4.",
  ],
  [
    "SEC-INSECURE-RANDOM",
    "Use of non-cryptographic random()",
    "medium",
    /\brandom\.(random|randint|choice|seed)\s*\(/,
    "Use crypto.randomBytes() / crypto.randomInt() for security-sensitive randomness.",
  ],
  [
    "SEC-XXE",
    "XML parsing without disabling external entities",
    "high",
    /\b(etree\.parse|xml\.etree|minidom\.parse|sax\.parse|DOMParser)\s*\(/,
    "Disable DTD/external entities or use a defused XML parser.",
  ],
  [
    "SEC-DANGEROUS-EVAL-JS",
    "JavaScript eval() / setTimeout(string) / setInterval(string)",
    "critical",
    /\b(eval|setTimeout|setInterval)\s*\(\s*['"]/,
    "Never evaluate strings as code in JavaScript; use JSON.parse or function references.",
  ],
  [
    "SEC-INNERHTML-ASSIGN",
    "innerHTML assigned from potentially unsanitized source",
    "high",
    /\.innerHTML\s*=/,
    "Use textContent or sanitize HTML with DOMPurify before assigning to innerHTML.",
  ],
];

const SKIP_EXTS = new Set([
  ".md", ".rst", ".txt", ".html", ".htm", ".css", ".json", ".yml", ".yaml",
  ".toml", ".cfg", ".ini", ".lock", ".png", ".jpg", ".jpeg", ".gif", ".svg",
  ".ico", ".woff", ".woff2", ".ttf", ".eot",
]);

class Detector {
  scanPath(root) {
    const findings = [];
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
          if (SKIP_DIRS.has(entry.name)) continue;
          walk(full);
        } else {
          if (!this._isScannable(entry.name)) continue;
          findings.push(...this.scanFile(full));
        }
      }
    };
    walk(root);
    findings.sort(
      (a, b) =>
        (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0) ||
        a.file.localeCompare(b.file) ||
        a.line - b.line
    );
    return findings;
  }

  scanFile(filePath) {
    let src;
    try {
      src = fs.readFileSync(filePath, "utf8");
    } catch (e) {
      return [];
    }
    const lines = src.split("\n");
    const findings = [];

    // Regex rules, line by line.
    for (const [ruleId, title, severity, regex, fixHint] of REGEX_RULES) {
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) {
          findings.push(
            new Finding(ruleId, title, severity, filePath, i + 1, lines[i].trim(), fixHint)
          );
        }
      }
    }

    // AST rules for JavaScript/TypeScript.
    if (filePath.endsWith(".js") || filePath.endsWith(".mjs") || filePath.endsWith(".jsx")) {
      findings.push(...this._astScan(filePath, src));
    }

    // Deduplicate identical (ruleId, file, line).
    const seen = new Set();
    const unique = [];
    for (const f of findings) {
      const key = `${f.ruleId}|${f.file}|${f.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      unique.push(f);
    }
    return unique;
  }

  _astScan(filePath, src) {
    const findings = [];
    const lines = src.split("\n");
    const snippet = (node) => {
      if (node.loc && node.loc.start.line >= 1 && node.loc.start.line <= lines.length) {
        return lines[node.loc.start.line - 1].trim();
      }
      return "";
    };

    let tainted = {}; // variable name -> true (assigned from template literal / concat)
    const safeLine = (node) => {
      return node && node.loc && node.loc.start ? node.loc.start.line : 0;
    };

    try {
      const ast = acorn.parse(src, {
        ecmaVersion: 2022,
        sourceType: "module",
      });

      const walk = (node) => {
        if (!node || typeof node.type !== "string") return;

        // Track tainted assignments: x = `...${...}...` or x = "..." + "..."
        if (node.type === "VariableDeclarator" && node.id && node.id.type === "Identifier") {
          const init = node.init;
          if (init && (init.type === "TemplateLiteral" || init.type === "BinaryExpression")) {
            tainted[node.id.name] = true;
          }
        }

        // eval(...) / exec(...)
        if (
          node.type === "CallExpression" &&
          node.callee &&
          node.callee.type === "Identifier" &&
          (node.callee.name === "eval" || node.callee.name === "exec")
        ) {
          findings.push(
            new Finding(
              "SEC-EVAL-USAGE",
              `Use of ${node.callee.name}()`,
              "critical",
              filePath,
              safeLine(node),
              snippet(node),
              `Replace ${node.callee.name}() with a validated parser or safe alternative.`
            )
          );
        }

        // db.query(\`...${...}...\`) or db.query(x) where x is tainted
        if (
          node.type === "CallExpression" &&
          node.callee &&
          node.callee.type === "MemberExpression" &&
          ["query", "execute", "executemany"].includes(node.callee.property.name)
        ) {
          for (const arg of node.arguments) {
            if (arg.type === "TemplateLiteral") {
              findings.push(
                new Finding(
                  "SEC-SQLI-FSTRING",
                  "SQL query built with a template literal",
                  "critical",
                  filePath,
                  node.loc.start.line,
                  snippet(node),
                  "Use parameterised queries (placeholders) instead of template literals in SQL."
                )
              );
              break;
            }
            if (arg.type === "Identifier" && tainted[arg.name]) {
              findings.push(
                new Finding(
                  "SEC-SQLI-FSTRING",
                  "SQL query built with a tainted string",
                  "critical",
                  filePath,
                  safeLine(node),
                  snippet(node),
                  "Use parameterised queries (placeholders) instead of string concatenation in SQL."
                )
              );
              break;
            }
          }
        }

        // Recurse into child properties.
        for (const key of Object.keys(node)) {
          if (key === "parent") continue;
          const val = node[key];
          if (Array.isArray(val)) {
            for (const child of val) walk(child);
          } else if (val && typeof val.type === "string") {
            walk(val);
          }
        }
      };

      walk(ast);
    } catch (e) {
      // Not parseable.
    }

    return findings;
  }

  _isScannable(name) {
    const ext = path.extname(name).toLowerCase();
    return !SKIP_EXTS.has(ext);
  }
}

module.exports = { Detector, Finding, SEVERITY_ORDER };
