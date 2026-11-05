#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { Detector, SEVERITY_ORDER } = require("./detector");
const { Sandbox } = require("./sandbox");
const { TestGenerator } = require("./testGenerator");
const { AIClient } = require("./aiClient");
const { AIOrchestrator } = require("./aiOrchestrator");

const USAGE = `
secpatch - Automated Vulnerability Patching / DevSecOps AI (npm)

Usage: secpatch <command> [options]

Commands:
  scan <path>           Scan a path for vulnerabilities
  patch <path>          Draft and validate patches for findings
  orchestrate <path>    AI-powered patch with context + iteration
  test <path>           Generate and run a test for every method
  commits <path>        Analyse git history for security fixes
  ci <path>             CI mode: report vulnerabilities found

Options:
  --severity <level>    Minimum severity (info|low|medium|high|critical)
  --format <fmt>        Output format (text|json)        [scan]
  --ai                  Use AI API (requires SECPATCH_AI_API_KEY)   [patch|orchestrate]
  --test-cmd <cmd>      Test command to run after patch             [patch|orchestrate|test]
  --draft-only          Print draft diffs without applying          [patch]
  --fail-on-findings    Exit 1 when findings are detected           [ci]
  --iterations <n>      Max AI retry iterations                     [orchestrate]
  --timeout <n>         Sandbox timeout seconds                     [test]

AI configuration:
  export SECPATCH_AI_API_KEY=<token>        # GitHub Models / OpenAI / Azure
  export SECPATCH_AI_BASE_URL=<url>         # optional (default: GitHub Models)
  export SECPATCH_AI_MODEL=<model>          # optional (default: gpt-4o)
`;

function printFindings(findings) {
  const lines = [
    "SEVERITY  RULE                     FILE                                     LINE TITLE",
    "----------------------------------------------------------------------------------------------------",
  ];
  for (const f of findings) {
    lines.push(
      `${f.severity.padEnd(9)} ${f.ruleId.padEnd(24)} ${f.file}:${f.line}`.padEnd(44) + f.title
    );
  }
  return lines.join("\n");
}

function _scan(detector, scanPath) {
  if (fs.statSync(scanPath).isFile()) return detector.scanFile(scanPath);
  return detector.scanPath(scanPath);
}

function _absFile(scanPathArg, findingFile) {
  if (path.isAbsolute(findingFile)) return path.resolve(findingFile);
  return path.resolve(path.join(scanPathArg, findingFile));
}

function cmdScan(args) {
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  const minSev = SEVERITY_ORDER[args.severity] || 0;
  const filtered = findings.filter((f) => (SEVERITY_ORDER[f.severity] || 0) >= minSev);

  if (args.format === "json") {
    console.log(JSON.stringify(filtered.map((f) => f.toDict()), null, 2));
  } else {
    if (filtered.length === 0) {
      console.log(`No vulnerabilities found in ${args.path}`);
    } else {
      console.log(printFindings(filtered));
      console.log(
        `\n${filtered.length} finding(s) in ${new Set(filtered.map((f) => f.file)).size} file(s)`
      );
    }
  }
  return filtered.length > 0 ? 1 : 0;
}

function cmdPatch(args) {
  const ai = args.ai ? new AIClient() : null;
  const orchestrator = new AIOrchestrator(ai);
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  if (findings.length === 0) {
    console.log("No vulnerabilities found - nothing to patch.");
    return 0;
  }

  let applied = 0;
  for (const f of findings) {
    const absFile = _absFile(args.path, f.file);
    if (!fs.existsSync(absFile)) {
      console.log(`[skip] ${f.file}:${f.line} - file not found`);
      continue;
    }

    const templateDiff = orchestrator._templatePatch(absFile, f);
    if (!templateDiff && !args.ai) {
      console.log(
        `[skip] ${f.file}:${f.line} [${f.ruleId}] - no draft available (set SECPATCH_AI_API_KEY for AI drafting)`
      );
      continue;
    }

    if (args.draftOnly) {
      const diff = templateDiff || null;
      if (!diff && args.ai) {
        console.log(`[skip] ${f.file}:${f.line} [${f.ruleId}] - AI drafting not yet implemented in draft-only mode`);
        continue;
      }
      console.log(`--- DRAFT for ${f.file}:${f.line} [${f.ruleId}] ---`);
      console.log(diff);
      console.log("--- end ---");
      continue;
    }

    const rootDir = fs.statSync(absFile).isDirectory() ? absFile : path.dirname(absFile);
    const relFile = path.relative(rootDir, absFile);
    const sandbox = new Sandbox(rootDir, 120);
    const tmp = sandbox.copyToTemp();
    let patched = false;
    try {
      const target = path.join(tmp, relFile);
      if (!fs.existsSync(target)) {
        console.log(`[fail] ${f.file}:${f.line} [${f.ruleId}] - file not found in sandbox`);
        continue;
      }
      applyDiffToFile(target, templateDiff);
      // syntax check
      try {
        require("acorn").parse(fs.readFileSync(target, "utf8"), { ecmaVersion: 2022, sourceType: "module" });
      } catch (e) {
        console.log(`[fail] ${f.file}:${f.line} [${f.ruleId}] - syntax error: ${e.message}`);
        continue;
      }
      if (args.testCmd) {
        const res = sandbox.run(args.testCmd, tmp, {}, 180);
        if (res.exitCode !== 0) {
          console.log(
            `[revert] ${f.file}:${f.line} [${f.ruleId}] - tests failed: ${(res.stderr || res.stdout || "").slice(-400)}`
          );
          continue;
        }
      }
      applyDiffToFile(absFile, templateDiff);
      applied++;
      console.log(`[patched] ${f.file}:${f.line} [${f.ruleId}] - template patch applied and validated`);
    } finally {
      sandbox.cleanup(tmp);
    }
  }
  console.log(`\n${applied} patch(es) applied and validated.`);
  return 0;
}

function cmdCommits(args) {
  const since = new Date();
  since.setDate(since.getDate() - (args.since || 30));
  try {
    const log = execSync(`git log --since="${since.toISOString()}" --pretty=format:"%H%x09%s%x09%ad" --date=short --all`, {
      cwd: args.path,
      encoding: "utf8",
    }).trim();
    if (!log) {
      console.log("No git history found.");
      return 0;
    }
    const keywords = ["cve", "vuln", "security", "patch", "fix", "sql injection", "xss", "hardcod", "secret", "credential", "token", "ssrf", "path traversal", "rce", "auth", "bypass"];
    const lines = ["Security-relevant commits:", "----------------------------------------------------------------------------------------------------"];
    let count = 0;
    for (const entry of log.split("\n")) {
      const parts = entry.split("\t");
      if (parts.length < 3) continue;
      const [hash, subject, date] = parts;
      const blob = `${hash} ${subject}`.toLowerCase();
      if (!keywords.some((k) => blob.includes(k))) continue;
      count++;
      lines.push(`${date}  ${hash.slice(0, 10)}  ${subject}`);
    }
    if (count === 0) lines.push("None found.");
    console.log(lines.join("\n"));
  } catch (e) {
    console.log("No git history found.");
  }
  return 0;
}

function cmdCi(args) {
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  const minSev = SEVERITY_ORDER[args.severity] || 0;
  const filtered = findings.filter((f) => (SEVERITY_ORDER[f.severity] || 0) >= minSev);
  if (filtered.length > 0) {
    console.log(`CI: ${filtered.length} vulnerability(s) at ${args.severity}+ severity:`);
    console.log(printFindings(filtered));
    if (args.failOnFindings) return 1;
    console.log("CI: findings reported (--fail-on-findings not set, not failing build).");
    return 0;
  }
  console.log("CI: no vulnerabilities found.");
  return 0;
}

function cmdTest(args) {
  const generator = new TestGenerator(args.path, args.timeout);
  const results = generator.runAll();
  let totalFound = 0, failed = 0;
  for (const r of results) {
    totalFound += r.methodsFound;
    const status = r.result.exitCode === 0 ? "passed" : "failed";
    if (r.result.exitCode !== 0) failed++;
    console.log(`${r.module}: ${r.methodsFound} method(s), ${status} (exit ${r.result.exitCode})`);
    if (r.result.stderr && r.result.exitCode !== 0) {
      console.log(`    ${r.result.stderr.slice(-400)}`);
    }
  }
  console.log(`\n${totalFound} method(s) across ${results.length} module(s); ${failed} module(s) had test failures.`);
  return failed > 0 ? 1 : 0;
}

function cmdOrchestrate(args) {
  const ai = args.ai ? new AIClient() : null;
  if (args.ai && !ai.available()) {
    console.log("[orchestrate] --ai requested but SECPATCH_AI_API_KEY is not set; using templates only");
  }
  const orchestrator = new AIOrchestrator(ai, args.iterations || 3);
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  const minSev = SEVERITY_ORDER[args.severity] || 0;
  const filtered = findings.filter((f) => (SEVERITY_ORDER[f.severity] || 0) >= minSev);
  if (filtered.length === 0) {
    console.log("No vulnerabilities found - nothing to orchestrate.");
    return 0;
  }

  let applied = 0;
  for (const f of findings) {
    const absFile = _absFile(args.path, f.file);
    if (!fs.existsSync(absFile)) {
      console.log(`[skip] ${f.file}:${f.line} - file not found`);
      continue;
    }
    const rootDir = fs.statSync(absFile).isDirectory() ? absFile : path.dirname(absFile);
    const relFile = path.relative(rootDir, absFile);

    // Run orchestration synchronously via a helper that returns a promise.
    // For CLI simplicity, use a top-level await wrapper (see main).
    console.log(`[queue] ${f.file}:${f.line} [${f.ruleId}] - orchestration requires async; use Node directly`);
  }
  return 0;
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq > 0) {
        args[a.slice(2, eq)] = a.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith("-")) {
          args[a.slice(2)] = next;
          i++;
        } else {
          args[a.slice(2)] = true;
        }
      }
    } else {
      args._.push(a);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);
  const command = args._[0];
  if (!command) {
    console.log(USAGE);
    process.exit(1);
  }

  // Fill defaults.
  args.path = args._[1] || ".";
  args.severity = args.severity || "info";
  args.format = args.format || "text";
  args.since = args.since ? parseInt(args.since, 10) : 30;
  args.timeout = args.timeout ? parseInt(args.timeout, 10) : 120;
  args.iterations = args.iterations ? parseInt(args.iterations, 10) : 3;
  args.failOnFindings = args.failOnFindings === "true";
  args.draftOnly = args.draftOnly === "true";
  args.ai = args.ai === "true";

  switch (command) {
    case "scan":
      process.exit(cmdScan(args));
    case "patch":
      process.exit(cmdPatch(args));
    case "commits":
      process.exit(cmdCommits(args));
    case "ci":
      process.exit(cmdCi(args));
    case "test":
      process.exit(cmdTest(args));
    case "orchestrate": {
      const ai = args.ai ? new AIClient() : null;
      const orchestrator = new AIOrchestrator(ai, args.iterations);
      const detector = new Detector();
      const findings = _scan(detector, args.path);
      const minSev = SEVERITY_ORDER[args.severity] || 0;
      const filtered = findings.filter((f) => (SEVERITY_ORDER[f.severity] || 0) >= minSev);
      if (filtered.length === 0) {
        console.log("No vulnerabilities found - nothing to orchestrate.");
        process.exit(0);
      }
      let applied = 0;
      for (const f of filtered) {
        const absFile = _absFile(args.path, f.file);
        if (!fs.existsSync(absFile)) {
          console.log(`[skip] ${f.file}:${f.line} - file not found`);
          continue;
        }
        const rootDir = fs.statSync(absFile).isDirectory() ? absFile : path.dirname(absFile);
        const relFile = path.relative(rootDir, absFile);
        const result = await orchestrator.patchWithValidation(rootDir, relFile, f, args.testCmd || null);
        if (result.applied) {
          applied++;
          console.log(
            `[patched] ${f.file}:${f.line} [${f.ruleId}] (${result.iterations} iteration(s)) - ${result.message}`
          );
        } else {
          console.log(`[revert] ${f.file}:${f.line} [${f.ruleId}] - ${result.message}`);
        }
      }
      console.log(`\n${applied} patch(es) applied and validated.`);
      process.exit(0);
    }
    default:
      console.error(`Unknown command: ${command}`);
      console.log(USAGE);
      process.exit(1);
  }
}

main().catch((e) => {
  console.error(e.stack);
  process.exit(1);
});
