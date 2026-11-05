#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { Detector, SEVERITY_ORDER } = require("./detector");
const { Sandbox } = require("./sandbox");
const { TestGenerator } = require("./testGenerator");
const { Logger, defaultLogger } = require("./logger");
const { Config } = require("./config");
const { AIConnector, OpenAICompatibleProvider, createDefaultProvider } = require("./aiConnector");
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
  --config <path>       Path to secpatch.config.json (default: secpatch.config.json)
  --log-file <path>     Log file path (default: secpatch.log)
  --log-level <level>   Log level (debug|info|warn|error, default: info)
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

function cmdScan(args, logger, config) {
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  const minSev = SEVERITY_ORDER[args.severity] || 0;
  const filtered = findings.filter((f) => (SEVERITY_ORDER[f.severity] || 0) >= minSev);

  logger.info("Scan complete", {
    path: args.path,
    totalFindings: findings.length,
    filteredFindings: filtered.length,
    minSeverity: args.severity,
  });

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

function cmdPatch(args, logger, config) {
  const patchCfg = config.getPatchConfig();
  const useAI = args.ai || patchCfg.useAI;
  const testCmd = args.testCmd || patchCfg.testCmd;
  const maxIterations = args.iterations || patchCfg.maxIterations;

  const aiConnector = new AIConnector();
  let aiProvider = null;
  if (useAI && !patchCfg.templateOnly) {
    aiProvider = createDefaultProvider(config);
    if (aiProvider) {
      aiConnector.register(aiProvider);
    }
  }

  const orchestrator = new AIOrchestrator(aiConnector, maxIterations, patchCfg.timeoutSeconds);
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  if (findings.length === 0) {
    logger.info("No vulnerabilities found - nothing to patch", { path: args.path });
    console.log("No vulnerabilities found - nothing to patch.");
    return 0;
  }

  logger.info("Starting patch run", {
    path: args.path,
    findings: findings.length,
    useAI,
    maxIterations,
    draftOnly: args.draftOnly,
  });

  let applied = 0;
  for (const f of findings) {
    const absFile = _absFile(args.path, f.file);
    if (!fs.existsSync(absFile)) {
      logger.warn("File not found, skipping", { file: f.file, line: f.line, rule: f.ruleId });
      console.log(`[skip] ${f.file}:${f.line} - file not found`);
      continue;
    }

    const rootDir = fs.statSync(absFile).isDirectory() ? absFile : path.dirname(absFile);
    const relFile = path.relative(rootDir, absFile);

    if (args.draftOnly) {
      const templateDiff = orchestrator._templatePatch(absFile, f);
      if (!templateDiff && !useAI) {
        console.log(
          `[skip] ${f.file}:${f.line} [${f.ruleId}] - no draft available (set SECPATCH_AI_API_KEY for AI drafting)`
        );
        continue;
      }
      console.log(`--- DRAFT for ${f.file}:${f.line} [${f.ruleId}] ---`);
      console.log(templateDiff || "<AI draft - run without --draft-only to generate>");
      console.log("--- end ---");
      continue;
    }

    console.log(`[queue] ${f.file}:${f.line} [${f.ruleId}] - orchestration requires async mode`);
  }
  console.log(`\n0 patch(es) applied (use 'orchestrate' command for async AI patching).`);
  return 0;
}

function cmdCommits(args, logger) {
  const since = new Date();
  since.setDate(since.getDate() - (args.since || 30));
  try {
    const { execSync } = require("child_process");
    const log = execSync(`git log --since="${since.toISOString()}" --pretty=format:"%H%x09%s%x09%ad" --date=short --all`, {
      cwd: args.path,
      encoding: "utf8",
    }).trim();
    if (!log) {
      logger.info("No git history found", { path: args.path });
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
    logger.info("Commit scan complete", { path: args.path, securityCommits: count });
    console.log(lines.join("\n"));
  } catch (e) {
    logger.info("No git history found", { path: args.path });
    console.log("No git history found.");
  }
  return 0;
}

function cmdCi(args, logger, config) {
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  const minSev = SEVERITY_ORDER[args.severity] || 0;
  const filtered = findings.filter((f) => (SEVERITY_ORDER[f.severity] || 0) >= minSev);

  logger.info("CI scan complete", {
    path: args.path,
    totalFindings: findings.length,
    filteredFindings: filtered.length,
    minSeverity: args.severity,
    failOnFindings: args.failOnFindings,
  });

  if (filtered.length > 0) {
    console.log(`CI: ${filtered.length} vulnerability(s) at ${args.severity}+ severity:`);
    console.log(printFindings(filtered));
    if (args.failOnFindings) {
      logger.error("CI failing due to findings", { count: filtered.length });
      return 1;
    }
    console.log("CI: findings reported (--fail-on-findings not set, not failing build).");
    return 0;
  }
  console.log("CI: no vulnerabilities found.");
  return 0;
}

function cmdTest(args, logger, config) {
  const testCfg = config.getTest();
  const timeout = args.timeout || testCfg.timeoutSeconds;
  const generator = new TestGenerator(args.path, timeout);
  const results = generator.runAll();
  let totalFound = 0, failed = 0;
  for (const r of results) {
    totalFound += r.methodsFound;
    const status = r.result.exitCode === 0 ? "passed" : "failed";
    if (r.result.exitCode !== 0) failed++;
    logger.info("Module test result", {
      module: r.module,
      methodsFound: r.methodsFound,
      status,
      exitCode: r.result.exitCode,
    });
    console.log(`${r.module}: ${r.methodsFound} method(s), ${status} (exit ${r.result.exitCode})`);
    if (r.result.stderr && r.result.exitCode !== 0) {
      console.log(`    ${r.result.stderr.slice(-400)}`);
    }
  }
  logger.info("Test run complete", {
    totalMethods: totalFound,
    modules: results.length,
    failedModules: failed,
  });
  console.log(`\n${totalFound} method(s) across ${results.length} module(s); ${failed} module(s) had test failures.`);
  return failed > 0 ? 1 : 0;
}

async function cmdOrchestrate(args, logger, config) {
  const patchCfg = config.getPatchConfig();
  const useAI = args.ai || patchCfg.useAI;
  const testCmd = args.testCmd || patchCfg.testCmd;
  const maxIterations = args.iterations || patchCfg.maxIterations;

  const aiConnector = new AIConnector();
  let aiProvider = null;
  if (useAI) {
    aiProvider = createDefaultProvider(config);
    if (aiProvider) {
      aiConnector.register(aiProvider);
    } else {
      logger.warn("AI requested but no API key configured; using templates only");
    }
  }

  const orchestrator = new AIOrchestrator(aiConnector, maxIterations, patchCfg.timeoutSeconds);
  const detector = new Detector();
  const findings = _scan(detector, args.path);
  const minSev = SEVERITY_ORDER[args.severity] || 0;
  const filtered = findings.filter((f) => (SEVERITY_ORDER[f.severity] || 0) >= minSev);

  if (filtered.length === 0) {
    logger.info("No vulnerabilities found - nothing to orchestrate", { path: args.path });
    console.log("No vulnerabilities found - nothing to orchestrate.");
    return 0;
  }

  logger.info("Starting orchestration", {
    path: args.path,
    findings: filtered.length,
    useAI,
    maxIterations,
  });

  let applied = 0;
  for (const f of filtered) {
    const absFile = _absFile(args.path, f.file);
    if (!fs.existsSync(absFile)) {
      logger.warn("File not found, skipping", { file: f.file, line: f.line, rule: f.ruleId });
      console.log(`[skip] ${f.file}:${f.line} - file not found`);
      continue;
    }
    const rootDir = fs.statSync(absFile).isDirectory() ? absFile : path.dirname(absFile);
    const relFile = path.relative(rootDir, absFile);

    const result = await orchestrator.patchWithValidation(rootDir, relFile, f, testCmd || null);
    if (result.applied) {
      applied++;
      logger.info("Patch applied", {
        file: f.file,
        line: f.line,
        rule: f.ruleId,
        iterations: result.iterations,
        message: result.message,
      });
      console.log(
        `[patched] ${f.file}:${f.line} [${f.ruleId}] (${result.iterations} iteration(s)) - ${result.message}`
      );
    } else {
      logger.warn("Patch reverted", {
        file: f.file,
        line: f.line,
        rule: f.ruleId,
        message: result.message,
      });
      console.log(`[revert] ${f.file}:${f.line} [${f.ruleId}] - ${result.message}`);
    }
  }
  logger.info("Orchestration complete", { applied, total: filtered.length });
  console.log(`\n${applied} patch(es) applied and validated.`);
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

  // Load config and logging first.
  const config = new Config(args.config || "secpatch.config.json");
  if (!config.isLoaded() && config.getLoadError()) {
    defaultLogger.warn(config.getLoadError());
  }

  const logCfg = config.getLoggingConfig();
  const logger = new Logger({
    level: args.logLevel || logCfg.level,
    outputs: logCfg.outputs,
    file: args.logFile || logCfg.file,
    format: logCfg.format,
  });

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
  args.logLevel = args.logLevel || logCfg.level;
  args.logFile = args.logFile || logCfg.file;

  logger.info("secpatch starting", {
    command,
    path: args.path,
    version: require(path.join(__dirname, "..", "package.json")).version,
  });

  let exitCode;
  try {
    switch (command) {
      case "scan":
        exitCode = cmdScan(args, logger, config);
        break;
      case "patch":
        exitCode = cmdPatch(args, logger, config);
        break;
      case "commits":
        exitCode = cmdCommits(args, logger);
        break;
      case "ci":
        exitCode = cmdCi(args, logger, config);
        break;
      case "test":
        exitCode = cmdTest(args, logger, config);
        break;
      case "orchestrate":
        exitCode = await cmdOrchestrate(args, logger, config);
        break;
      default:
        console.error(`Unknown command: ${command}`);
        console.log(USAGE);
        process.exit(1);
    }
  } finally {
    logger.close();
  }
  process.exit(exitCode ?? 0);
}

main().catch((e) => {
  defaultLogger.error("Fatal error", { error: e.message, stack: e.stack });
  console.error(e.stack);
  process.exit(1);
});
