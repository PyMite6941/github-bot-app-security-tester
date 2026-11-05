#!/usr/bin/env node
"use strict";

/**
 * SecPatch Bot Webhook Server
 *
 * Receives GitHub webhook events and triggers security scans.
 * Can be deployed anywhere that runs Node.js (Cloudflare Workers, Vercel,
 * Railway, Fly.io, Heroku, AWS Lambda, Google Cloud Run, etc.).
 *
 * Deploy options:
 *   - Cloudflare Workers: wrangler deploy
 *   - Vercel: vercel deploy (api/server.js as serverless function)
 *   - Node.js: node server.js
 *   - Docker: see Dockerfile
 */

const http = require("http");
const crypto = require("crypto");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------

const PORT = process.env.PORT || 8080;
const WEBHOOK_SECRET = process.env.SECPATCH_WEBHOOK_SECRET;
const GITHUB_APP_ID = process.env.GITHUB_APP_ID;
const GITHUB_PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY;
const GITHUB_PRIVATE_KEY_PATH = process.env.GITHUB_PRIVATE_KEY_PATH;
const INSTALLATION_ID = process.env.GITHUB_INSTALLATION_ID;
const REPO_OWNER = process.env.SECPATCH_REPO_OWNER; // optional: scope to one owner
const LOG_LEVEL = process.env.SECPATCH_LOG_LEVEL || "info";

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

function log(level, msg, meta) {
  const order = { debug: 0, info: 1, warn: 2, error: 3 };
  if (order[level] < order[LOG_LEVEL]) return;
  const entry = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    message: msg,
  };
  if (meta && Object.keys(meta).length > 0) entry.meta = meta;
  console.log(JSON.stringify(entry));
}

function verifySignature(payload, signature) {
  if (!WEBHOOK_SECRET) {
    log("warn", "No SEPATCH_WEBHOOK_SECRET set — accepting all webhooks (insecure)");
    return true;
  }
  if (!signature) return false;
  const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET);
  hmac.update(payload);
  const expected = `sha256=${hmac.digest("hex")}`;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function getPrivateKey() {
  if (GITHUB_PRIVATE_KEY) return GITHUB_PRIVATE_KEY;
  if (GITHUB_PRIVATE_KEY_PATH) {
    try {
      return fs.readFileSync(GITHUB_PRIVATE_KEY_PATH, "utf8");
    } catch (e) {
      log("error", `Failed to read private key from ${GITHUB_PRIVATE_KEY_PATH}: ${e.message}`);
      return null;
    }
  }
  return null;
}

// ---------------------------------------------------------------
// Run secpatch scan in a temp clone
// ---------------------------------------------------------------

function runSecPatchScan(repoDir, options = {}) {
  const args = ["scan", repoDir, "--severity", options.severity || "high", "--format", "json"];
  try {
    const output = execSync(`node /path/to/secpatch/src/cli.js ${args.join(" ")}`, {
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
      timeout: 300000, // 5 minutes
    });
    return { success: true, output };
  } catch (e) {
    return {
      success: false,
      output: e.stdout ? e.stdout.toString() : "",
      stderr: e.stderr ? e.stderr.toString() : e.message,
    };
  }
}

// ---------------------------------------------------------------
// Webhook handlers
// ---------------------------------------------------------------

async function handlePullRequest(payload) {
  const pr = payload.pull_request;
  const repo = payload.repository;
  const action = payload.action;

  log("info", "Pull request event", {
    action,
    repo: repo.full_name,
    pr: pr.number,
    title: pr.title,
  });

  // Only scan on opened, reopened, or synchronize
  if (!["opened", "reopened", "synchronize"].includes(action)) {
    log("info", "Skipping PR action", { action });
    return { status: "skipped", reason: `action ${action} not scanned` };
  }

  // Clone the PR's head branch and scan
  const headRef = pr.head.ref;
  const headSha = pr.head.sha;
  const cloneUrl = pr.head.repo.clone_url;

  log("info", "Scanning PR head branch", { headRef, headSha, cloneUrl });

  const tmpDir = `/tmp/secpatch-${repo.id}-${pr.number}`;
  try {
    execSync(`git clone --depth 1 --branch ${headRef} ${cloneUrl} ${tmpDir}`, {
      timeout: 120000,
      maxBuffer: 50 * 1024 * 1024,
    });

    const result = runSecPatchScan(tmpDir, { severity: "high" });
    if (!result.success) {
      log("error", "Scan failed", { repo: repo.full_name, pr: pr.number, error: result.stderr });
      return { status: "error", error: result.stderr };
    }

    const findings = JSON.parse(result.output);
    const critical = findings.filter((f) => f.severity === "critical");
    const high = findings.filter((f) => f.severity === "high");

    log("info", "Scan complete", {
      repo: repo.full_name,
      pr: pr.number,
      findings: findings.length,
      critical: critical.length,
      high: high.length,
    });

    return {
      status: "scanned",
      findings,
      critical,
      high,
      repo: repo.full_name,
      pr: pr.number,
    };
  } catch (e) {
    log("error", "Failed to clone or scan PR", { repo: repo.full_name, pr: pr.number, error: e.message });
    return { status: "error", error: e.message };
  }
}

async function handlePush(payload) {
  const repo = payload.repository;
  const ref = payload.ref;

  log("info", "Push event", { repo: repo.full_name, ref });

  // Only scan pushes to default branch
  if (!ref.includes("/master") && !ref.includes("/main")) {
    log("info", "Skipping push to non-default branch", { ref });
    return { status: "skipped", reason: `not default branch: ${ref}` };
  }

  return { status: "scanned", note: "default branch push — workflow handles CI scan" };
}

async function handleSchedule(payload) {
  log("info", "Scheduled scan", payload);
  return { status: "scanned", note: "scheduled" };
}

async function handleCodeScanningAlert(payload) {
  const alert = payload.alert;
  const repo = payload.repository;
  log("info", "Code scanning alert", {
    repo: repo.full_name,
    alert: alert.number,
    rule: alert.rule?.name || alert.rule_id,
    severity: alert.rule?.severity,
  });
  return { status: "scanned", note: "code_scanning_alert" };
}

const HANDLERS = {
  pull_request: handlePullRequest,
  push: handlePush,
  schedule: handleSchedule,
  code_scanning_alert: handleCodeScanningAlert,
};

// ---------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------

function handleRequest(req, res) {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "text/plain" });
    res.end("Method Not Allowed");
    return;
  }

  const event = req.headers["x-github-event"];
  const signature = req.headers["x-hub-signature-256"];
  const deliveryId = req.headers["x-github-delivery"];

  if (!event) {
    res.writeHead(400, { "Content-Type": "text/plain" });
    res.end("Missing X-GitHub-Event header");
    return;
  }

  log("info", "Webhook received", { event, delivery: deliveryId });

  let body = "";
  req.on("data", (chunk) => {
    body += chunk;
  });
  req.on("end", async () => {
    if (!verifySignature(body, signature)) {
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("Invalid signature");
      return;
    }

    let payload;
    try {
      payload = JSON.parse(body);
    } catch (e) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("Invalid JSON payload");
      return;
    }

    log("info", "Processing event", { event, delivery: deliveryId, action: payload.action });

    const handler = HANDLERS[event];
    if (!handler) {
      log("info", "Unhandled event type", { event });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ignored", event }));
      return;
    }

    try {
      const result = await handler(payload);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
    } catch (e) {
      log("error", "Handler failed", { event, delivery: deliveryId, error: e.message });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "error", error: e.message }));
    }
  });
}

const server = http.createServer(handleRequest);

server.listen(PORT, () => {
  log("info", "SecPatch Bot webhook server listening", { port: PORT });
});

// Graceful shutdown
process.on("SIGTERM", () => {
  log("info", "SIGTERM received, shutting down");
  server.close(() => process.exit(0));
});
process.on("SIGINT", () => {
  log("info", "SIGINT received, shutting down");
  server.close(() => process.exit(0));
});

module.exports = { handleRequest, verifySignature };
