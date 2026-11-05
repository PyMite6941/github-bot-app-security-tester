"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync, execSync } = require("child_process");

class Sandbox {
  constructor(repoRoot, timeout = 120) {
    this.repoRoot = path.resolve(repoRoot);
    this.timeout = timeout;
  }

  copyToTemp(ignore = null) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "secpatch-sandbox-"));
    const ignorePatterns = ignore || [
      ".git", "__pycache__", ".venv", "venv", "env", ".env",
      "node_modules", ".tox", ".egg-info", "dist", "build", ".next", ".cache",
    ];
    const ignoreSet = new Set(ignorePatterns);

    const copy = (src, dst) => {
      const stat = fs.statSync(src);
      if (stat.isDirectory()) {
        fs.mkdirSync(dst, { recursive: true });
        for (const entry of fs.readdirSync(src)) {
          if (ignoreSet.has(entry)) continue;
          copy(path.join(src, entry), path.join(dst, entry));
        }
      } else {
        fs.copyFileSync(src, dst);
      }
    };

    for (const entry of fs.readdirSync(this.repoRoot)) {
      copy(path.join(this.repoRoot, entry), path.join(tmp, entry));
    }
    return tmp;
  }

  run(command, cwd = this.repoRoot, env = {}, timeout = this.timeout) {
    const mergedEnv = { ...process.env, ...env };
    try {
      const result = execFileSync(
        process.platform === "win32" ? "cmd.exe" : "sh",
        process.platform === "win32" ? ["/c", command] : ["-c", command],
        {
          cwd,
          env: mergedEnv,
          timeout: timeout * 1000,
          maxBuffer: 10 * 1024 * 1024,
        }
      );
      return {
        command,
        cwd,
        exitCode: 0,
        stdout: result.toString("utf8"),
        stderr: "",
        timedOut: false,
      };
    } catch (e) {
      return {
        command,
        cwd,
        exitCode: e.status != null ? e.status : -1,
        stdout: e.stdout ? e.stdout.toString("utf8") : "",
        stderr: e.stderr ? e.stderr.toString("utf8") : e.message,
        timedOut: e.code === "ETIMEDOUT",
      };
    }
  }

  cleanup(dir) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // ignore
    }
  }
}

module.exports = { Sandbox };
