"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_CONFIG = {
  version: "1.0",
  logging: {
    level: "info",
    outputs: ["console"],
    file: "secpatch.log",
    format: "json",
  },
  scanner: {
    minSeverity: "info",
    skipDirs: [
      ".git", ".svn", ".hg",
      "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
      "dist", "build", ".tox", ".egg-info", ".next", ".cache",
    ],
    skipExtensions: [
      ".md", ".rst", ".txt", ".html", ".htm", ".css", ".json", ".yml", ".yaml",
      ".toml", ".cfg", ".ini", ".lock",
      ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
      ".ttf", ".eot",
    ],
  },
  patch: {
    useAI: false,
    maxIterations: 3,
    testCmd: "npm test",
    timeoutSeconds: 120,
    draftOnly: false,
    failOnFindings: false,
    templateOnly: false,
  },
  ai: {
    provider: "github-models",
    apiKeyEnv: "SECPATCH_AI_API_KEY",
    baseUrlEnv: "SECPATCH_AI_BASE_URL",
    modelEnv: "SECPATCH_AI_MODEL",
    defaultBaseUrl: "https://models.inference.ai.azure.com",
    defaultModel: "gpt-4o",
    timeoutSeconds: 60,
    retry: {
      maxAttempts: 3,
      backoffMs: 2000,
    },
  },
  test: {
    generateForEveryMethod: true,
    framework: "jest",
    timeoutSeconds: 180,
  },
  bot: {
    mode: "report-only",
    postCommentOnPR: true,
    createIssueOnCritical: true,
    autoApplyPatches: false,
  },
};

class Config {
  constructor(configPath = "secpatch.config.json") {
    this.configPath = path.resolve(configPath);
    this.raw = { ...DEFAULT_CONFIG };
    this.loaded = false;
    this.loadError = null;

    try {
      if (fs.existsSync(this.configPath)) {
        const fileContent = fs.readFileSync(this.configPath, "utf8");
        const parsed = JSON.parse(fileContent);
        this.raw = this._deepMerge(DEFAULT_CONFIG, parsed);
        this.loaded = true;
      } else {
        this.loadError = `Config file not found: ${this.configPath} (using defaults)`;
      }
    } catch (e) {
      this.loadError = `Failed to load config ${this.configPath}: ${e.message} (using defaults)`;
    }
  }

  _deepMerge(target, source) {
    const result = { ...target };
    for (const key of Object.keys(source)) {
      if (
        source[key] &&
        typeof source[key] === "object" &&
        !Array.isArray(source[key]) &&
        result[key] &&
        typeof result[key] === "object" &&
        !Array.isArray(result[key])
      ) {
        result[key] = this._deepMerge(result[key], source[key]);
      } else {
        result[key] = source[key];
      }
    }
    return result;
  }

  get(section, key) {
    if (section && key !== undefined) {
      return this.raw[section] && this.raw[section][key] !== undefined
        ? this.raw[section][key]
        : DEFAULT_CONFIG[section] && DEFAULT_CONFIG[section][key];
    }
    if (section) return this.raw[section];
    return this.raw;
  }

  getAIConfig() {
    const ai = this.raw.ai;
    return {
      provider: ai.provider,
      apiKey: process.env[ai.apiKeyEnv] || "",
      baseUrl: process.env[ai.baseUrlEnv] || ai.defaultBaseUrl,
      model: process.env[ai.modelEnv] || ai.defaultModel,
      timeoutSeconds: ai.timeoutSeconds,
      retry: ai.retry,
    };
  }

  getScannerConfig() {
    return this.raw.scanner;
  }

  getPatchConfig() {
    return this.raw.patch;
  }

  getBotConfig() {
    return this.raw.bot;
  }

  getLoggingConfig() {
    return this.raw.logging;
  }

  isLoaded() {
    return this.loaded;
  }

  getLoadError() {
    return this.loadError;
  }
}

module.exports = { Config, DEFAULT_CONFIG };
