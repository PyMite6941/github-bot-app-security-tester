"use strict";

const fs = require("fs");
const path = require("path");

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

class Logger {
  constructor(opts = {}) {
    this.level = LEVELS[opts.level || process.env.SECPATCH_LOG_LEVEL || "info"] || 1;
    this.outputs = opts.outputs || ["console"];
    this.file = opts.file || "secpatch.log";
    this.format = opts.format || "json";
    this._fileStream = null;

    if (this.outputs.includes("file")) {
      try {
        this._fileStream = fs.createWriteStream(this.file, { flags: "a" });
      } catch (e) {
        // If we can't open the log file, fall back to console only.
        this.outputs = this.outputs.filter((o) => o !== "file");
        this.error(`Could not open log file ${this.file}: ${e.message}`);
      }
    }
  }

  _shouldLog(level) {
    return LEVELS[level] >= this.level;
  }

  _format(level, msg, meta) {
    const entry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message: msg,
    };
    if (meta && Object.keys(meta).length > 0) {
      entry.meta = meta;
    }
    if (this.format === "json") {
      return JSON.stringify(entry);
    }
    const metaStr = meta ? ` ${JSON.stringify(meta)}` : "";
    return `[${entry.timestamp}] [${entry.level}] ${msg}${metaStr}`;
  }

  _write(line) {
    if (this.outputs.includes("console")) {
      process.stdout.write(line + "\n");
    }
    if (this.outputs.includes("file") && this._fileStream) {
      this._fileStream.write(line + "\n");
    }
  }

  debug(msg, meta) {
    if (this._shouldLog("debug")) this._write(this._format("debug", msg, meta));
  }

  info(msg, meta) {
    if (this._shouldLog("info")) this._write(this._format("info", msg, meta));
  }

  warn(msg, meta) {
    if (this._shouldLog("warn")) this._write(this._format("warn", msg, meta));
  }

  error(msg, meta) {
    if (this._shouldLog("error")) this._write(this._format("error", msg, meta));
  }

  close() {
    if (this._fileStream) {
      this._fileStream.end();
      this._fileStream = null;
    }
  }
}

const defaultLogger = new Logger();

module.exports = { Logger, defaultLogger, LEVELS };
