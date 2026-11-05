"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

class DiffError extends Error {
  constructor(message) {
    super(message);
    this.name = "DiffError";
  }
}

// ---------------------------------------------------------------------------
// Unified-diff parser & applier
// ---------------------------------------------------------------------------

function _parseDiff(diffText) {
  const files = {};
  let currentFile = null;
  let hunks = [];
  const lines = diffText.split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("--- ")) {
      if (currentFile !== null && hunks.length > 0) {
        if (!files[currentFile]) files[currentFile] = [];
        files[currentFile].push(...hunks);
        hunks = [];
      }
      currentFile = line.slice(4).trim();
      i++;
      continue;
    }
    if (line.startsWith("@@") && currentFile !== null) {
      // @@ -old_start[,old_count] +new_start[,new_count] @@
      const header = line.slice(3).split(" @@")[0];
      const oldPart = header.split(" ")[0];
      const oldStart = parseInt(oldPart.split(",")[0].slice(1), 10);
      const hunkLines = [];
      i++;
      while (
        i < lines.length &&
        " \\-+".includes(lines[i][0])
      ) {
        hunkLines.push(lines[i]);
        i++;
      }
      hunks.push([oldStart, hunkLines.length, 0, 0, hunkLines]);
      continue;
    }
    i++;
  }
  if (currentFile !== null && hunks.length > 0) {
    if (!files[currentFile]) files[currentFile] = [];
    files[currentFile].push(...hunks);
  }
  return files;
}

function applyDiffToFile(filePath, diffText) {
  const text = fs.readFileSync(filePath, "utf8");
  const hadTrailingNewline = text.endsWith("\n");
  const original = text.split("\n");
  const parsed = _parseDiff(diffText);

  const name = path.basename(filePath);
  let target = null;
  for (const key of Object.keys(parsed)) {
    if (key === name || path.posix.basename(key) === name || path.win32.basename(key) === name) {
      target = key;
      break;
    }
  }
  if (target === null) {
    throw new DiffError(`diff does not contain file ${name}`);
  }

  const newLines = [];
  let cursor = 0;
  for (const [oldStart, , , , hunkLines] of parsed[target]) {
    let start = Math.max(0, oldStart - 1);
    start = Math.min(start, original.length);
    newLines.push(...original.slice(cursor, start));
    cursor = start;
    for (const hline of hunkLines) {
      const code = hline.length > 1 ? hline.slice(1).replace(/\r$/, "") : "";
      if (hline.startsWith(" ")) {
        if (cursor >= original.length || original[cursor]?.replace(/\r$/, "") !== code) {
          throw new DiffError(
            `context mismatch at line ${cursor + 1}: expected ${JSON.stringify(code)}, got ${JSON.stringify(cursor < original.length ? original[cursor] : "EOF")}`
          );
        }
        newLines.push(code);
        cursor++;
      } else if (hline.startsWith("-")) {
        if (cursor >= original.length || original[cursor]?.replace(/\r$/, "") !== code) {
          throw new DiffError(
            `removal mismatch at line ${cursor + 1}: expected ${JSON.stringify(code)}, got ${JSON.stringify(cursor < original.length ? original[cursor] : "EOF")}`
          );
        }
        cursor++;
      } else if (hline.startsWith("+")) {
        newLines.push(code);
      }
      // "\\ No newline at end of file" — skip
    }
  }
  newLines.push(...original.slice(cursor));

  const result = newLines.join("\n") + (hadTrailingNewline ? "\n" : "");
  fs.writeFileSync(filePath, result, "utf8");
}

module.exports = { applyDiffToFile, DiffError };
