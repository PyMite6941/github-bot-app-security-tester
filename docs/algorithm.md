# SecPatch Algorithm

SecPatch follows a deterministic **detect → context → draft → validate → apply → report** pipeline.
Every patch is validated in an isolated sandbox before touching the working tree. Failures revert
automatically.

## Pipeline Overview

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌─────────┐
│ Detect  │────▶│ Context  │────▶│ Draft    │────▶│ Validate │────▶│ Apply    │────▶│ Report  │
│ (SAST)  │     │ (AST)    │     │ (AI/Tmpl)│     │ (Sandbox)│     │ (Tree)   │     │ (Log)   │
└─────────┘     └──────────┘     └──────────┘     └──────────┘     └──────────┘     └─────────┘
```

## Stage 1 — Detect (SAST)

**Input:** repository path + minimum severity threshold.

The detector scans every scannable file (`.js`, `.mjs`, `.jsx`) using two complementary
techniques:

1. **Regex rules** — line-by-line pattern matching for dangerous API usage and literals
   (hardcoded secrets, `eval()`, `shell=True`, dynamic SQL concatenation, unsafe `innerHTML`,
   `pickle.load`, weak crypto `MD5/SHA1`, insecure `random()`, path traversal, XXE,
   insecure cookies, JS `eval`/`innerHTML`).

2. **AST rules** (via `acorn`) — parse JavaScript into an abstract syntax tree and apply
   context-aware checks:
   - Taint tracking: variables assigned from template literals or string concatenation
     are marked "tainted".
   - SQL injection: `db.query(\`...\`)` or `db.query(taintedVar)` flagged as critical.
   - `eval()`/`exec()` calls flagged as critical.

**Deduplication:** findings with the same `(ruleId, file, line)` from both regex and AST
are collapsed into one.

**Output:** sorted list of `Finding` objects (severity descending, then file, then line).

## Stage 2 — Context (AST)

**Input:** a `Finding` (file + line number).

The method analyzer (`methodAnalyzer.js`) walks the AST of the vulnerable file to gather
context for the AI:

- Enclosing function/class name and line range.
- The source snippet of the enclosing code block.
- All `import` statements in the file.

This context is passed to the AI so it drafts a fix that fits the existing code style
and dependencies, not an isolated line.

## Stage 3 — Draft (AI or Template)

**Input:** finding + context.

### AI drafting (when `SECPATCH_AI_API_KEY` is set)

The AI connector posts to any OpenAI-compatible `/chat/completions` endpoint (GitHub
Models, OpenAI, Azure OpenAI, Ollama, LM Studio). The prompt requests **one unified diff
only** — no markdown fences, no explanation. The diff header must match the file, one
hunk, three lines of context, exact line numbers.

The connector supports pluggable providers (`AIProvider` interface) and automatic retry
with exponential backoff on 429/5xx responses or network errors.

### Template drafting (no AI key, safe subset only)

Deterministic fixes for a small safe subset of rules:
- `SEC-EVAL-USAGE`: `eval(x)` → `safeEval(x)` (JSON.parse wrapper).
- `SEC-HARDCODED-SECRET`: `SECRET = "..."` → `SECRET = process.env.SECRET`.

All other rules require AI or are reported only.

## Stage 4 — Validate (Sandbox)

**Input:** repo root, relative file path, unified diff, optional test command.

Validation runs in a **disposable temp-directory copy** of the repo (`.git`,
`node_modules`, venvs, and build outputs excluded):

1. Copy repo to temp dir.
2. Apply the diff with `applyDiffToFile()` — throws `DiffError` on context/removal
   mismatch or missing file (never silently applies a wrong patch).
3. Syntax check with `acorn.parse()`.
4. If a test command is configured, run it (e.g. `npm test`) with a timeout.
5. Clean up the temp dir in a `finally` block.

**Result:** the patch passes validation only if it compiles cleanly AND (if tests are
configured) the test command exits 0.

## Stage 5 — Apply (Working Tree)

**Input:** validated diff + working tree file path.

Only patches that passed Stage 4 are written to the working tree via `applyDiffToFile()`.
The original file is never modified if validation failed.

## Stage 6 — Report (Logging)

**Input:** structured event records.

Every stage emits structured log entries (JSON Lines by default) to console and/or a log
file:
- Scan: path, finding count, filtered count, min severity.
- Patch: file, line, rule, useAI, iterations, draftOnly.
- CI: findings count, failOnFindings, pass/fail.
- Test: module, methods found, status, exit code.
- AI draft: provider, duration, diff length, success/failure, retryable.
- Apply/Revert: file, line, rule, iterations, message.

Log levels: `debug`, `info`, `warn`, `error`. Configurable via `secpatch.config.json`
or `SECPATCH_LOG_LEVEL` env var.

## Failure Handling

| Failure | Behavior |
|---------|----------|
| Diff context mismatch | `DiffError` thrown, patch not applied |
| Syntax error after patch | Patch reverted, not applied |
| Test command fails | Patch reverted, not applied |
| AI request fails | Retry with backoff (up to N attempts), then fall back to templates |
| All AI providers fail | Template-only mode; unreported rules skipped |
| Log file unavailable | Fall back to console-only logging |

## Example: End-to-End Patch

**Vulnerable code:**
```js
const API_KEY = "sk-1234567890abcdef";
```

**Detection:** `SEC-HARDCODED-SECRET` at line 1, severity high.

**Template draft:**
```diff
--- a/app.js
+++ b/app.js
-const API_KEY = "sk-1234567890abcdef";
+const API_KEY = process.env.API_KEY;
```

**Validation:** sandbox copy, apply diff, `acorn.parse()` OK, `npm test` passes.

**Apply:** working tree updated. Log entry written.

## Configuration Reference

See `secpatch.schema.json` for the full JSON schema. Key sections:

- `logging.level` / `logging.outputs` / `logging.file` / `logging.format`
- `scanner.minSeverity` / `scanner.skipDirs` / `scanner.skipExtensions`
- `patch.useAI` / `patch.maxIterations` / `patch.testCmd` / `patch.timeoutSeconds`
- `ai.provider` / `ai.apiKeyEnv` / `ai.baseUrlEnv` / `ai.modelEnv` / `ai.retry`
- `test.generateForEveryMethod` / `test.framework` / `test.timeoutSeconds`
- `bot.mode` / `bot.postCommentOnPR` / `bot.createIssueOnCritical` / `bot.autoApplyPatches`

## CLI Commands

| Command | Purpose |
|---------|---------|
| `scan <path>` | Static analysis; exit 1 when findings exist |
| `patch <path>` | Draft + validate + apply template patches |
| `orchestrate <path>` | AI-powered patch with context + iteration |
| `test <path>` | Generate + run a test for every method |
| `commits <path>` | Scan git history for security fixes |
| `ci <path>` | CI mode (report-only by default; `--fail-on-findings` for strict) |

Environment variables: `SECPATCH_AI_API_KEY`, `SECPATCH_AI_BASE_URL`,
`SECPATCH_AI_MODEL`, `SECPATCH_LOG_LEVEL`.
