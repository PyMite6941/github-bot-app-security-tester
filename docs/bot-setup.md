# SecPatch Bot Setup — Run on Any Repository

SecPatch can be deployed as a **GitHub Actions bot** that scans any repository on every
push, pull request, and daily schedule. It reports vulnerabilities, drafts AI-powered
patches, and posts results as PR comments or issues — all without modifying your source
unless you explicitly enable auto-apply.

## 1. Add SecPatch to Your Repository

Copy these files into your repo (or use this repo as a template):

```
.github/
  workflows/
    secpatch-bot.yml   # GitHub Actions workflow (see below)
secpatch.config.json   # Configuration (see below)
secpatch.schema.json   # JSON schema for validation
package.json           # npm package (if running locally)
```

You do **not** need to copy the `src/` directory — the workflow runs SecPatch from this
published package. Alternatively, vendor `src/` directly into your repo.

## 2. GitHub Actions Workflow

Create `.github/workflows/secpatch-bot.yml`:

```yaml
name: SecPatch Bot

on:
  push:
    branches: [master, main]
  pull_request:
    branches: [master, main]
  schedule:
    - cron: "0 2 * * *"
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  secpatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"

      - run: npm ci
      - run: npm test

      - name: Run SecPatch scan
        env:
          SECPATCH_AI_API_KEY: ${{ secrets.SECPATCH_AI_API_KEY }}
        run: |
          npx secpatch@latest ci . --severity high --log-file secpatch.log --format json > secpatch-scan.json || true

      - name: Upload results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secpatch-results
          path: |
            secpatch.log
            secpatch-scan.json
```

### Required secrets

| Secret | Purpose |
|--------|---------|
| `SECPATCH_AI_API_KEY` | AI API token (GitHub Models, OpenAI, Azure, Ollama) — optional; enables AI-powered patch drafting |
| `SECPATCH_AI_BASE_URL` | AI endpoint URL — optional (default: GitHub Models) |
| `SECPATCH_AI_MODEL` | Model name — optional (default: `gpt-4o`) |

## 3. Configuration (`secpatch.config.json`)

```json
{
  "version": "1.0",
  "logging": {
    "level": "info",
    "outputs": ["console", "file"],
    "file": "secpatch.log",
    "format": "json"
  },
  "scanner": {
    "minSeverity": "high",
    "skipDirs": [".git", "node_modules", ".venv", "dist", "build"],
    "skipExtensions": [".md", ".json", ".yml", ".lock"]
  },
  "patch": {
    "useAI": true,
    "maxIterations": 3,
    "testCmd": "npm test",
    "timeoutSeconds": 120,
    "draftOnly": false,
    "failOnFindings": false,
    "templateOnly": false
  },
  "ai": {
    "provider": "github-models",
    "apiKeyEnv": "SECPATCH_AI_API_KEY",
    "baseUrlEnv": "SECPATCH_AI_BASE_URL",
    "modelEnv": "SECPATCH_AI_MODEL",
    "defaultBaseUrl": "https://models.inference.ai.azure.com",
    "defaultModel": "gpt-4o",
    "timeoutSeconds": 60,
    "retry": { "maxAttempts": 3, "backoffMs": 2000 }
  },
  "bot": {
    "mode": "report-only",
    "postCommentOnPR": true,
    "createIssueOnCritical": true,
    "autoApplyPatches": false
  }
}
```

**`bot.mode`:**
- `report-only` (default): scan and report, never modify files. Safe for any repo.
- `auto-apply`: apply validated patches directly. Use only on repos where you review
  every change before merging.

## 4. AI Provider Configuration

SecPatch works with any OpenAI-compatible `/chat/completions` endpoint:

| Provider | `SECPATCH_AI_BASE_URL` | `SECPATCH_AI_MODEL` |
|----------|----------------------|---------------------|
| GitHub Models | `https://models.inference.ai.azure.com` | `gpt-4o` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` |
| Azure OpenAI | `https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-02-01` | deployment name |
| Ollama | `http://localhost:11434/v1` | `llama3` |
| LM Studio | `http://localhost:1234/v1` | `local-model` |

Without `SECPATCH_AI_API_KEY`, SecPatch runs in **template-only mode**: it detects
vulnerabilities and applies safe deterministic fixes (`eval()` → `safeEval()`,
hardcoded secrets → `process.env`), but does not use AI.

## 5. Safety Guarantees

- **Working tree is never modified** until a patch passes sandbox validation
  (compile + test command).
- **Each validation uses a fresh temp copy** — one bad patch cannot corrupt another.
- **Auto-apply is off by default** — patches are drafted and validated, but only
  written when you explicitly enable `bot.autoApplyPatches`.
- **Report-only CI** — the default CI mode never fails the build on findings, so
  adding SecPatch to an existing repo won't break your pipeline.

## 6. Viewing Results

- **Logs:** `secpatch.log` (structured JSON Lines, uploaded as a workflow artifact).
- **Scan results:** `secpatch-scan.json` (all findings with severity, rule, file, line).
- **PR comments:** critical/high findings are posted as comments on pull requests.
- **Issues:** critical findings on push create a GitHub issue with `security` and
  `critical` labels.

## 7. Local Development

```bash
# Install
npm install

# Scan (exit 1 if findings)
npx secpatch scan . --severity high

# CI mode (report-only)
npx secpatch ci . --severity high

# Strict CI (fail on findings)
npx secpatch ci . --severity high --fail-on-findings

# Test every method
npx secpatch test .

# AI-powered patching
export SECPATCH_AI_API_KEY=<token>
npx secpatch orchestrate . --ai --test-cmd "npm test"

# Draft only (no changes)
npx secpatch patch . --ai --draft-only --test-cmd "npm test"

# With config file
npx secpatch scan . --config secpatch.config.json --log-level debug
```

## 8. Custom AI Provider

To add a provider not covered by the built-in OpenAI-compatible connector, implement
the `AIProvider` interface (`draftPatch(prompt)` returns a unified diff string) and
register it with `AIConnector`:

```js
const { AIConnector } = require("secpatch/src/aiConnector");
const connector = new AIConnector();
connector.register(myCustomProvider);
const diff = await connector.draftPatch(prompt);
```

## License

MIT