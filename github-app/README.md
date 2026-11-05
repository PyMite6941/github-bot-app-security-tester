# SecPatch Bot - GitHub App Deployment

Deploy the SecPatch Bot as a GitHub App that can be installed on any repository.

## Option 1: GitHub App (Recommended)

Create a GitHub App from the manifest, then install it on your repositories.

### Step 1: Create the GitHub App

Go to https://github.com/settings/apps/new and use the manifest in
`github-app/manifest.json`, or create it manually with these settings:

| Setting | Value |
|---------|-------|
| GitHub App name | `secpatch-bot` |
| Homepage URL | `https://github.com/PyMite6941/github-bot-app-security-tester` |
| Webhook URL | `https://<your-server>/webhook` |
| Webhook secret | Generate a random string, set as `SEPATCH_WEBHOOK_SECRET` |
| Permissions → Contents | Read-only |
| Permissions → Pull requests | Read & write |
| Permissions → Issues | Read & write |
| Permissions → Security events | Read & write |
| Permissions → Checks | Read & write |
| Subscribe to events | Pull request, Push, Schedule, Code scanning alert |

### Step 2: Generate a Private Key

In the GitHub App settings, click "Generate a private key". Save it as
`private-key.pem` and set `GITHUB_PRIVATE_KEY` or
`GITHUB_PRIVATE_KEY_PATH` in your server environment.

### Step 3: Deploy the Webhook Server

The server in `github-app/server.js` can run anywhere Node.js runs:

```bash
# Local development
cd github-app
npm install
SEPATCH_WEBHOOK_SECRET=<your-secret> \
GITHUB_APP_ID=<your-app-id> \
GITHUB_PRIVATE_KEY_PATH=./private-key.pem \
node server.js
```

Or deploy to any platform:

| Platform | Deploy command |
|----------|---------------|
| Cloudflare Workers | `wrangler deploy` |
| Vercel | `vercel deploy` |
| Railway | `railway up` |
| Fly.io | `fly launch && fly deploy` |
| Docker | `docker build -t secpatch-bot github-app && docker run -p 8080:8080 secpatch-bot` |

### Step 4: Install the App on Your Repository

Go to your GitHub App page and click "Install App", then select the repository
or organization you want to protect.

## Option 2: GitHub Actions Workflow (No Server)

If you don't want to host a webhook server, use the GitHub Actions workflow
directly. Copy this into your repository at
`.github/workflows/secpatch.yml`:

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
          SECPATCH_LOG_LEVEL: info
        run: |
          node src/cli.js ci . --severity high --log-file secpatch.log --format json > secpatch-scan.json || true

      - name: Generate method-level tests
        run: |
          node src/cli.js test . --log-file secpatch.log --log-level info --timeout 180 || true

      - name: Upload results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secpatch-results
          path: |
            secpatch.log
            secpatch-scan.json

      - name: Post PR comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let findings = [];
            try {
              findings = JSON.parse(fs.readFileSync('secpatch-scan.json', 'utf8'));
            } catch (e) {}
            const critical = findings.filter(f => f.severity === 'critical');
            const high = findings.filter(f => f.severity === 'high');
            const body = [
              '## 🔒 SecPatch Bot Security Scan',
              '',
              `Found **${findings.length}** vulnerability(s): **${critical.length}** critical, **${high.length}** high.`,
              '',
              '| Severity | Rule | File | Line | Title |',
              '|----------|------|------|------|-------|',
            ].concat(
              findings.map(f =>
                `| ${f.severity} | \`${f.ruleId}\` | \`${f.file}\` | ${f.line} | ${f.title} |`
              )
            ).join('\n');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body.join('\n'),
            });
```

### Required secrets

| Secret | Purpose |
|--------|---------|
| `SECPATCH_AI_API_KEY` | AI API token (GitHub Models, OpenAI, Azure, Ollama) |
| `SECPATCH_AI_BASE_URL` | AI endpoint URL (optional, default: GitHub Models) |
| `SECPATCH_AI_MODEL` | Model name (optional, default: `gpt-4o`) |

## Option 3: Reusable Workflow

Call SecPatch from any workflow in your organization:

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [master, main]
  pull_request:

jobs:
  secpatch:
    uses: PyMite6941/github-bot-app-security-tester/.github/workflows/secpatch-reusable.yml@master
    secrets: inherit
```

## Verification

After setup, trigger a scan:

```bash
# Local
node src/cli.js scan . --severity high

# CI report (exit 0, reports findings)
node src/cli.js ci . --severity high

# Strict CI (exit 1 on findings)
node src/cli.js ci . --severity high --fail-on-findings

# AI-powered patching
export SECPATCH_AI_API_KEY=<token>
node src/cli.js orchestrate . --ai --test-cmd "npm test"
```

## Logs

All scans write structured JSON Lines to `secpatch.log` by default. View with:

```bash
tail -f secpatch.log
# or
jq . secpatch.log
```

## License

MIT