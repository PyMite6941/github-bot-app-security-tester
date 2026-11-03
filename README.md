# secpatch - Automated Vulnerability Patching / DevSecOps AI

A CI/CD-friendly open-source developer tool that does not just alert you to
security flaws: it finds them, drafts a clean code patch, applies it, and
validates that tests still pass before anything reaches production.

## The problem

Finding bugs is fast. Writing, testing, and shipping the fix is the
bottleneck. Teams drown in alert fatigue while exploitable flaws sit in
the backlog. secpatch shifts the standard from "alert and wait" to
"automated, safe remediation".

## What it does

1. **Scan** - Static analysis (Python AST + regex rules) finds SQL
   injection, hardcoded secrets, `eval()`/`exec()`, `shell=True`,
   dynamic SQL concatenation, and unsafe `innerHTML` assignments.
2. **Draft** - For every finding it produces a minimal unified diff.
   With `SECPATCH_AI_API_KEY` set, the draft is written by an AI API
   (GitHub Models, OpenAI, Azure OpenAI, or any OpenAI-compatible
   endpoint such as Ollama/LM Studio). Without a key, safe deterministic
   templates are used (`eval()` → `ast.literal_eval()`, hardcoded
   secrets → `os.environ.get(...)`).
3. **Validate** - Each patch is applied in an isolated copy of the repo,
   syntax-checked, and run against your test command (`pytest -q`, etc.).
   If validation fails, the patch is discarded and the original file is
   left untouched.
4. **Apply** - Only validated patches are written to the working tree,
   ready for review and merge.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan a repository (exit code 1 when findings exist - CI friendly)
secpatch scan . --severity high

# JSON output
secpatch scan . --format json

# Draft patches (printed, not applied)
secpatch patch . --ai --draft-only --test-cmd "pytest -q"

# Draft, validate, and apply in one step
secpatch patch . --ai --test-cmd "pytest -q"

# Scan commit history for security fixes
secpatch commits . --since 30

# CI mode - fail the build on high+ severity findings
secpatch ci . --severity high
```

## AI configuration

```bash
export SECPATCH_AI_API_KEY=<your token>          # GitHub Models / OpenAI / Azure
export SECPATCH_AI_BASE_URL=https://models.inference.ai.azure.com  # optional
export SECPATCH_AI_MODEL=gpt-4o                  # optional
```

The client posts to any OpenAI-compatible `/chat/completions` endpoint,
so it works with GitHub Copilot-compatible model endpoints, local models
(Ollama, LM Studio), or OpenAI directly.

## CI/CD

`.github/workflows/secpatch.yml` runs `secpatch scan` on every push and
pull request, fails the build on critical findings, and uploads the scan
results as an artifact. When `SECPATCH_AI_API_KEY` is a repository
secret, it also drafts and validates patches automatically.

## Example vulnerable code the detector catches

```python
API_KEY = "sk-1234567890abcdef"                    # SEC-HARDCODED-SECRET

def get_user(db, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SEC-SQLI-FSTRING
    return db.execute(query).fetchall()

def config_value(raw):
    return eval(raw)                                 # SEC-EVAL-USAGE
```

## Roadmap

- [ ] GitHub App that opens draft PRs with validated patches on `code_scanning` alerts
- [ ] Language-agnostic AST rules (JavaScript/TypeScript, Java, Go)
- [ ] Commit-history impact scoring (which commits introduced the flaw)
- [ ] Snyk/CodeQL SARIF import so secpatch can patch findings from other scanners

## License

MIT