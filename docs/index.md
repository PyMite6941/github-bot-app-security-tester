secpatch — Automated Vulnerability Patching / DevSecOps AI
==========================================================

A CI/CD-friendly open-source developer tool that does not just alert you to
security flaws: it finds them, drafts a clean code patch, applies it, and
validates that tests still pass before anything reaches production.

The problem
-----------
Finding bugs is fast. Writing, testing, and shipping the fix is the
bottleneck. Teams drown in alert fatigue while exploitable flaws sit in
the backlog. secpatch shifts the standard from "alert and wait" to
"automated, safe remediation".

Core capabilities
-----------------

1. Scan — Static analysis (Python AST + regex rules) finds SQL injection,
   hardcoded secrets, eval()/exec(), shell=True, dynamic SQL, unsafe
   innerHTML, insecure deserialization (pickle), weak crypto (MD5/SHA1),
   insecure randomness, path traversal, XXE, insecure cookies, and JS eval.

2. Test every method — `secpatch test` walks the AST of every Python file,
   enumerates every function and method, auto-generates a pytest stub for
   each one, and runs them in an isolated sandbox. Nothing ships without
   method-level coverage.

3. Draft — For every finding it produces a minimal unified diff. With
   SECPATCH_AI_API_KEY set, the draft is written by an AI API (GitHub
   Models, OpenAI, Azure OpenAI, or any OpenAI-compatible endpoint such
   as Ollama/LM Studio). Without a key, safe deterministic templates are
   used (eval() → ast.literal_eval(), hardcoded secrets → os.environ.get()).

4. Sandbox validation — Each patch is applied in a disposable copy of the
   repo, syntax-checked, and run against your test command. If validation
   fails, the patch is discarded and the original file is left untouched.
   The AI orchestrator iterates: on failure it feeds the error back to the
   AI and retries (up to N iterations).

5. Apply — Only validated patches are written to the working tree, ready
   for review and merge.

Install
-------

pip install -e .

Usage
-----

# Scan a repository (exit code 1 when findings exist - CI friendly)
secpatch scan . --severity high

# JSON output
secpatch scan . --format json

# Test every method in the repo (sandboxed)
secpatch test .

# Draft patches (printed, not applied)
secpatch patch . --ai --draft-only --test-cmd "pytest -q"

# Draft, validate in sandbox, and apply in one step
secpatch patch . --ai --test-cmd "pytest -q"

# AI-powered orchestration with context + iteration
secpatch orchestrate . --ai --test-cmd "pytest -q"

# Scan commit history for security fixes
secpatch commits . --since 30

# CI mode - fail the build on high+ severity findings
secpatch ci . --severity high

AI configuration
----------------

export SECPATCH_AI_API_KEY=<your token>          # GitHub Models / OpenAI / Azure
export SECPATCH_AI_BASE_URL=https://models.inference.ai.azure.com  # optional
export SECPATCH_AI_MODEL=gpt-4o                  # optional

The client posts to any OpenAI-compatible /chat/completions endpoint, so it
works with GitHub Copilot-compatible model endpoints, local models (Ollama,
LM Studio), or OpenAI directly.

CI/CD
-----

.github/workflows/secpatch.yml runs secpatch scan on every push and pull
request, fails the build on critical findings, and uploads scan results as
an artifact. When SECPATCH_AI_API_KEY is a repository secret, it also drafts
and validates patches automatically.

.github/workflows/pages.yml builds and deploys this documentation to
GitHub Pages on every push to master.

Algorithm overview
------------------

Detection:
  - Regex rules scan every line for dangerous API usage and literals.
  - Python AST rules track tainted data flow (f-strings → variables →
    db.execute()) so dynamically-built SQL is caught even when the string
    is assembled on a prior line.
  - Deduplication collapses overlapping regex/AST hits.

Testing:
  - AST visitor enumerates every function/method/class.
  - A pytest stub is generated per method and executed in a temp-dir
    sandbox copy of the repo.
  - Results are reported per-module so you know exactly which methods
    lack coverage.

Patching:
  - Template patches handle a safe subset without any AI.
  - The AI orchestrator gathers enclosing-function context + imports,
    requests a unified diff, validates in a sandbox, and on failure
    feeds the error back to the AI for a revised diff.
  - Only patches that compile and pass tests are written to disk.

License
-------

MIT
