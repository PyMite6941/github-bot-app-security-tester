# secpatch Usage

## Installation

```bash
git clone https://github.com/PyMite6941/github-bot-app-security-tester.git
cd github-bot-app-security-tester
pip install -e .
```

## Commands

### `secpatch scan <path>`
Static analysis. Exit code 1 when findings exist (CI-friendly).

```bash
secpatch scan . --severity high          # text, high+
secpatch scan . --format json            # machine-readable
secpatch scan app.py                     # single file
```

### `secpatch test <path>`
Test every method. Walks the AST, generates a pytest stub per
function/method, runs them in an isolated sandbox.

```bash
secpatch test .
```

### `secpatch patch <path>`
Draft and validate patches. Without `--ai`, only safe template fixes
(eval→ast.literal_eval, secrets→env vars) are applied.

```bash
secpatch patch . --test-cmd "pytest -q"              # template only
secpatch patch . --ai --test-cmd "pytest -q"         # AI-powered
secpatch patch . --ai --draft-only                   # print diffs, don't apply
```

### `secpatch orchestrate <path>`
Full AI orchestration: context gathering + diff + sandbox validation +
iterative refinement on failure.

```bash
secpatch orchestrate . --ai --test-cmd "pytest -q"
```

### `secpatch commits <path>`
Scan git history for security-related commits (CVE, vuln, sql injection,
xss, hardcoded secret, etc.).

```bash
secpatch commits . --since 30
```

### `secpatch ci <path>`
CI mode: fail on high+ severity findings.

```bash
secpatch ci . --severity high
```

## Example vulnerable code caught

```python
API_KEY = "sk-1234567890abcdef"            # SEC-HARDCODED-SECRET

def get_user(db, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SEC-SQLI-FSTRING
    return db.execute(query).fetchall()

def config_value(raw):
    return eval(raw)                        # SEC-EVAL-USAGE
```

Resulting patches (template):

```python
import os
API_KEY = os.environ.get("API_KEY")

import ast
def config_value(raw):
    return ast.literal_eval(raw)
```
