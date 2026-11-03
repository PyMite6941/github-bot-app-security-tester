# Connecting secpatch to an AI API

secpatch ships with deterministic template patches for a small safe subset
of rules. To get advanced, context-aware patching, connect an AI API.

## Supported endpoints

Any OpenAI-compatible `/chat/completions` endpoint works:

- **GitHub Models** — `https://models.inference.ai.azure.com` (default)
- **OpenAI** — `https://api.openai.com/v1`
- **Azure OpenAI** — your resource endpoint
- **Local models** — Ollama (`http://localhost:11434/v1`), LM Studio,
  anything exposing the OpenAI chat-completions shape

## Configuration

```bash
export SECPATCH_AI_API_KEY=<your token>
export SECPATCH_AI_BASE_URL=https://models.inference.ai.azure.com  # optional
export SECPATCH_AI_MODEL=gpt-4o                                    # optional
```

Or set them as GitHub repository secrets for CI/CD.

## What the AI does

When you run `secpatch patch --ai` or `secpatch orchestrate --ai`:

1. **Context gathering** — secpatch locates the enclosing function/class
   and the file's imports, so the AI sees the vulnerable code in context,
   not an isolated line.
2. **Draft** — the AI is asked for a single unified diff (no markdown,
   no explanation) that fixes only the reported vulnerability.
3. **Validate** — the diff is applied in a sandbox copy, syntax-checked,
   and run against your test command.
4. **Iterate** — if validation fails, the error is fed back to the AI and
   it revises the diff. Up to `max_iterations` (default 3) attempts.

## Example prompt (what secpatch sends)

```
You are a senior security engineer. Produce ONE unified diff that fixes the
vulnerability below. Output ONLY the diff - no markdown fences.

File: app.py
Vulnerability: SQL query built with an f-string (SEC-SQLI-FSTRING)
Severity: critical
Location: line 9
Fix hint: Use parameterised queries (placeholders) instead of f-strings in SQL.
Enclosing code: function get_user
...
Return the unified diff now:
```

## CI/CD with AI

Add `SECPATCH_AI_API_KEY` as a repository secret. The
`.github/workflows/secpatch.yml` "Draft and validate patches (AI)" step
runs automatically on push/PR and posts draft diffs as an artifact.

## Security notes

- The AI only receives the vulnerable file's context, not your entire repo
  (unless you scan a tiny repo).
- Diffs are never applied to the working tree without sandbox validation.
- Review AI-generated diffs before merging — treat them as a draft PR from
  a junior engineer, not a commit-ready fix.
