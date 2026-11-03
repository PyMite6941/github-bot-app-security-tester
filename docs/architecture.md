# secpatch Architecture

## Goals

- **Zero alert fatigue**: findings ship with a draft fix, not just a warning.
- **Safe by default**: patches are validated in a sandbox before touching
  the working tree; failures revert automatically.
- **AI-connected**: any OpenAI-compatible endpoint (GitHub Models, OpenAI,
  Azure, Ollama, LM Studio) can power patch drafting.
- **Full method coverage**: every function/method gets an auto-generated
  test stub and is executed in isolation.

## Components

```
secpatch/
├── cli.py               # CLI: scan / patch / test / orchestrate / commits / ci
├── advanced_detector.py # AST + regex vulnerability rules (multi-language)
├── ai_client.py         # OpenAI-compatible chat client for diff drafting
├── ai_orchestrator.py   # Context gathering + iterative AI patching + validation
├── method_analyzer.py   # AST enumeration of every function/method/class
├── test_generator.py    # Auto-generated pytest stubs + sandbox test runs
├── patcher.py           # Unified-diff applier + deterministic template fixes
├── sandbox.py           # Isolated temp-dir execution with timeouts
└── __init__.py
```

## Data flow

### Scan
```
repo files -> advanced_detector (regex + AST) -> Finding[]
                                   -> dedupe -> sorted by severity
```

### Test every method
```
repo files -> method_analyzer (AST visitor) -> ModuleInfo (fn/methods/classes)
                                     -> test_generator (pytest stub per method)
                                     -> sandbox (temp copy, pip install pytest, run)
                                     -> TestRunResult per module
```

### Patch (AI orchestrator)
```
Finding -> gather enclosing function + imports (context)
        -> AI drafts unified diff
        -> sandbox_copy_validate (temp copy, apply diff, compile, run tests)
        -> if fail: feed error back to AI, retry (max N iterations)
        -> if pass: apply to working tree
```

## Safety guarantees

- The host working tree is **never** modified until a patch passes sandbox
  validation (compile + test command).
- Each validation run uses a fresh temp copy, so one bad patch cannot
  corrupt another.
- Only a safe subset of rules has deterministic template fixes; everything
  else requires AI (opt-in via `SECPATCH_AI_API_KEY`) or is reported only.
- Time bound: every sandbox command has a configurable timeout (default
  120s) to prevent hangs.

## Extending

- Add a regex rule: append to `REGEX_RULES` in `advanced_detector.py`.
- Add an AST rule: subclass `ast.NodeVisitor` in `advanced_detector.py`.
- Add a language: write a rule set keyed by file extension in
  `AdvancedDetector._is_scannable` / `scan_file`.
