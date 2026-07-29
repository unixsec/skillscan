# Eval Dataset Scanning

SkillSpector treats authored eval datasets as test-case data, not installed
skill logic.

The static pattern analyzers skip these dataset files:

- `evals/evals.json`
- `evals/evals.jsonl`
- `evals/evals.yaml`
- `evals/evals.yml`
- `eval/dataset.json`
- `eval/dataset.jsonl`
- `eval/dataset.yaml`
- `eval/dataset.yml`

This applies to both the agentskills.io format and the legacy flat ACES format.
Security analysis still covers executable skill code, instructions, scripts,
dependencies, MCP metadata, and other install-time surfaces. Eval prompts,
expected outputs, assertions, and ground-truth strings are not treated as code
accessing credentials or exfiltrating data.
