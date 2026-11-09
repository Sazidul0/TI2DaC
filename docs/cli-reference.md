# CLI reference

[Back to README](../README.md)

| Command | Purpose |
|---|---|
| `run`, `analyze`, `generate` | Full pipeline, or the two-step analyse / choose / generate flow |
| `convert [--client C]`, `check` | Convert or validate existing Sigma rules (no AI) |
| `chain <run> <rule> <rule> … --within 10m --on host` | Join existing rules into a multi-event detection (no AI) |
| `client list / init / check` | Client profiles: list, write a starter, validate and preview queries |
| `replay`, `rule-test` | Run a rule against lab/incident logs; run rule unit tests (CI) |
| `test record`, `review` | Record test results and dispositions; approve or reject rules |
| `ai-review <run> [--model M\|code] [--provider P] [--show]` | Second opinion on a run against its report: ti2dac's checks, then the chosen model; prints the findings |
| `feedback add / list / apply / resolve / export`, `lessons` | Feedback loop and the lessons learned from it |
| `export`, `sigmahq-sync` | Hand-off to a detection repository; refresh the SigmaHQ duplicate index |
| `ai-status [--reset]` | AI provider health: key configured, limits hit, requests today; clear a pause |
| `health [--json]` | Database, disk space, AI provider and stuck jobs; exit code 1 when a check fails |
| `model [<id>] [--provider P] [--stage S] [--refresh]` | List or choose the provider and model (same setting as the web AI page) |
| `render <run> [--recheck]` | Rebuild a package; `--recheck` re-runs validation, conversion, self-tests, the safety lint, IOC extraction and the ATT&CK check with the current version, and re-checks kept AI translations (no AI, no tokens) |
| `lint-sim`, `targets`, `runs`, `attack-update` | Utilities |
| `serve`, `user add / list / remove` | Web UI and its users |
