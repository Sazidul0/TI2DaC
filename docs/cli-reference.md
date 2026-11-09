# CLI reference

[Back to README](../README.md)

The executable is `ti2dac`, installed by the package. Run `ti2dac --help` or
`ti2dac <command> --help` for the live option list. Commands use the current
directory's `ti2dac.yaml` when present.

## Setup and global options

```bash
pip install ti2dac
cp .env.example .env
cp ti2dac.example.yaml ti2dac.yaml
ti2dac --config /path/to/ti2dac.yaml --verbose <command>
```

The global options must appear before the command:

| Option | Meaning |
|---|---|
| `--config`, `-c` | Use a particular YAML configuration file |
| `--verbose`, `-v` | Enable verbose logging |

API keys belong in the environment or `.env`, never in YAML:
`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, and optionally `TI2DAC_PROVIDER` or
`TI2DAC_MODEL`. Use `ti2dac ai-status` to check configuration without printing
a key.

## Main pipeline

### One-command pipeline

```bash
ti2dac run report.html
ti2dac run report.pdf --count 5 --select B1,B3
ti2dac run incident.docx --incident --events evidence.jsonl
ti2dac run report.html --no-ai
```

`run` ingests the source, analyzes behaviours, generates selected rules,
validates them, converts them to configured SIEM targets, and writes
`output/<run-id>/`. Use `--out DIR` to choose another output directory,
`--client NAME` (repeatable) for client profiles, and `--tlp-override REASON`
only when the audited data-handling policy allows it.

### Two-step pipeline

```bash
ti2dac analyze report.html
ti2dac runs
ti2dac generate <run-id> --select B2,B5
ti2dac render <run-id>
```

`analyze` performs the report analysis first. Review the ranked behaviour IDs,
then use `generate` to spend generation tokens only on selected behaviours.
Previously completed analysis and responses are cached locally.

## Deterministic Sigma and test commands

```bash
ti2dac check rules/*.yml
ti2dac convert rules/*.yml --targets splunk,elastic_esql
ti2dac targets
ti2dac lint-sim simulations/rule-001/simulate.sh --cleanup simulations/rule-001/cleanup.sh
ti2dac replay --run <run-id> --rule-slug rule-001 --events lab.jsonl --expect match --record
ti2dac rule-test rules tests
ti2dac chain <run-id> rule-001 rule-003 --within 10m --on host
ti2dac render <run-id> --recheck
```

These commands do not call an AI unless a configured conversion gap explicitly
requires it. `--recheck` rebuilds validation, conversion, self-tests, safety
linting, IOC extraction, and ATT&CK checks with the installed version.

## Review, feedback, and export

```bash
ti2dac test record <run-id> rule-001 --target splunk --result fired
ti2dac feedback add <run-id> rule-001 --artifact sigma_rule \
  --category too_broad_fp --comment "Explain the issue"
ti2dac feedback list --run <run-id>
ti2dac feedback apply <feedback-id> --ai
ti2dac feedback resolve <feedback-id> --status applied
ti2dac lessons
ti2dac review <run-id> rule-001 --status approved
ti2dac export <run-id> --repo ../detections
```

Use `feedback apply` with a corrected Sigma document when fixing manually.
Every correction creates a new draft version and keeps the prior version in
the rule history. Approval requires an approver and a different author.
Only approved rules are exported.

## AI, health, and maintenance

```bash
ti2dac ai-status
ti2dac ai-status --reset
ti2dac model
ti2dac model <model-id> --provider anthropic --stage generate
ti2dac model --refresh
ti2dac ai-review <run-id> --model code --show
ti2dac health
ti2dac health --json
ti2dac attack-update
ti2dac sigmahq-sync
```

`ai-status --reset` is for an administrator after fixing a key, quota, or
provider problem. `health` checks the database, disk space, provider state,
and stuck jobs; it exits with status 1 when a check fails. `ai-review` does
not change a run until a reviewer accepts or dismisses its findings.

## Client profiles and users

```bash
ti2dac client list
ti2dac client init acme --targets splunk,elastic_esql
ti2dac client check acme --rule rules/example.yml
ti2dac user add alice --role analyst
ti2dac user add bob --role approver
ti2dac user list
ti2dac user remove alice
```

Client profiles live under `clients/` (or `clients_dir` in the YAML). Users
are stored locally with salted password hashes and can have `analyst`,
`approver`, or `admin` roles.

## Web UI mode

Start the local UI from the same environment as the CLI:

```bash
ti2dac serve
# open http://127.0.0.1:8000
ti2dac serve --host 127.0.0.1 --port 8080
```

By default it binds to loopback and runs in single-user local mode. Add users
to enable login and role checks:

```bash
ti2dac user add alice --role analyst
ti2dac user add bob --role approver
ti2dac serve
```

The UI provides:

1. **Runs:** upload a report or paste a public URL, choose document type and
   rule count, and monitor background jobs.
2. **Run details:** inspect evidence, ATT&CK mappings, Sigma, SIEM queries,
   field mappings, simulations, ADS, validation, token use, and downloads.
3. **Feedback and review:** submit corrections, record test results, manage
   lessons, and approve or reject rules with four-eyes review.
4. **AI settings:** choose provider and per-stage models, view limits and
   costs, refresh available models, and clear a handled pause as an admin.
5. **Health and API:** use `/healthz` for an unauthenticated liveness check and
   `/api/docs` for the authenticated API documentation.

The UI never runs generated simulations or connects to a SIEM. Downloads omit
the original report, redaction map, and raw evidence logs. For production,
bind only behind an authenticated reverse proxy/SSO and keep the service
private.

## Command groups

| Command | Purpose |
|---|---|
| `run`, `analyze`, `generate` | Full pipeline or analyze-then-select workflow |
| `check`, `convert`, `chain`, `targets` | Validate, convert, list targets, or correlate Sigma rules |
| `replay`, `rule-test`, `lint-sim`, `render` | Test events, run CI tests, lint scripts, or rebuild packages |
| `test`, `review`, `feedback`, `lessons` | Record outcomes and operate the review/learning workflow |
| `export`, `sigmahq-sync`, `attack-update` | Hand off approved content or refresh indexes |
| `ai-status`, `model`, `ai-review`, `health` | Operate AI settings, reviews, and health checks |
| `client`, `user` | Manage client profiles and web users |
| `serve`, `runs` | Start the UI or list generated runs |

## Files and exit behavior

The default state directory is `.ti2dac/` (database, cache, logs, model
status, and ATT&CK index). Generated packages are under `output/`; begin with
`report-summary.md`. CLI errors are printed to stderr and return a non-zero
exit code, making commands suitable for CI. Operational logs are JSONL and
contain metadata rather than report text, prompts, model output, or secrets.
