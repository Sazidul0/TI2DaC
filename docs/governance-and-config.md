# Review, hand-off and configuration

[Back to README](../README.md)

## Review, feedback and governance

0. **Second opinion (optional):** the **AI review** card on a run's page (or `ti2dac ai-review <run> [--model M] [--provider P]`) checks the whole run against its report. ti2dac's own checks run first and cost nothing: selections the condition never uses, KQL string operators holding a `*` (a literal star in KQL, so the query never matches), IOCs cut in two at a PDF line break, and encryption keys listed as file hashes. Then the model you pick for that review (any provider whose key is set and whose TLP policy allows the report; the default is the `review` stage on the AI page) reads the report and the run's outputs and lists mistakes. A finding that rests on the report must quote it; quotes are machine-checked, and findings whose quote is not in the report are set aside as *discarded*, not shown as findings. Pick "ti2dac checks only" for a free review without an AI call. Findings change nothing until someone decides: **Accept** on a rule, query or simulation finding opens feedback on that rule (step 2 then fixes it as a new version); on an analysis or IOC finding it adds a run warning. **Dismiss** records why, and dismissed findings are passed to the next review so it does not raise them again. The review is marked *out of date* when a rule changes afterwards, and the runs list shows each run's review state.
1. **Report problems:** `ti2dac feedback add <run> rule-001 --artifact sigma_rule --category too_broad_fp --comment "..."`, or use the form on each rule in the web UI. Categories cover hallucinated evidence, wrong ATT&CK mapping, wrong logsource or field, logic error, false positives, false negatives, syntax, translation, unsafe simulation, simulation not triggering, incomplete cleanup and documentation.
2. **Fix:** attach a corrected rule, which is validated and saved as **v2** (v1 is archived in `rules/history/`), or use `ti2dac feedback apply <id> --ai`. Every new version starts as a draft.
3. **Learn:** applied feedback becomes a short *lesson*, stored per technique and log source. Up to 5 relevant lessons are added to future generation prompts. A lesson keeps the TLP of the run it came from and only reaches runs of the same or a stricter TLP whose provider may receive it. Manage them with `ti2dac lessons`.
4. **Record outcomes:** lab results and production alert dispositions (`fired`, `not_fired`, `quiet`, `false_positive`, `true_positive`, `benign_true_positive`) feed the validation matrix.
5. **Approve:** `ti2dac review <run> rule-001 --status approved`. Only users with the approver role can approve. **Four-eyes:** the author of a version, whoever generated or corrected it, cannot approve it, and a version with no recorded author cannot be approved at all. Identity in the CLI is the logged-in OS account; there is no `--reviewer` flag to type someone else's name. In the web UI it is the login. Approval moves the Sigma status from `experimental` to `test`.
6. **Audit and evaluate:** every action is in the audit log. `ti2dac feedback export` produces a JSONL regression set to run before changing models or prompts.

## Detection-as-code hand-off

`ti2dac export <run> --repo ../detections` copies **approved** rules into a Git repository:
`rules/<product>/<category>/`, `tests/`, `queries/<siem>/`, `simulations/` and `docs/`.

The first export also writes `.github/workflows/detections.yml`. On every pull request it validates the rules,
runs the rule unit tests (`ti2dac rule-test rules tests`) and converts the rules for every SIEM. Deploying to
SIEM APIs is left to your existing pipeline.

## Configuration

Copy `ti2dac.example.yaml` to `ti2dac.yaml`, which is git-ignored. The settings that matter most:

| Setting | Purpose |
|---|---|
| `redaction.internal_domains`, `redaction.terms`, `redaction.internal_networks`, `redaction.hostname_patterns` | What counts as internal and must be redacted |
| `ai.allowed_tlp`, `ai.default_tlp_incident` | Data-handling policy per AI provider |
| `telemetry: [windows:process_creation, windows:security, …]` | Log sources you actually collect: steers the model, and warns about rules that cannot fire yet |
| `index_overrides: {splunk: "index=wineventlog", elastic_esql: "logs-endpoint.events.*"}` | Scope queries to your indexes and tables |
| `rule_repos: [../detections/rules]` | Internal rules to check for duplicates (plus `ti2dac sigmahq-sync`) |
| `targets`, `ai_fill_gaps`, `llm_targets` | Which SIEMs to produce queries for, and where AI may fill gaps |
| `clients: [acme]`, `clients_dir: clients` | Client profiles to produce queries for (`["*"]` = all profiles) |
| `ai.provider`, `ai.<stage>.model / effort / max_tokens` | Provider, models and the token/quality trade-off (the web AI page / `ti2dac model` choice overrides these models) |
| `ai.failover_provider`, `ai.failover_model` | Second provider for outages only (off by default; TLP policy still applies) |
| `ai.prices: {model-id: [input, output, cache_read]}` | USD per 1M tokens for models ti2dac has no price for (e.g. a paid Gemini tier) |

Secrets come only from the environment: `ANTHROPIC_API_KEY` (or `ant auth login`) and `GEMINI_API_KEY`.
