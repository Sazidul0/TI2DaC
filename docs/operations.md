# Operations: monitoring, web UI and output package

[Back to README](../README.md)

## Monitoring, logs and alerts

ti2dac writes **JSON lines** (one event per line) so your SIEM can ingest its own activity. Events carry metadata
only: ids, counts, models, tokens, durations and outcomes, never report text, prompts, model output, redaction maps
or keys (anything shaped like an API key is replaced with `[SECRET]`).

- **Where:** `.ti2dac/logs/ti2dac-web.jsonl` (the server) and `ti2dac-cli.jsonl` (commands), owner-readable only,
  rotated at `log.max_mb` with `log.backups` old files kept. Forward them with your log agent, or set `log.syslog`
  to send events straight to a syslog/SIEM collector. `log.json_stderr` also prints them for containers.
- **Fields on every line:** `ts`, `level`, `event`, `component` (web/cli), `host`, `pid`, and `run_id`, `job_id`,
  `request_id` when known. Responses carry the request id in `X-Request-ID`.
- **The audit log is never deleted automatically.** It stays in the database and every entry is also an `audit` event.

| Event | When | Useful for |
|---|---|---|
| `ai.call` | every AI request: `stage`, `provider`, `model`, `served_by`, `outcome` (ok, cached, refused, outage, truncated, error, paused, rate_limited, quota_exhausted, auth_error), `latency_ms`, tokens, `cost_usd` | AI request and token/cost metrics |
| `ai.failover`, `ai.schema_retry` | failover to the second provider; a corrective re-ask | provider outage alerts |
| `ai.unconstrained` | Anthropic could not compile a schema into an output grammar ("compiled grammar is too large"); that model and schema are then asked for plain JSON, validated by ti2dac | schema-size tracking |
| `run.finish`, `run.failed`, `rule.failed` | each pipeline run, with rule counts, tokens and cost | failed-run alerts |
| `job.start`, `job.finish`, `job.stopped` | web background jobs, with status and duration; `job.stopped` when a job was stopped by a user, hit `jobs.timeout_minutes` or its worker died | job monitoring |
| `audit` | every audit entry (`action`, `actor`, `details`), including `auth.failed` (wrong login), `access.denied` (role not allowed) and `csrf.refused` (cross-site request), at warning level | security monitoring |
| `http.request` | every web request: method, path, status, user, client, duration | access log |
| `cli.command` | each CLI command and the OS user | audit of operator actions |

Example alert rules for your SIEM: `event=run.failed` or `event=job.finish status=failed`; `event=ai.call
outcome=outage`; `event=audit action=auth.failed` more than 5 times from one `details.client` in 10 minutes;
`event=audit action IN (ai.key.set, ai.key.remove, user.add, tlp.override)`.

**Health:** `GET /healthz` (no login, so uptime checkers can poll it; no secrets in the answer) and `ti2dac health`
check the database (`PRAGMA quick_check`), free disk space for the state and output folders (`health.min_free_mb`),
the AI provider (no key, paused or down) and jobs running longer than `health.stuck_job_minutes`. Each check is
ok, warn or fail; `/healthz` returns 503 and `ti2dac health` exits 1 when one fails. AI problems only warn, because
everything except AI drafting keeps working.

**Background jobs:** each web job (analysis, generating more rules, AI rewrite from feedback) runs in its own
worker process (`jobs.isolation: process`). A report that makes the pipeline hang or run out of memory only stops
that job: the UI keeps working, the job page has a **Stop job** button (for the user who started it, approvers and
admins), and a job is stopped after `jobs.timeout_minutes` (default 180). Each worker is capped at `jobs.memory_mb`
(default 4096). Workers log through the server, so their events carry the same `job_id` and `run_id`.

## Web UI

`ti2dac serve` binds to `127.0.0.1`. The page-by-page guide is in [Getting started](getting-started.md#using-ti2dac-step-by-step).

Its main features:
- **Runs:** upload a report or give a URL, then pick behaviours.
- **Rules:** each rule's Sigma, queries, field mapping, simulation guide and ADS, plus the feedback, test and review forms.
- **Feedback and lessons:** pages for feedback, lessons and the audit log.
- **AI token usage:** in the header (today), on the Runs page (per run), on each run (per stage) and on the AI settings page (today and all time, with estimated cost).
- **JSON API:** available at `/api/docs`; `/api/ai-status` returns AI status and token counters.

Security:
- **Users and roles:** `ti2dac user add alice --role approver` (roles: analyst, approver, admin; salted PBKDF2 hashes). With users configured, login is required. Listening on another interface is refused until users exist.
- **Request protection:** same-origin check on every write, autoescaping, CSP and anti-framing headers.
- **Downloads:** a download never includes `source/` (original report, redaction map) or `evidence/` (raw logs), whatever the document type.
- **Jobs:** stored in SQLite, so they survive restarts.

For production, put the UI behind your SSO reverse proxy.

## Output package

```
output/<run-id>/
  report-summary.md            summary, provenance (AI provider/models, who ran it, TLP, redactions), detections, warnings, AI usage
  behaviour-analysis.yaml      all behaviours with evidence (verified flags), scores, ATT&CK checks
  telemetry-requirements.yaml  log sources, event IDs, key fields, audit-policy needs, blind spots
  iocs.json                    IOCs for enrichment (never used as rule logic); `excluded` lists values left out (keys, IDs, lab/reserved IPs, legitimate services, Windows files) with the reason
  rules/rule-001-*.yml         Sigma rule; threshold rules include a second document (Sigma correlation); history/ = old versions
  tests/rule-001.json          rule unit-test events
  queries/rule-001/            one file per SIEM + README with all queries and the field-mapping table
  simulations/rule-001/        guide (README), simulate.ps1|sh, cleanup.ps1|sh, atomic-test.yaml
  validation/validation-matrix.md
  documentation/rule-001-ads.md  Palantir ADS
  attack-navigator/layer.json
  FEEDBACK.md                  how to report problems and record tests for this run
  evidence/                    raw events found in an incident report (local)
  source/                      original report + SHA256SUMS (+ redaction-map.json for incidents; sensitive, never exported)
  run.json                     machine-readable record; packages can be re-rendered from it at zero token cost
```
