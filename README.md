# ti2dac: Threat Intelligence → Detection-as-Code

ti2dac turns a **threat-intelligence report or an internal incident report** into a reviewed, tested detection package:

- the attacker behaviours (TTPs) in the report, with evidence quotes checked against the source and verified MITRE ATT&CK mappings
- one vendor-neutral **Sigma** rule per behaviour (single-event or threshold/correlation), validated with pySigma
- the same rule as native queries for **Splunk, Elastic, Microsoft Sentinel, Defender XDR, CrowdStrike NG-SIEM, QRadar, OpenSearch and Grafana Loki**, with a per-SIEM field-mapping table
- a **simulation and test guide** per rule: a safe lab script and its cleanup, the matching Atomic Red Team test, expected events, and positive and false-positive test procedures
- **unit tests** for each rule, plus local replay of real lab or incident logs, so you know a rule fires *before* it reaches a SIEM
- **ADS** triage documentation, telemetry requirements, a validation matrix and an ATT&CK Navigator layer
- a **feedback and review workflow**: error taxonomy, versioned corrections, lessons fed back into the AI, four-eyes approval and an audit log

The AI does the reading and the detection writing. Everything that can be deterministic is deterministic: conversion,
validation, documentation, safety checks and redaction. This keeps token use low and the output reproducible.

```
report ─► ingest ─► TLP policy ─► redact ─► condense ─► [AI] analyze ─► verify + rank ─► [AI] generate ─► check ─► convert ─► package
          DOCX/PDF/  RED never    users,    ~50% fewer   1 call          evidence,         1 call/rule      Sigma     12 SIEM
          HTML/EML/  leaves       hosts,    tokens,      structured      ATT&CK,           structured       self-test targets,
          MD/CSV/URL              IPs,      no IOCs      JSON            score cap         JSON             quality   0 tokens
                                  secrets                                                                   repair≤2
```

## Quick start

```bash
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"
cp .env.example .env                         # then add ANTHROPIC_API_KEY (see 'Setting up an AI provider')
cp ti2dac.example.yaml ti2dac.yaml           # then set your domains, customer names, telemetry

ti2dac run path/to/report.html               # public threat-intel report (file or URL)
ti2dac run IR-2026-0147.docx --incident --events host-sysmon.evtx   # internal incident report + its evidence logs
ti2dac serve                                 # web UI on http://127.0.0.1:8000
```

The two-step flow lets an analyst choose behaviours before any rule-generation tokens are spent:

```bash
ti2dac analyze report.html                   # 1 AI call: behaviours ranked as B1..Bn
ti2dac generate <run-id> --select B2,B5      # 1 AI call per chosen behaviour
```

Without AI (`--no-ai` or `TI2DAC_NO_AI=1`), the deterministic parts still work: ingestion, IOC extraction,
cited ATT&CK IDs, and validation, conversion, unit tests and replay of hand-written rules.

## Setting up an AI provider

The tool needs **one** API key, for Claude (default) or Gemini. Keys are read from the environment, or from a
`.env` file in the project folder. `.env` is git-ignored; copy `.env.example`. Keys are never stored in
`ti2dac.yaml`, the database, or the web UI.

**Claude (recommended)**
1. Sign in at **console.anthropic.com** with your company account, add billing, and open **API keys** → **Create key**. Create one key per environment.
2. Optionally, set a monthly **spend limit** on the workspace.
3. Put the key in `.env`:
   ```
   ANTHROPIC_API_KEY=sk-ant-...
   ```
   Alternatively, `export` it in your shell or run `ant auth login`.
4. Check it with `ti2dac ai-status`, or open the **AI settings** page in the web UI.
5. Pick the model under **Model** on that page (Opus 5.5 by default; Sonnet 5.5, Haiku 5.5, Fable 5.1 or Opus 5,
   for every stage or per stage), or run `ti2dac model claude-sonnet-5-5`.

A Claude.ai or Claude Code subscription is not an API key. API usage is billed separately in the Console.

**Gemini (Google AI Studio)**
1. Go to **aistudio.google.com** → **Get API key**, in a Google Cloud project with **billing enabled**.
2. Install the extra dependency: `uv pip install --python .venv/bin/python -e ".[gemini]"`.
3. Put the key and provider in `.env`:
   ```
   GEMINI_API_KEY=...
   TI2DAC_PROVIDER=gemini
   ```
   Or paste the key on the web **AI settings** page. If Claude has no key, Gemini becomes the active provider as
   soon as its key passes the check.
4. On a low quota, set `ai.daily_request_limit` in `ti2dac.yaml` a little under it (e.g. `18` for 20 a day).
   On a paid key, leave it at `0` and set `ai.max_parallel: 4`. The default of 1 parallel request is only there to be gentle on free keys.
   Free-tier quotas are per model (`gemini-flash-latest` is an alias of the newest Flash model). A run needs one
   request for the analysis plus about two to five per rule (generation, then AI translation for each SIEM no
   converter covers), so 20 requests a day is roughly four rules. A tested free-tier run on 2 November 2026 took
   2 to 7 minutes per call and saw `503 high demand` errors, which ti2dac retries and then reports per query.

> Free-tier Gemini keys allow about 20 requests a day, may use your prompts for training, and their abuse
> filters can react to attack-simulation content. Use them only for public reports and light testing.

### What happens when a limit is hit

The tool stops instead of hammering the provider:

| Situation | Behaviour |
|---|---|
| Daily/free-tier quota, credit balance or spend limit exhausted | Stops at once with **no retries**, and pauses AI calls until the reset time the provider gave |
| Per-minute rate limit | At most 2 short retries, then pauses until the provider's retry time |
| Your own `ai.daily_request_limit` reached | Pauses until local midnight, before the provider's limit is ever hit |
| Key missing, invalid or without permission | Pauses until the key is fixed and the pause is cleared |
| Model declines one request | That rule is skipped with a warning; not a pause |
| Provider down or overloaded (connection error, timeout, 5xx/529) | The SDK retries (Gemini: 2 retries); then `ai.failover_provider` answers if set and the report's TLP is allowed there, otherwise that step fails with a retry command. Not a pause |
| Response does not match the schema | One corrective re-ask that tells the model what failed; a second failure is reported |

- **The pause is shared.** It lives in `.ti2dac/ai_status.json`, so every CLI run and the web UI respect it, and no request is sent while it is active. Cache hits still work.
- **Finished work is kept.** Rules finished before the limit are kept, and each skipped behaviour gets a ready-to-paste retry command.
- **The web UI shows it everywhere.** A banner on every page shows the pause and the time left. AI jobs are not started while paused, and the **AI settings** page shows the provider, models, key status (never the key), today's request count, the last error and setup steps. Admins can clear a pause after fixing its cause.
- **The CLI has the same view:** `ti2dac ai-status` shows the status, and `ti2dac ai-status --reset` clears a pause.
- **Gemini runs one request at a time by default** (`ai.max_parallel`; raise it on a paid key).

The daily cap is **off by default** (`daily_request_limit: 0`). The automatic pause only reacts to the provider
saying "limit reached", so neither ever gets in the way of a working paid key.

## Using ti2dac, step by step

### 1. First-time setup (once)

```bash
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"   # add ",gemini" for Gemini, ",evtx" for EVTX replay
cp .env.example .env                    # add your API key (see "Setting up an AI provider")
cp ti2dac.example.yaml ti2dac.yaml      # set your internal domains, customer names, telemetry, SIEM index names
.venv/bin/ti2dac ai-status              # should say: credentials ... is set, state ok
.venv/bin/ti2dac sigmahq-sync           # optional: enables "possible duplicate of a SigmaHQ rule" hints
.venv/bin/ti2dac user add alice --role analyst      # web users (only needed for the web UI)
.venv/bin/ti2dac user add bob --role approver
.venv/bin/ti2dac user add admin --role admin
```

### 2. Using the web UI

Start it with `.venv/bin/ti2dac serve` and open **http://127.0.0.1:8000**. Sign in with a user from step 1.

**Header (every page):** the menu, your name and role, the AI status (on, off or paused) and **tokens used today**.
A red banner appears if AI calls are paused, and a yellow one if no API key is set.

**① Runs page (home): start a new package**
1. Upload the report (HTML, PDF, DOCX, EML, MD, TXT, CSV), or paste a public URL.
2. Choose how many rules to create (default 3) and, optionally, specific behaviours (`B1,B4`).
3. Pick the document type: *Auto-detect*, *Public threat-intel report*, or *Internal incident report*. Incident reports are redacted and treated as TLP:AMBER.
4. Click **Analyse report**. You land on a progress page that refreshes itself. It usually takes a few minutes, and then you are taken to the run.

The runs table lists every package with its date, AI calls, **tokens in/out**, estimated cost and a **zip** download.

**② Run page: everything about one report**
- **Header box:** source, SHA-256, actors and tools, summary, **AI usage** (calls, tokens, cost) and an expandable **token usage by stage** table. Warnings (unverified evidence, ATT&CK corrections, TLP, redactions) are listed below.
- **Behaviours table:** every behaviour found, with its ATT&CK technique, rank, and evidence quotes (✔ = found in the report, ✘ = possible hallucination). Tick more behaviours and click **Generate rules for selected behaviours** to add rules later; cached analysis means no re-reading cost.
- **One card per rule**, with chips at the top: version, technique, Sigma validity, **self-test**, review status, level, author. Below the chips:
  - **Sigma rule:** the YAML, validator notes and older versions.
  - **SIEM queries:** one per SIEM, each labelled (*not-tested*, *verify field names*, *AI-translated (unverified)*, *tested-positive* …).
  - **Field mapping:** how each field is named in each SIEM, with unsupported ones in red.
  - **Simulation & test guide:** lab requirements, safety review, the Atomic Red Team option, the ti2dac script and its cleanup, expected events, positive and negative test checklists.
  - **ADS:** goal, blind spots, false positives, analyst triage and response steps.
  - **Report a mistake / give feedback:** pick the artifact and category, explain, and optionally paste a corrected rule (it becomes the next version). Open items can be closed or **Fixed with AI**.
  - **Record test result / alert disposition:** per SIEM: fired, not fired, quiet, false positive, true positive, benign true positive.
  - **Review status:** draft, reviewed, approved or rejected. Approving needs the approver role, and nobody can approve their own version.

**③ Feedback & lessons page:** all feedback with its status, the *lessons* the AI receives on future runs (each can be disabled), the audit log, and a JSONL export.

**④ AI settings page:** provider, models, whether a key is configured, status and reset time, requests and
**tokens today and in total** with estimated cost, the last error, and setup steps. Admins can clear a pause here,
and choose the **provider and model** (one for every stage, or a different one per stage), with each model's price
and whether it has refusal fallback. *Refresh model list* asks the provider which models your key can use (no tokens).
The choice is saved in `.ti2dac/ai_models.json`, overrides `ti2dac.yaml`, and applies to jobs started after saving;
`TI2DAC_PROVIDER` / `TI2DAC_MODEL` in the server environment still win, and the page says so when they are set.

**⑤ Downloads:** the zip on the Runs page is the shareable package. It never includes the original report, the redaction map or raw logs.

### 3. The same with the command line

```bash
ti2dac run report.pdf                              # or a URL; add --incident --events logs.evtx for incident reports
ti2dac analyze report.pdf                          # two-step: see behaviours first …
ti2dac generate <run-id> --select B2,B4            # … then generate only the ones you want
ti2dac replay --run <run-id> --rule-slug rule-001 --events lab.evtx --expect match --record
ti2dac test record <run-id> rule-001 --target splunk --result fired --evidence "event 4711"
ti2dac feedback add <run-id> rule-001 --artifact sigma_rule --category too_broad_fp --comment "..."
ti2dac review <run-id> rule-001 --status approved  # as a different user than the author
ti2dac export <run-id> --repo ../detections        # approved rules into your Git detection repo
ti2dac ai-status                                   # key, limits, requests and tokens today
ti2dac model                                       # list models with prices; `ti2dac model <id> [--stage generate]` to choose (stages: analyze, generate, repair, translate, review)
```

Each `run` prints its AI calls and tokens at the end. The package folder is `output/<run-id>/`; start with `report-summary.md`.

### 4. Who does what

| Role | Typical work |
|---|---|
| **Analyst** | Uploads reports, picks behaviours, reads the rules and guides, runs the simulation in the lab, replays or records test results, files feedback and corrections |
| **Approver** (senior detection engineer) | Reviews another person's rules, checks the test evidence, approves or rejects, exports approved rules to the detection repo |
| **Admin** | Manages users, the AI key and limits, and clears AI pauses after a quota or billing problem is fixed |

## Inputs

### Public threat-intel reports

Vendor blogs, DFIR write-ups, CISA advisories, as HTML, PDF, Markdown, text or a URL. Incident-style write-ups
(The DFIR Report, CISA advisories) give the best rules. Strategic or annual reports are flagged as having
"little procedural detail", because rules from them would be generic.

### Internal incident reports

Often better input than public threat intel, because they carry exact command lines, process trees and timelines.
They also carry data that must not leave the company:

| Control | Behaviour |
|---|---|
| **Formats** | DOCX (paragraphs, headings and timeline tables), PDF, EML, Markdown, TXT, CSV/TSV. The type is auto-detected; force it with `--incident` / `--threat-intel`. |
| **Redaction before any AI call** | Usernames (profile paths, `DOMAIN\user`, `initial.lastname`, service accounts, user fields in pasted logs), internal hosts (internal FQDNs, UNC servers, host fields, naming schemes like `FIN-WS-0231`), private IPs, emails, SIDs, and passwords, keys and tokens are replaced with `[USER_1]`, `[HOST_2]`, `[SECRET]`. Attacker infrastructure and command lines are kept. The map back to real values stays in `source/redaction-map.json` and is never sent or exported. Secrets are not mapped at all. |
| **TLP 2.0 policy** | RED is never sent to an AI. Claude may receive CLEAR, GREEN or AMBER (after redaction). Gemini free tier may receive CLEAR or GREEN only. Unmarked incident reports count as AMBER. A violation stops the run and lists the options; `--tlp-override "<reason>"` is audited. |
| **No environment-specific rules** | A rule containing a placeholder (e.g. this incident's host) is sent back for repair. |
| **Proof from the incident itself** | Raw events pasted in the report, and logs passed with `--events` (EVTX/JSON/JSONL, kept local), are replayed against every rule: "would this rule have caught this incident?" A match is recorded in the validation matrix. |

Configure `redaction.internal_domains` (also yields NetBIOS names) and `redaction.terms` (customer and organisation
names): pattern matching cannot recognise arbitrary names written in prose.

## How the AI is used, and how tokens are kept low

A typical report costs **1 + N calls** (N = rules, default 3). Each run reports its token use and estimated cost.

| Technique | Effect |
|---|---|
| Report condensing: boilerplate, IOC tables, YARA, hex dumps and hashes removed; paragraphs ranked by TTP signal | A DFIR case drops from ~12K to ≤6K tokens (configurable budget) |
| IOCs extracted with regex and never sent to the model | Hashes and IOC appendices cost thousands of tokens |
| Rule generation sees only the behaviour, its verified quotes and short context, never the report | A few hundred input tokens per rule |
| Schema-constrained JSON output (structured outputs) | No prose and no format retries |
| IDs, dates, tags, references, docs, Atomic YAML and the Navigator layer are templated | Output tokens go to detection logic |
| SIEM translation with pySigma backends | **0 tokens** and reproducible. AI translation only fills gaps the backends cannot handle. |
| Thresholds, multi-event joins and Wazuh rules are generated by code (templates), not by the model | **0 tokens**, and no hallucinated correlation logic |
| Repairs only on real problems, at most 2, sending only the draft plus the error list | No tokens spent on a single vendor's gap |
| Per-stage effort: analyze `medium`, generate `high`, repair `medium`, translate `low` | Thinking is spent where it pays |
| Content-addressed response cache (prompt version + model + input) | Re-runs and later `--select` choices cost 0 tokens |

**Providers.** Claude (`claude-opus-5-5`) is the default, with server-side refusal fallback enabled because security
content can trip safety classifiers. When a fallback model answers, its tokens are priced at that model's rates
(and a refusal before any output is counted as free unless its category is billed). Models without a known price
are shown as *not priced* rather than $0. Gemini is optional, for testing with an AI Studio key:

```bash
uv pip install --python .venv/bin/python -e ".[gemini]"
export GEMINI_API_KEY=...                    # environment only, never in ti2dac.yaml
TI2DAC_PROVIDER=gemini ti2dac run report.html
```

Two things to know about Gemini:
- **Data use:** Google may use free-tier prompts to improve its products, which is why that tier only receives TLP:CLEAR/GREEN.
- **Rate limits and output length:** the provider retries on rate limits. Gemini counts thinking tokens toward its output limit, so a truncated answer is retried once with more room and less thinking.

## Quality and safety controls

AI output is treated as an untrusted draft. Each check below runs on every rule:

- **Evidence verification:** every quote is matched against the source. A behaviour with no verifiable quote is flagged as a possible hallucination and never auto-selected.
- **ATT&CK verification:** technique IDs are checked against a local index of MITRE ATT&CK v20 (refresh with `ti2dac attack-update`). Invalid, revoked or deprecated IDs are flagged and wrong tactics corrected. A revoked ID is replaced by its successor (e.g. T1562.001 → T1685 *Disable or Modify Tools*, tactic defense-impairment). Self-reported reproducibility is capped for techniques that cannot be simulated safely (credential dumping, destruction).
- **Sigma validation:** pySigma parsing and validators (the `sigma check` set), plus conversion by every backend.
- **Self-test:** the rule must match the event its own simulation produces and must not match benign look-alikes. A failure triggers a repair.
- **Brittleness:** a rule that depends on artifact names from this one intrusion (e.g. `socks32.exe`) is flagged and generalised, because attackers rename such files for free.
- **Duplicates:** compared with SigmaHQ (`ti2dac sigmahq-sync`, 3,300+ rules) and your own rule folders, so reviewers can extend an existing rule instead of adding a near-copy.
- **Honest status:** queries stay `not-tested` until a result is recorded. Labels such as *unsupported field*, *verify field names*, *check backend warning* and *AI-translated (unverified)* say exactly how far each query can be trusted.
- **Simulation safety:** scripts are never executed by the tool. The linter blocks credential access, destructive commands, log clearing, external downloads and security-tool tampering. It re-joins commands split across `Start-Process`/`-ArgumentList` and decodes `-EncodedCommand`, and it requires cleanup for any persistence created. Blocked scripts are replaced with a stub. Every script refuses to run unless `TI2DAC_LAB=1` is set.
- **Prompt-injection hygiene:** hidden (zero-width/bidi) characters are stripped, report text is wrapped as untrusted data, output is schema-constrained, and nothing the model writes is executed.
- **Network:** URL fetching blocks private, loopback and metadata addresses and re-checks every redirect. The original report is preserved with its SHA-256.

## Proving a rule works

| Level | How | Result recorded as |
|---|---|---|
| 1. Self-test (automatic) | Rule evaluated locally (pySigma SQLite backend, Sigma's case-insensitive semantics) against `tests/<rule>.json` | `Self-test: pass/fail` |
| 2. Local replay (no SIEM) | Run the simulation, export the events (EVTX or SIEM JSON), then `ti2dac replay --run <run> --rule-slug rule-001 --events lab.evtx --expect match --record`; use `--expect nomatch` on a normal-activity export for the false-positive test | `sigma_replay` column |
| 3. SIEM test | Run the converted query in the SIEM, then `ti2dac test record <run> rule-001 --target splunk --result fired` | per-SIEM column |

Statuses follow the plan's vocabulary: `not-tested`, `syntax-validated`, `desk-checked`, `tested-positive`, `tested-negative`, `tested-positive-and-negative`, `failed`.

## SIEM coverage

| Log source | Splunk | Elastic | Sentinel | Defender | CrowdStrike | QRadar | Wazuh |
|---|---|---|---|---|---|---|---|
| process_creation, file_event, registry_set, network_connection | ok | ok | ok | ok | ok | mostly | ok |
| ps_script (4104), Security/System events (4698, 7045 …), process_access, dns_query, image_load | ok | ok | AI-filled | AI-filled / partial | ok | partial | ok |
| linux process_creation | ok | ok (ti2dac ECS pipeline) | ok | ok | ok | ok | AI-filled if enabled |
| cloud (aws, azure, okta …) | verify fields | verify fields | AI-filled | AI-filled | verify fields | partial | AI-filled if enabled |
| threshold rules (Sigma correlation) | ok | ok (ES\|QL, EQL) | template | template | template | group-by must map | `frequency` rule |
| multi-event chains | template | template (EQL, ES\|QL) | template | template | — | — | — |

"template" = generated by ti2dac code from the converted single-event query, never by the AI.

- **Gap filling:** when no backend of a required SIEM family (`ai_fill_gaps`: Splunk, Elastic, Sentinel, Defender, CrowdStrike; add `wazuh` for non-Windows Wazuh rules) can convert a rule, one small AI call writes the query. It is grounded: it gets the Sigma-to-target field map (from the converters and the client profile), up to two verified converter outputs for other SIEMs as a logic reference, and the client's schema notes. Its answer is then checked against the same field map (and parsed, for Wazuh XML) and labelled unverified, with any problem listed as `CHECK:`. Threshold rules are never sent to the AI.
- **Converter fixes:** ti2dac corrects a known `OriginalFileName` mismapping in the ASIM backend and adds an ECS mapping for Linux.
- **No silent failures:** backend warnings, such as QRadar dropping a condition it cannot map, are surfaced on the query instead of hidden.

### Wazuh

There is no pySigma backend for Wazuh, so ti2dac generates both outputs itself, deterministically, for Windows
event channel logs (Sysmon, Security, System, PowerShell, Defender …):

- **`wazuh_rule`: rule XML for `local_rules.xml`.** Fields follow the eventchannel decoder (`win.eventdata.commandLine`,
  `win.system.eventID`), values become anchored, case-insensitive PCRE2. Each rule hangs off the most specific built-in
  rule for its event (Sysmon event 1 → `61603`, failed logon 4625 → `60122` …), because Wazuh only descends into the
  first matching child: a rule attached higher up never fires. The parent table comes from the Wazuh 4.9 default
  ruleset (`data/wazuh_parents.json`). OR branches become separate rules, `not` becomes `negate="yes"`, and thresholds
  become a `frequency`/`timeframe` rule with `<same_field>`. Rule ids fall in 100000-119999; renumber them to your
  range and run `wazuh-logtest` before deploying.
- **`wazuh_indexer`: Lucene hunting query** for the Wazuh dashboard (`data.win.eventdata.*`). `wazuh-alerts-*` only
  holds events that matched a rule; hunt over `wazuh-archives-*` (needs `logall_json`).

### Correlations: thresholds and multi-event chains

Models are good at single-event logic and unreliable at stateful joins, so the AI never writes correlation logic.

- **Thresholds** ("10 failed logons from one IP in 5 minutes"): the model only marks the behaviour as a count or
  distinct count; ti2dac writes a Sigma correlation rule. Where a pySigma backend cannot convert it, ti2dac converts
  the single event and adds the aggregation from a fixed template: KQL `summarize … by bin()`, CrowdStrike `bucket()`,
  QRadar `GROUP BY … HAVING … LAST n MINUTES`, EQL `sequence … with runs=n`, Wazuh `frequency`. Lucene/OpenSearch get
  the event query plus the threshold settings to enter in a threshold rule or monitor. If the group-by field has no
  mapping for a SIEM, the query is reported as not available rather than guessed.
- **Chains** ("password spraying, then a successful logon, then a new scheduled task, same host, 10 minutes"): each
  step is its own generated, validated rule. The analysis may *propose* a sequence by behaviour ID, with a verbatim
  quote; sequences whose quote is not in the report or whose steps do not exist are dropped. ti2dac then joins the
  rules with a Sigma `temporal_ordered` correlation and per-language templates: Splunk `multisearch` + `stats`,
  KQL `union` + `summarize`, Elastic EQL `sequence … by`, ES|QL `case` + `stats`. Analysts add their own with
  `ti2dac chain <run> rule-001 rule-003 --within 10m --on host`. Chains are rebuilt whenever a step's rule changes.
  Time bins are fixed windows and the order check in Splunk/KQL is approximate; the notes on each query say so.

### Client profiles (one rule, each client's field names)

Sigma assumes standard field names; real SIEMs differ per client (Client A's Splunk `dest_ip`, Client B's Sentinel
`DestinationIP`, Client C's Wazuh `data.dstip`). A profile in `clients/<name>.yaml` maps Sigma fields to the
client's names per target, and can add pySigma pipeline files, indexes, telemetry and schema notes:

```yaml
name: acme
targets: [splunk, wazuh_rule]                 # default: the global list
fields:
  splunk: {DestinationIp: dest_ip, SourceIp: src_ip, DestinationPort: dest_port}
  wazuh_rule: {DestinationIp: data.dstip}
pipelines: {splunk: [acme-splunk.yml]}        # standard pySigma pipeline YAML, next to the profile
index_overrides: {splunk: "index=acme_windows"}
telemetry: [windows:process_creation, windows:security]
notes: {splunk: "Firewall data: index=acme_fw sourcetype=pan:traffic"}   # for AI translation
```

The client mapping runs before the standard pipelines, so the deterministic converters produce the client's own
queries, and the AI translator receives the same map for SIEMs without a converter. Queries land in
`queries/<rule>/clients/<name>/`; fields a client's map does not cover are listed on each query.
`ti2dac client init acme --targets splunk,wazuh_rule` writes a starter listing the Sigma fields your rules use;
`ti2dac client check acme --rule r.yml` shows the result. Enable clients with `clients: [acme]` in the config or
`--client acme` on `run` / `generate` / `convert`.

Add a SIEM: install its pySigma backend and add a `Target` in `src/ti2dac/targets.py` (`sigma list targets` and
`sigma list pipelines` show the identifiers). For SIEMs without a backend, list the target ID in `llm_targets`
(`ti2dac targets` shows the options).

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

`ti2dac serve` binds to `127.0.0.1`. The page-by-page guide is in *Using ti2dac, step by step* above. Its main features:
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

## CLI reference

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

## Known limitations

- **Simulation self-tests are a consistency check, not proof.** Their events come from the model. Proof is a replay of real lab or incident events, or a SIEM test.
- **Redaction is pattern-based, not a DLP/NER product.** List customer and organisation names in `redaction.terms`, review `redaction-map.json` on first runs, and keep TLP:RED material in `--no-ai` mode.
- **Local replay limits:** it does not apply correlation thresholds (it reports the matching base events) and does not support `field: null` checks. Fields must use Sigma/Sysmon names, as in EVTX and Winlogbeat/Elastic exports, where nested `winlog.event_data.*` is flattened.
- **Multi-event chains need a template per language.** Splunk, Sentinel/Defender KQL and Elastic (EQL, ES|QL) get one; CrowdStrike, QRadar, Lucene/OpenSearch, Loki and Wazuh show "not available" for chains. Steps on log sources a backend cannot convert (e.g. Security events for Sentinel ASIM) cannot be joined there.
- **Wazuh output is generated without a Wazuh manager.** Parent rules follow the 4.9 default ruleset; check every rule with `wazuh-logtest`, and add `wazuh` to `ai_fill_gaps` if you want AI drafts for non-Windows Wazuh rules.
- **Report screenshots are not read.** DFIR reports often show command lines only in images.
- **Some inputs are rejected.** JavaScript-rendered pages saved from a browser contain no article text and are rejected with instructions; scanned PDFs need OCR first.
- **Splunk raw and Loki assume Sysmon** for Windows process telemetry. Adjust `targets.py` for 4688-only environments.
- **CrowdStrike CQL has no free test tenant.** Mark it `desk-checked` after review.
- **Regexes are rewritten for whole-value engines.** Sigma `|re` matches anywhere; Lucene/OpenSearch/Wazuh indexer, ES|QL, EQL and Loki match the whole value, so ti2dac wraps the pattern in `.*….*` and, for Lucene and ES|QL (no `(?i)`), spells case-insensitivity as `[aA]` classes. Lookarounds, back-references and lazy quantifiers have no Lucene equivalent; such queries carry a note.
- **Some pySigma backends are patched in `targets.py`.** Loki (OR groups from `|windash` and other expansions lost their parentheses: 59 SigmaHQ Windows rules converted to wrong logic), EQL (regex backslash escaping) and the QRadar pipeline (crashed on `|cidr`; now `INCIDR()`). Remove a patch when the upstream package fixes it.
- **Duplicate detection is a similarity heuristic.** It surfaces candidates and leaves the decision to the reviewer.
- **Live validation so far:** rule generation has been run end to end with Gemini Flash on one public DFIR case. On a synthetic incident report, redaction, the TLP policy and evidence extraction were checked live, but AI generation was stopped by free-tier rate limits. Claude, the default provider, has not yet run live. Review the first runs on your own reports closely.

## Development

```bash
.venv/bin/python -m pytest -q      # 75 tests, no network or API key needed
```

Dependency pins that matter: pySigma must stay `0.11.x`, because the QRadar backend breaks on 2.x and newer
SQLite-backend releases silently pull in pySigma 2. `pyparsing` must stay below 3.2, which pySigma 0.11's condition
parser needs. `pySigma-backend-sqlite` must be `0.2.0`.

---

## How it works (architecture in plain terms)

Picture ti2dac as a small **detection factory**. A report comes in one end; a box of finished, labelled
detection parts comes out the other. Each station does one job. Only two stations use AI. The others are
ordinary, predictable code, so they behave the same every time and cost nothing to run.

Printable flow diagram: [ti2dac-flow.svg](./ti2dac-flow.svg)

```
                         ┌──────────────────────────── your machine ─────────────────────────────┐
                         │                                                                        │
 report / URL ──► 1 READER ──► 2 GATEKEEPER ──► 3 SUMMARISER ──────────────► 4 AI BRAIN ◄──────────┼──► AI provider
                         │      (TLP + redact)   (trim + IOCs aside)          (2 jobs only)         │   (Claude / Gemini)
                         │                                                         │              │   gets: trimmed,
                         │                                                         ▼              │   redacted text only
                         │                                             5 INSPECTORS (checks)       │
                         │                                                         │              │
                         │            6 TRANSLATORS ◄──────────────────────────────┘              │
                         │            (Sigma ► 12 SIEMs)                                          │
                         │                    │                                                   │
                         │                    ▼                                                   │
                         │            7 PACKAGER ──► output/<run>/  (rules, queries, guides, docs)  │
                         │                    ▲                                                   │
                         │            8 MEMORY (feedback, lessons, tests, approvals, audit)       │
                         │                    ▲                                                   │
                         │            9 FRONT DOORS: command line (ti2dac …) and web UI           │
                         └────────────────────────────────────────────────────────────────────────┘
```

| # | Station | What it does, in simple terms | Uses AI? | Code |
|---|---|---|---|---|
| 1 | **Reader** | Opens the report (Word, PDF, web page, email, text, CSV, or a URL) and turns it into clean text. Fingerprints it with SHA-256 so you can always prove which report a rule came from. URL downloads refuse internal addresses. | No | `ingest.py` |
| 2 | **Gatekeeper** | Reads the TLP marking and decides whether the text may go to an AI at all. Then it swaps every name, host, internal IP, email, account ID and password for a placeholder such as `[USER_1]`. The real values never leave the machine. | No | `redact.py` |
| 3 | **Summariser** | Cuts the report down to the parts that describe what the attacker *did* (commands, tools, techniques). It drops adverts, IOC tables and hex dumps. IOCs (hashes, IPs, domains) are pulled out into their own file, because they are not behaviour. This step roughly halves what the AI has to read. | No | `condense.py`, `iocs.py` |
| 4 | **AI brain** | Does the two jobs that need judgement. **Job 1:** read the trimmed report and list the attacker behaviours, with quotes as proof. **Job 2:** for each chosen behaviour, write a Sigma rule, a safe simulation, test events and analyst notes. Answers must come back in a fixed form (structured JSON), so they can be checked by code. Identical questions are answered from a local cache for free. | **Yes** | `llm.py`, `prompts.py` |
| 5 | **Inspectors** | Trust nothing the AI says without checking it. Is the quote really in the report? Does the ATT&CK ID exist? Is the Sigma valid? Does the rule match its own simulation and ignore look-alikes? Is it too tied to this one attack? Does a similar public rule already exist? Is the simulation script safe? If a check fails, the rule is sent back to the AI with only the problem list (at most twice). | No (repairs use AI) | `pipeline.py`, `attack.py`, `quality.py`, `replay.py`, `duplicates.py`, `safety.py`, `sigma_tools.py` |
| 6 | **Translators** | Turn the one Sigma rule into each SIEM's own query language (Splunk SPL, Sentinel KQL, CrowdStrike CQL…) using the standard pySigma converters. That is free and repeatable. Only where a converter cannot handle a rule does the AI write that one query, labelled "unverified". | Only for gaps | `targets.py`, `sigma_tools.py` |
| 7 | **Packager** | Writes everything into one folder per report: rules, queries, simulation guides, test events, ADS docs, validation matrix, ATT&CK layer, summary. Can rebuild that folder at any time from its saved record without using AI. | No | `render.py` |
| 8 | **Memory** | A small local database. It remembers feedback, the lessons learned from it, test results, who approved what, background jobs and a full audit log. Lessons are fed into future AI requests so mistakes are not repeated. | No | `feedback.py`, `users.py` |
| 9 | **Front doors** | Two ways to drive the factory: the `ti2dac` command line, and a web UI for analysts and reviewers with logins and roles. | No | `cli.py`, `web/` |

Supporting pieces: `config.py` (settings from `ti2dac.yaml`), `models.py` (the shape of every piece of data),
`data/` (a compact MITRE ATT&CK index and the CI workflow template).

**Why it is built this way**

- **AI only where judgement is needed.** Reading a report and designing a detection need an expert; formatting, converting, validating and documenting do not. That keeps cost low and results repeatable.
- **Never trust, always check.** Every AI answer passes through code checks before anyone sees it, and is labelled with how far it has been tested.
- **Private data stays home.** The AI only ever sees trimmed, redacted text. Logs used for testing are replayed locally and never sent.
- **Humans stay in charge.** The tool drafts; people review, test and approve, and a second person must approve what the first one created.

## The working process

### A. From report to detection package (automatic, a few minutes)

Example: `ti2dac run IR-2026-0147.docx --incident --events host-sysmon.evtx`

| Step | What happens | Who |
|---|---|---|
| 1. Read | The Word file is opened, its text and tables extracted, and its fingerprint recorded. | Code |
| 2. Classify | The tool decides "incident report" (or uses `--incident`) and finds the TLP marking. Unmarked incident reports are treated as AMBER. | Code |
| 3. Policy check | If the marking is not allowed for the chosen AI provider, the run stops here and explains the options. TLP:RED never goes to an AI. | Code |
| 4. Redact | Usernames, hosts, internal IPs, emails, SIDs, passwords and customer names become placeholders. The real-value map is saved locally only. | Code |
| 5. Trim | Boilerplate and IOC tables are removed and the best behavioural paragraphs kept. IOCs go to `iocs.json`. Raw log events pasted in the report are set aside as evidence. | Code |
| 6. Find behaviours | **AI call 1:** "What did the attacker do?" Each behaviour comes back with an ATT&CK technique, quotes as proof, and scores. | AI |
| 7. Verify and rank | Quotes are checked against the report and ATT&CK IDs against MITRE's list. Behaviours are ranked by how detectable, safely testable and low-noise they are, and the top 3 picked (one per technique). Unproven behaviours are never auto-picked. | Code |
| 8. Write detections | **AI call per behaviour:** Sigma rule, telemetry needs, safe simulation and cleanup, test events, analyst triage notes. | AI |
| 9. Inspect and repair | Validate the Sigma; run the rule against its own test events; look for environment-specific or brittle values; check the simulation script's safety. Problems go back to the AI (at most 2 small repair calls). | Code (+AI for repairs) |
| 10. Translate | Convert to 12 SIEM targets, build the field-mapping table, flag unmapped fields and backend warnings. Fill any SIEM a converter cannot handle with one AI-written query, labelled unverified. | Code (+AI for gaps) |
| 11. Prove against the incident | Replay the incident's own logs (pasted events plus `--events`) against every rule: "would this have caught it?" Matches go into the validation matrix. | Code |
| 12. Package | Write the output folder: rules, queries, guides, tests, ADS, validation matrix, ATT&CK layer, summary with full provenance. | Code |

For a public threat-intel report the flow is the same. Step 3 usually passes (TLP:CLEAR), step 4 finds little
to redact, and step 11 only runs if you supply lab logs.

### B. From draft to production (people, with the tool's help)

```
 draft ──► review ──► lab test ──► fix? ──► approve ──► export to Git ──► CI checks ──► deploy
   │         │           │          │          │             │                │
   │   read summary,  simulate,   feedback   second       approved      validate, unit-test,
   │   rules, notes   replay or   → v2,      person       rules only    convert on every
   │                  SIEM query  lesson     (four-eyes)                pull request
```

1. **Review:** an analyst reads `report-summary.md` (or the web page): warnings, duplicate hints, self-test results, the rule itself.
2. **Lab test:** follow `simulations/rule-001/README.md` in an isolated lab VM. Run the script, export the events, then `ti2dac replay … --expect match --record`. Do the same with normal activity and `--expect nomatch` to count false positives. Optionally run the query in your SIEM and `ti2dac test record …`.
3. **Fix:** if something is wrong, file feedback. Attach a corrected rule (it becomes v2), or let the AI rewrite it from your comment. The correction becomes a *lesson* used in future runs.
4. **Approve:** a second person with the approver role approves. Whoever wrote a version cannot approve it.
5. **Hand off:** `ti2dac export <run> --repo ../detections` puts approved rules into your Git detection repository, with a CI workflow that re-checks them on every change. Deploy to SIEMs with your usual pipeline.
6. **Keep learning:** production alert outcomes (true positive, benign, false positive) are recorded the same way, feeding the validation matrix and future tuning.

### C. What leaves your machine, and what does not

| Leaves (to the AI provider) | Never leaves |
|---|---|
| Trimmed, redacted report text (analysis call) | The original report and the redaction map |
| One behaviour + its quotes + short context (generation call) | IOC lists, lab logs, incident evidence (`--events`) |
| The rule's detection logic + its problem list + redacted feedback text (repair call) | Feedback database, audit log, user accounts |
| A finished Sigma rule (only for SIEM gap translation) | TLP:RED documents, and anything when `--no-ai` is used |
