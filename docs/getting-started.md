# Getting started

[Back to README](../README.md)

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
