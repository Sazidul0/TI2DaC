# Known limitations

[Back to README](../README.md)

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
