# Quality, safety and testing

[Back to README](../README.md)

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

Statuses use this fixed vocabulary: `not-tested`, `syntax-validated`, `desk-checked`, `tested-positive`, `tested-negative`, `tested-positive-and-negative`, `failed`.
