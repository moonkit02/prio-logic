# prio-logic

Post-processing prioritization logic for DevSecOps scanner output.

Each script takes one scanner's flat findings and sorts them into four tiers (P1 to P4) that
follow the SSVC deployer actions (Immediate, Out-of-Cycle, Scheduled, Defer). The goal is to
cut alert fatigue and surface what actually needs fixing now, instead of a long severity-flat
list where a low-risk critical sits next to a real one.

## Scripts

| Script | Scanner | What decides the priority |
|---|---|---|
| `sca-logic.py` | SCA | CVSS x EPSS dual gate, KEV / CWE-506 override to P1, attackVector downgrade, CVSS>=9 floor at P2 |
| `sbom-logic.py` | SBOM | Same CVSS x EPSS model as SCA over the component inventory |
| `sast-logic.py` | SAST | OWASP Risk Rating matrix (Impact x Likelihood), FP verdict override, audit / low-confidence downgrade |
| `iac-logic.py` | IaC | Severity to tier + prod-vs-test path filter |
| `infra-logic.py` | Infra | Severity to tier + account filter + category-volume escalation + toxic-combination override |
| `secret-logic.py` | Secret | Severity to tier + test-path filter |

## Priority tiers

| Tier | Meaning | SSVC action |
|---|---|---|
| P1 | Emergency, fix now | Immediate |
| P2 | Urgent, fix soon | Out-of-Cycle |
| P3 | Plan, schedule | Scheduled |
| P4 | Monitor, accept / watch | Defer |

## Usage

Every script has a built-in self-check:

```bash
python3 sca-logic.py --demo
```

Run against a scanner's JSON output:

```bash
python3 sca-logic.py    report.json [network_focused|balanced|vector_agnostic]
python3 sbom-logic.py   SBOM.json
python3 sast-logic.py   results.json           # raw or merged input is auto-detected
python3 iac-logic.py    IAC.json    --test-paths test-paths.txt
python3 infra-logic.py  INFRA.json  --exclude-accounts nonprod-accounts.txt
python3 secret-logic.py SECRET.json --test-paths test-paths.txt
```

Each run prints a summary, a before/after table, and writes a `filtered-*.json` with the
prioritized findings.

The `--test-paths` and `--exclude-accounts` files are plain text, one entry per line, blank
lines and `#` comments ignored.

## Requirements

Python 3.9+, standard library only. No third-party packages.

`sca-logic.py` can pull live EPSS and KEV data when a network is available; without it, it
falls back to the report's own severity.

## Notes

- Input is each scanner's JSON report. The scripts do not run the scanners themselves.
- P1 to P4 follow the SSVC deployer tree, the same scale across all scripts.
- See `prio-logic-summary.md` for the full write-up of each script's logic and its before/after
  effect on the queue.
