# SCA Vulnerability Prioritization

A CLI tool that re-ranks OWASP Dependency-Check SCA findings into four actionable priority tiers to reduce alert fatigue.

## Overview

This tool reads an OWASP Dependency-Check JSON report and assigns each vulnerability a priority tier (P1–P4) using four signals: CVSS severity, EPSS exploitation probability, CISA KEV confirmed-exploitation status, and the CWE classification. It exists because severity-only triage floods small teams with "critical" findings that are never actually exploited; combining CVSS with EPSS and KEV concentrates the top tiers on vulnerabilities that are both serious and likely to be exploited. It is designed for SCA results where findings are labeled by GHSA advisory ID, recovering the CVE alias needed for EPSS and KEV lookups.

## Prerequisites

- Python 3.10+
- An OWASP Dependency-Check JSON report (the input file)
- Network access to `api.first.org` (EPSS) and `www.cisa.gov` (KEV) for live scoring; runs offline without them

No third-party Python packages are required — the script uses only the standard library.

## Installation

No installation step. Copy `sca_prioritize.py` into your working directory.

### From Source

```bash
git clone https://github.com/moonkit02/prio-logic
cd prio-logic
python3 sca_prioritize.py
```

## Configuration

Configuration is done through CLI arguments and tunable constants in the script. There are no required environment variables. The scoring thresholds and exposure behavior are defined in the `CONFIG` and `EXPOSURE_MODES` dictionaries near the top of the script.

| Item | Location | Default | Description |
|---|---|---|---|
| CVSS / EPSS thresholds | `CONFIG` dict | see script | Tier cutoffs for CVSS and EPSS |
| Malicious CWEs | `CONFIG["malicious_cwes"]` | `CWE-506, CWE-829, CWE-1357` | CWEs that force a P1 override |
| Exposure mode | `--mode` flag | `balanced` | How hard non-network findings are downgraded |
| KEV cache | `.cache/kev.json` | 24h TTL | Local cache of the CISA KEV catalog |

## Usage

Prioritize a report with live EPSS and KEV scoring (default `balanced` mode):

```bash
python3 sca_prioritize.py dependency-check-report.json
```

Run without network access (CVSS and CWE only, EPSS/KEV skipped):

```bash
python3 sca_prioritize.py dependency-check-report.json --offline
```

Use a stricter exposure mode for a public-facing service:

```bash
python3 sca_prioritize.py dependency-check-report.json --mode network_focused
```

Default input is `report.json` in the current directory if no path is given:

```bash
python3 sca_prioritize.py
```

Every run prints a summary, a before/after comparison table, a per-finding signal breakdown, and a per-package view, then writes `filtered-result.json`.

## Arguments Reference

| Argument | Required | Default | Description |
|---|---|---|---|
| `report_path` (positional) | No | `report.json` | Path to the Dependency-Check JSON report |
| `--mode` | No | `balanced` | Exposure mode: `balanced`, `network_focused`, `vector_agnostic` |
| `--offline` | No | `false` | Skip live EPSS/KEV lookups; tier by CVSS/CWE/severity only |

### Priority tiers

| Priority | CVSS | EPSS | KEV |
|---|---|---|---|
| P1 | ≥ 9.0 | ≥ 0.7 | Present (KEV forces P1) |
| P2 | ≥ 7.0 | ≥ 0.4 | Absent |
| P3 | ≥ 4.0 | ≥ 0.1 | Absent |
| P4 | < 4.0 | < 0.1 | Absent |

KEV presence and a malicious-code CWE (e.g. `CWE-506`) each force P1 unconditionally, regardless of CVSS or EPSS.

## Limitations

- Input is OWASP Dependency-Check JSON only. Other scanner formats (Grype, Trivy, Snyk) are not parsed.
- EPSS and KEV are CVE-keyed. Findings whose advisory has no recoverable CVE cannot be scored by EPSS or KEV and fall back to severity-based tiering.
- EPSS does not score very new CVEs immediately; a recently published CVE may return no EPSS value until the model catches up.
- The `attackVector` exposure modifier reflects the vulnerability's theoretical reachability, not whether it is reachable in your specific deployment. It is a coarse proxy, not true reachability analysis.
- **Live scoring requires outbound network access to `api.first.org` and `www.cisa.gov`. In restricted networks, run with `--offline` — but be aware that EPSS and KEV signals will be unavailable and tiers will rely on CVSS and CWE alone.**
- The malicious-CWE set includes `CWE-829` and `CWE-1357` alongside `CWE-506`. Only `CWE-506` unambiguously indicates embedded malicious code; the other two also appear on legitimate-but-flawed code, so the P1 override may over-trigger.

## Documentation

For complete documentation, see: `<documentation-url-here>`
