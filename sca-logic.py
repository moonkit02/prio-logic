"""
SCA Vulnerability Prioritization
=================================
Process:
  1. Read report.json from the current directory (default).
  2. For each finding, extract security-risk signals.
  3. Assign a priority 1-4:
       Priority 1 = EMERGENCY  - fix now
       Priority 2 = URGENT     - fix soon
       Priority 3 = PLAN       - schedule
       Priority 4 = MONITOR    - accept / watch
  4. Apply exposure mode (how hard to downgrade non-network findings).
  5. Output to CLI and to filtered-result.json.

Signals used:
  - CWE            (malicious-code / supply-chain override)
  - CISA KEV       (confirmed exploitation override)
  - CVSS base      (severity floor)
  - EPSS v4        (exploitation probability)
  - attackVector   (exposure proxy: NETWORK vs LOCAL/NONE)

EPSS and KEV are CVE-keyed. Dependency-Check npm output is GHSA-keyed, so
step 2 also recovers the CVE alias from each advisory before those lookups.
EPSS/KEV calls are isolated in Enricher so this runs offline (lookups return
empty -> logic falls back to severity-based tiering).
"""

from __future__ import annotations
import json
import re
import sys
import os
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Tunable thresholds — keep as config, NOT frozen constants.
# EPSS recalibrates between model versions; a version bump shifts tiers.
# ---------------------------------------------------------------------------
CONFIG = {
    "epss_p1": 0.70,
    "epss_p2": 0.40,
    "epss_p3": 0.10,
    "cvss_p1": 9.0,
    "cvss_p2": 7.0,
    "cvss_p3": 4.0,
    # Malicious-code CWEs -> emergency override.
    # NOTE (open decision): CWE-506 unambiguously means embedded malicious code
    # (Snyk labels every malicious package with it). CWE-829/1357 describe risky
    # patterns that legitimate-but-flawed code also exhibits, so keeping them as
    # auto-P1 is more aggressive than the evidence strictly supports. Left as-is
    # pending your call; to narrow, set this to {"CWE-506"}.
    "malicious_cwes": {"CWE-506", "CWE-1357", "CWE-829"},
    # Remotely-reachable attack vectors (exposure proxy).
    "exposed_vectors": {"NETWORK", "ADJACENT_NETWORK"},
}

# ---------------------------------------------------------------------------
# Exposure modes (Stage 4/5). Named by THREAT MODEL, not by "more/fewer alerts",
# so users pick based on their deployment, not to shrink their queue.
#   local_downgrade = how many tiers a non-network finding drops.
# Hard overrides (KEV, malicious-CWE) are immune to this in all modes.
# Evidence: network-vector = the dominant, remotely-reachable exposure class
# (~71.6% of CVEs, 2021-2024, S2W). Local vulns still matter in post-compromise
# privilege-escalation chains -> they are downgraded, not dismissed.
# ---------------------------------------------------------------------------
EXPOSURE_MODES = {
    "balanced":        {"local_downgrade": 1},   # default; evidence-backed middle
    "network_focused": {"local_downgrade": 2},   # public-facing services
    "vector_agnostic": {"local_downgrade": 0},   # internal tools / distrust signal
}
DEFAULT_MODE = "balanced"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


# ---------------------------------------------------------------------------
# Priority: 1 = emergency ... 4 = monitor
# ---------------------------------------------------------------------------
class Priority(IntEnum):
    P1 = 1   # emergency - fix now
    P2 = 2   # urgent    - fix soon
    P3 = 3   # plan      - schedule
    P4 = 4   # monitor   - accept / watch

    @property
    def label(self) -> str:
        return {
            Priority.P1: "Priority 1 - EMERGENCY (fix now)",
            Priority.P2: "Priority 2 - URGENT (fix soon)",
            Priority.P3: "Priority 3 - PLAN (schedule)",
            Priority.P4: "Priority 4 - MONITOR (accept/watch)",
        }[self]


# ---------------------------------------------------------------------------
# Step 2 output: extracted signals per finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    package: str
    advisory_id: str            # GHSA-xxxx or CVE-xxxx
    source: str
    severity: str               # critical / high / moderate / low
    cvss: Optional[float]
    attack_vector: str          # NETWORK / LOCAL / NONE / ...
    cwes: list[str]
    cve: Optional[str] = None   # recovered alias
    epss: Optional[float] = None
    kev: bool = False
    priority: Optional[Priority] = None
    reasons: list[str] = field(default_factory=list)


# ===========================================================================
# STEP 1 — read report.json (default: current directory)
# ===========================================================================
def load_report(path: str = "report.json") -> dict:
    with open(path) as fh:
        return json.load(fh)


# ===========================================================================
# STEP 2 — extract security-risk signals from each finding
# ===========================================================================
def extract_signals(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for dep in report.get("dependencies", []):
        pkg = dep.get("fileName", "unknown")
        for v in dep.get("vulnerabilities", []):
            cvssv3 = v.get("cvssv3") or {}
            cvss = round(float(cvssv3["baseScore"]), 1) if "baseScore" in cvssv3 else None
            av = (cvssv3.get("attackVector") or "NONE").upper()
            name = v.get("name", "")
            f = Finding(
                package=pkg,
                advisory_id=name,
                source=v.get("source", ""),
                severity=(v.get("severity") or "unknown").lower(),
                cvss=cvss,
                attack_vector=av,
                cwes=list(v.get("cwes", [])),
            )
            f.cve = _recover_cve(name, v)
            findings.append(f)
    return findings


def _recover_cve(name: str, vuln: dict) -> Optional[str]:
    if name.startswith("CVE-"):
        return name
    blob = json.dumps(vuln.get("references", [])) + " " + (vuln.get("description") or "")
    m = CVE_RE.search(blob)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Enrichment — the only network-touching part.
#   EPSS: GET https://api.first.org/data/v1/epss?cve=CVE-...   (batch 100/req)
#   KEV : GET CISA known_exploited_vulnerabilities.json -> build a set
# Offline: leave maps empty; lookups no-op and logic falls back to severity.
# ---------------------------------------------------------------------------
class Enricher:
    def __init__(self, epss_map: dict[str, float] | None = None,
                 kev_set: set[str] | None = None):
        self.epss_map = epss_map or {}
        self.kev_set = kev_set or set()

    def enrich(self, f: Finding) -> None:
        if not f.cve:
            return
        if f.cve in self.epss_map:
            f.epss = self.epss_map[f.cve]
        f.kev = f.cve in self.kev_set


# ---------------------------------------------------------------------------
# Live feed loaders (network). KEV caches to disk; both fail safe to empty.
# ---------------------------------------------------------------------------
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
KEV_CACHE = os.path.join(CACHE_DIR, "kev.json")
KEV_CACHE_TTL = 86400  # 1 day


def load_kev_set(use_cache: bool = True) -> set[str]:
    """Fetch CISA KEV catalog -> set of CVE IDs. Cached to disk for a day."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    if use_cache and os.path.exists(KEV_CACHE):
        if time.time() - os.path.getmtime(KEV_CACHE) < KEV_CACHE_TTL:
            try:
                with open(KEV_CACHE) as fh:
                    return set(json.load(fh))
            except Exception:
                pass
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "sca-prioritize"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
        try:
            with open(KEV_CACHE, "w") as fh:
                json.dump(sorted(cves), fh)
        except Exception:
            pass
        return cves
    except Exception as e:
        print(f"[warn] KEV fetch failed ({e}); KEV checks disabled", file=sys.stderr)
        return set()


def load_epss_map(cves: list[str]) -> dict[str, float]:
    """Batch-fetch EPSS scores from FIRST (100 CVEs/request)."""
    out: dict[str, float] = {}
    uniq = sorted({c for c in cves if c})
    if not uniq:
        return out
    for i in range(0, len(uniq), 100):
        batch = uniq[i:i + 100]
        q = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"{EPSS_URL}?{q}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sca-prioritize"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.load(r)
            for row in data.get("data", []):
                try:
                    out[row["cve"]] = float(row["epss"])
                except (KeyError, ValueError):
                    continue
        except Exception as e:
            print(f"[warn] EPSS batch fetch failed ({e}); those scores unavailable",
                  file=sys.stderr)
    return out


def build_live_enricher(findings: list[Finding], offline: bool = False) -> Enricher:
    if offline:
        return Enricher()
    cves = [f.cve for f in findings if f.cve]
    return Enricher(epss_map=load_epss_map(cves), kev_set=load_kev_set())


# ===========================================================================
# STEP 3 — assign priority 1-4   (STEP 4 exposure mode applied at the end)
# ===========================================================================
def assign_priority(f: Finding, mode: str = DEFAULT_MODE, cfg: dict = CONFIG) -> Finding:
    # --- Priority 1 overrides (emergency). Immune to exposure mode. ---
    if f.kev:
        return _set(f, Priority.P1, "CISA KEV: confirmed exploited in the wild")
    mal = set(f.cwes) & cfg["malicious_cwes"]
    if mal:
        return _set(f, Priority.P1, f"Malicious-code CWE: {', '.join(sorted(mal))}")

    # --- Three-signal path (when EPSS available) ---
    if f.epss is not None and f.cvss is not None:
        if f.cvss >= cfg["cvss_p1"] and f.epss >= cfg["epss_p1"]:
            _set(f, Priority.P1, f"CVSS {f.cvss} + EPSS {f.epss:.2f} (critical sev, high exploit prob)")
        elif f.cvss >= cfg["cvss_p2"] and f.epss >= cfg["epss_p2"]:
            _set(f, Priority.P2, f"CVSS {f.cvss} + EPSS {f.epss:.2f} (high sev, moderate exploit prob)")
        elif f.cvss >= cfg["cvss_p3"] and f.epss >= cfg["epss_p3"]:
            _set(f, Priority.P3, f"CVSS {f.cvss} + EPSS {f.epss:.2f} (moderate)")
        else:
            _set(f, Priority.P4, f"CVSS {f.cvss} + EPSS {f.epss:.2f} (below thresholds)")
    else:
        # --- Fallback: no EPSS (no recoverable CVE, or CVE not scored) ---
        sev_tier = {
            "critical": Priority.P2,
            "high": Priority.P2,
            "moderate": Priority.P3,
            "low": Priority.P4,
        }.get(f.severity, Priority.P4)
        _set(f, sev_tier, f"No EPSS; tiered by severity='{f.severity}'")

    # --- STEP 4: exposure modifier (mode-controlled, downgrade only) ---
    downgrade = EXPOSURE_MODES.get(mode, EXPOSURE_MODES[DEFAULT_MODE])["local_downgrade"]
    if downgrade and f.attack_vector not in cfg["exposed_vectors"]:
        before = f.priority
        new_val = min(int(f.priority) + downgrade, int(Priority.P4))
        if new_val != int(f.priority):
            f.priority = Priority(new_val)
            f.reasons.append(
                f"exposure[{mode}]: attackVector={f.attack_vector} "
                f"(not network-exposed) -> {before.name}->{f.priority.name}")
    return f


def _set(f: Finding, p: Priority, reason: str) -> Finding:
    f.priority = p
    f.reasons.append(reason)
    return f


# ---------------------------------------------------------------------------
# Per-package grouping (act on the package, not each CVE)
# ---------------------------------------------------------------------------
@dataclass
class PackageGroup:
    package: str
    priority: Priority
    finding_count: int
    top_cvss: Optional[float]
    any_kev: bool
    any_malicious: bool
    reasons: list[str]


def group_by_package(findings: list[Finding]) -> list[PackageGroup]:
    from collections import defaultdict
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[f.package].append(f)
    groups = []
    for pkg, fs in buckets.items():
        top = min(fs, key=lambda x: x.priority)
        groups.append(PackageGroup(
            package=pkg,
            priority=top.priority,
            finding_count=len(fs),
            top_cvss=max((f.cvss for f in fs if f.cvss is not None), default=None),
            any_kev=any(f.kev for f in fs),
            any_malicious=any(set(f.cwes) & CONFIG["malicious_cwes"] for f in fs),
            reasons=top.reasons,
        ))
    groups.sort(key=lambda g: (g.priority, -(g.top_cvss or 0)))
    return groups


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def comparison_table(findings: list[Finding]) -> str:
    from collections import Counter
    sev = Counter(f.severity for f in findings)
    pri = Counter(f.priority.name for f in findings)
    total = len(findings) or 1
    sev_actnow = sev.get("critical", 0) + sev.get("high", 0)
    pri_actnow = pri.get("P1", 0) + pri.get("P2", 0)
    sev_order = ["critical", "high", "moderate", "low"]
    pri_order = ["P1", "P2", "P3", "P4"]
    rows = ["BEFORE (severity-only)              AFTER (priority 1-4)",
            "-" * 64]
    for i in range(4):
        s, p = sev_order[i], pri_order[i]
        left = f"  {s:<10} {sev.get(s,0):>4} ({sev.get(s,0)/total*100:>3.0f}%)"
        right = f"  {p:<4} {pri.get(p,0):>4} ({pri.get(p,0)/total*100:>3.0f}%)"
        rows.append(f"{left:<36}{right}")
    rows.append("-" * 64)
    rows.append(f"  {'TOTAL':<10} {len(findings):>4}          {'TOTAL':<4} {len(findings):>4}")
    if sev_actnow:
        rows.append("")
        rows.append(f"  act-now (crit+high): {sev_actnow}  ->  (P1+P2): {pri_actnow}"
                    f"   reduction: {(1 - pri_actnow/sev_actnow)*100:.0f}%")
    return "\n".join(rows)


def summarize(findings: list[Finding], mode: str) -> dict:
    from collections import Counter
    return {
        "exposure_mode": mode,
        "total_findings": len(findings),
        "by_priority": dict(Counter(f.priority.name for f in findings)),
        "cve_recovered": sum(1 for f in findings if f.cve),
        "no_cve": sum(1 for f in findings if not f.cve),
    }


def signals_then_verdict(findings: list[Finding]) -> str:
    lines = ["PER-FINDING: SIGNALS -> VERDICT", "=" * 72]
    for f in findings:
        cve = f.cve or "no-CVE"
        cvss = f"{f.cvss}" if f.cvss is not None else "n/a"
        epss = f"{f.epss:.2%}" if f.epss is not None else "n/a"
        kev = "YES" if f.kev else "no"
        lines.append(f"{f.package}  ({f.advisory_id})")
        lines.append(f"    CVE  : {cve}")
        lines.append(f"    CVSS : {cvss}")
        lines.append(f"    EPSS : {epss}")
        lines.append(f"    KEV  : {kev}")
        lines.append(f"    AV   : {f.attack_vector}")
        lines.append(f"    --> VERDICT: P{f.priority}  ({f.priority.label})")
        for r in f.reasons:
            lines.append(f"        reason: {r}")
        lines.append("")
    return "\n".join(lines)


# ===========================================================================
# STEP 5 — JSON output (filtered-result.json)
# ===========================================================================
def finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    d["priority"] = int(f.priority) if f.priority is not None else None
    d["priority_label"] = f.priority.label if f.priority is not None else None
    return d


def write_filtered_json(findings: list[Finding], mode: str,
                        path: str = "filtered-result.json") -> str:
    out = {
        "exposure_mode": mode,
        "summary": summarize(findings, mode),
        "findings": [finding_to_dict(f) for f in findings],
        "packages": [
            {
                "package": g.package,
                "priority": int(g.priority),
                "priority_label": g.priority.label,
                "finding_count": g.finding_count,
                "top_cvss": g.top_cvss,
                "any_kev": g.any_kev,
                "any_malicious": g.any_malicious,
                "reasons": g.reasons,
            }
            for g in group_by_package(findings)
        ],
    }
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    return path


# ===========================================================================
# Driver
# ===========================================================================
def run(path: str = "report.json", enricher: Enricher | None = None,
        offline: bool = False, mode: str = DEFAULT_MODE):
    report = load_report(path)                 # step 1
    findings = extract_signals(report)         # step 2
    if enricher is None:
        enricher = build_live_enricher(findings, offline=offline)
    for f in findings:
        enricher.enrich(f)
        assign_priority(f, mode=mode)          # step 3 + step 4
    findings.sort(key=lambda x: (x.priority, -(x.cvss or 0)))
    return findings


def _parse_mode(argv: list[str]) -> str:
    for i, a in enumerate(argv):
        if a == "--mode" and i + 1 < len(argv):
            m = argv[i + 1]
            if m not in EXPOSURE_MODES:
                print(f"[warn] unknown mode '{m}'; using '{DEFAULT_MODE}'. "
                      f"Choices: {', '.join(EXPOSURE_MODES)}", file=sys.stderr)
                return DEFAULT_MODE
            return m
        if a.startswith("--mode="):
            m = a.split("=", 1)[1]
            if m not in EXPOSURE_MODES:
                print(f"[warn] unknown mode '{m}'; using '{DEFAULT_MODE}'. "
                      f"Choices: {', '.join(EXPOSURE_MODES)}", file=sys.stderr)
                return DEFAULT_MODE
            return m
    return DEFAULT_MODE


if __name__ == "__main__":
    argv = sys.argv[1:]
    offline = "--offline" in argv
    mode = _parse_mode(argv)
    positional = [a for a in argv
                  if not a.startswith("-") and a not in EXPOSURE_MODES]
    path = positional[0] if positional else "report.json"

    findings = run(path, offline=offline, mode=mode)

    print(json.dumps(summarize(findings, mode), indent=2))
    print()
    print(comparison_table(findings))
    print()
    print(signals_then_verdict(findings))
    print()

    groups = group_by_package(findings)
    print(f"PER-PACKAGE VIEW  ({len(findings)} findings -> {len(groups)} packages)  "
          f"[exposure mode: {mode}]")
    print("-" * 64)
    for g in groups:
        flags = [x for x, on in (("KEV", g.any_kev), ("MALICIOUS", g.any_malicious)) if on]
        flag_str = (" [" + ",".join(flags) + "]") if flags else ""
        print(f"P{g.priority} {g.package}  ({g.finding_count} findings, "
              f"top_cvss={g.top_cvss}){flag_str}")
        for r in g.reasons:
            print(f"      - {r}")

    out_path = write_filtered_json(findings, mode)
    print()
    print(f"[written] {out_path}")
