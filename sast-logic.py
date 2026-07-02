"""
SAST Vulnerability Prioritization
=================================
Post-processes SAST output (OpenGrep raw, or the auto-triaged "merged" file) into
four ranked tiers (P1-P4) so the queue answers "which code findings need fixing
now." Same 4-stage shape as sca-logic.py, so the two read and maintain alike.

The model — ONE pipeline, four stages (every prio-logic script shares this shape):

    extract -> [1] OVERRIDES -> [2] BASE TIER -> [3] DOWNGRADES -> output

  Stage 1  OVERRIDES   a *confirmed* fact hard-sets the tier and returns early.
                       For SAST the confirmed fact is the auto-triage verdict:
                         - verdict = FP -> P4 (confirmed not a live vuln)
                       We settle false positives FIRST; the rest (mostly TP) flow
                       on to normal grading.
  Stage 2  BASE TIER   grade the survivors by the fields each schema gives us:
                         - raw OpenGrep: Impact x Likelihood matrix (OWASP Risk
                           Rating shape; Impact = stronger of severity/impact)
                         - merged      : severity word (the only "how bad" axis)
  Stage 3  DOWNGRADES  proxies that only ever DEMOTE, never escalate.
                         - subcategory=audit (hardening note, not a live vuln)
                         - confidence=LOW    (only when there is no TP/FP verdict)
  Stage 4  OUTPUT      tiers + reasons, per-file grouping, CLI + filtered JSON.

P1-P4 carry the SSVC deployer actions (Immediate / Out-of-Cycle / Scheduled /
Defer), the same tier scale every prio-logic script uses.

No network. Code findings have no CVE, so there is no EPSS/KEV/CVE layer here
(that is sca-logic.py's job, not this one).
"""

from __future__ import annotations
import json
import sys
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Config — tunable thresholds, grouped by the stage that uses them.
# Heuristics, not frozen constants.
# ---------------------------------------------------------------------------
CONFIG = {
    # Stage 1 — overrides
    "fp_verdicts": {"FP"},          # auto-triage verdict that floors a finding

    # Stage 2 — base tier
    # raw OpenGrep grades on the OWASP Risk Rating shape: Impact x Likelihood, NOT
    # an additive sum. Impact band = the stronger of severity and the impact axis.
    "level_score": {"HIGH": 3, "MEDIUM": 2, "LOW": 1,
                    "ERROR": 3, "WARNING": 2, "INFO": 1},
    "default_level": 2,             # missing axis -> treat as MEDIUM, don't over-suppress
    # (impact_band, likelihood_band) -> tier. The authentic OWASP Risk Rating
    # severity matrix: Critical->P1, High->P2, Medium->P3, Low/Note->P4.
    "risk_matrix": {
        ("HIGH", "HIGH"): 1, ("HIGH", "MEDIUM"): 2, ("HIGH", "LOW"): 3,
        ("MEDIUM", "HIGH"): 2, ("MEDIUM", "MEDIUM"): 3, ("MEDIUM", "LOW"): 4,
        ("LOW", "HIGH"): 3, ("LOW", "MEDIUM"): 4, ("LOW", "LOW"): 4,
    },
    # merged: no impact/likelihood axes, only a severity word -> tier on that.
    "merged_sev_tier": {"critical": 1, "high": 2, "moderate": 3,
                        "medium": 3, "low": 4},

    # Stage 3 — downgrades (tiers dropped; stack, floored at P4)
    "audit_downgrade": 1,           # subcategory=audit -> hardening, not a live vuln
    "lowconf_downgrade": 1,         # confidence=LOW (only when no TP/FP verdict)
    # ponytail: no path/reachability downgrade for now. Test paths are meant to be
    # excluded at scan time (a future per-run exclude), not demoted here.
}


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
# Extracted signals per finding (union of both schemas; absent fields = None)
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    rule_id: str
    path: str
    lines: list[str]
    severity: str                    # raw: ERROR/WARNING/INFO | merged: critical/high/...
    impact: Optional[str] = None     # raw only: HIGH/MEDIUM/LOW
    likelihood: Optional[str] = None # raw only: HIGH/MEDIUM/LOW
    confidence: Optional[str] = None # HIGH/MEDIUM/LOW
    subcategory: Optional[str] = None# raw only: vuln/audit
    verdict: Optional[str] = None    # merged only: TP/FP (auto-triage)
    cwes: list[str] = field(default_factory=list)
    vuln_type: Optional[str] = None  # merged only
    priority: Optional[Priority] = None
    reasons: list[str] = field(default_factory=list)


# ===========================================================================
# STEP 1 — load the report (default: results.json in current directory)
# ===========================================================================
def load_report(path: str = "results.json") -> dict:
    with open(path) as fh:
        return json.load(fh)


# ===========================================================================
# STEP 2 — extract signals. Auto-detect schema by its top-level array:
#   merged (post-triage) -> "findings"   | raw OpenGrep -> "results"
# ===========================================================================
def extract_signals(report: dict) -> list[Finding]:
    if "findings" in report:
        return _extract_merged(report["findings"])
    return _extract_raw(report.get("results", []))


def _extract_raw(results: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        md = r.get("extra", {}).get("metadata", {})
        sl = r.get("start", {}).get("line")
        el = r.get("end", {}).get("line")
        lines = [str(sl)] if (el is None or el == sl) else [str(sl), str(el)]
        findings.append(Finding(
            rule_id=r.get("check_id", "unknown"),
            path=r.get("path", ""),
            lines=lines,
            severity=(r.get("extra", {}).get("severity") or "WARNING").upper(),
            impact=(md.get("impact") or None),
            likelihood=(md.get("likelihood") or None),
            confidence=(md.get("confidence") or None),
            subcategory=_join(md.get("subcategory")),
            cwes=list(md.get("cwe", [])),
        ))
    return findings


def _extract_merged(items: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for it in items:
        ev = it.get("evaluation", {})
        findings.append(Finding(
            rule_id=it.get("rule_id", "unknown"),
            path=it.get("source_file") or it.get("reported_file", ""),
            lines=[str(x) for x in it.get("lines", [])],
            severity=(it.get("severity") or "medium").lower(),
            confidence=(ev.get("confidence") or None),
            verdict=(ev.get("verdict") or None),
            cwes=list(ev.get("cwe_ids", [])),
            vuln_type=ev.get("vulnerability_type"),
        ))
    return findings


def _join(v) -> Optional[str]:
    """subcategory comes as a list (['audit']) or a string; normalize to a string."""
    if not v:
        return None
    return ",".join(v) if isinstance(v, list) else str(v)


# ===========================================================================
# STEP 3 — assign priority: the 4-stage model
# ===========================================================================
def assign_priority(f: Finding, cfg: dict = CONFIG) -> Finding:
    # Stage 1 — OVERRIDES: a confirmed FP is settled first, floored to P4.
    override = _stage1_override(f, cfg)
    if override is not None:
        return _set(f, *override)

    # Stage 2 — BASE TIER: grade the survivor by the fields its schema gives us.
    p = _stage2_base_tier(f, cfg)

    # Stage 3 — DOWNGRADES: proxies that only ever demote.
    p = _stage3_downgrades(f, p, cfg)

    f.priority = p
    return f


def _stage1_override(f: Finding, cfg: dict) -> Optional[tuple[Priority, str]]:
    """Confirmed false positive -> P4 and stop. None if no verdict / not FP."""
    if f.verdict and f.verdict.upper() in cfg["fp_verdicts"]:
        return Priority.P4, "[override] auto-triage verdict=FP -> floor P4 (not a live vuln)"
    return None


def _level(v: Optional[str], cfg: dict) -> int:
    return cfg["level_score"].get((v or "").upper(), cfg["default_level"])


def _band(level: int) -> str:
    return "HIGH" if level >= 3 else ("MEDIUM" if level == 2 else "LOW")


def _stage2_base_tier(f: Finding, cfg: dict) -> Priority:
    """raw: Impact x Likelihood matrix (OWASP Risk Rating); merged: severity word."""
    if f.impact is not None and f.likelihood is not None:
        imp = _band(max(_level(f.severity, cfg), _level(f.impact, cfg)))
        lik = _band(_level(f.likelihood, cfg))
        p = Priority(cfg["risk_matrix"][(imp, lik)])
        f.reasons.append(
            f"[base] impact={imp} (severity {f.severity}/impact {f.impact}) "
            f"x likelihood={lik} -> {p.name}")
        return p
    # merged schema: tier on the severity word alone
    p = Priority(cfg["merged_sev_tier"].get(f.severity.lower(), int(Priority.P4)))
    f.reasons.append(f"[base] severity='{f.severity}' -> {p.name}")
    return p


def _stage3_downgrades(f: Finding, p: Priority, cfg: dict) -> Priority:
    """Demote-only proxies. They stack and are floored at P4."""
    drop = 0
    if f.subcategory and "audit" in f.subcategory.lower():
        drop += cfg["audit_downgrade"]
        f.reasons.append(f"[downgrade] subcategory={f.subcategory} (hardening, not a live vuln)")
    if f.verdict is None and (f.confidence or "").upper() == "LOW":
        drop += cfg["lowconf_downgrade"]
        f.reasons.append("[downgrade] confidence=LOW (no TP/FP verdict to trust)")
    if drop:
        new = Priority(min(int(p) + drop, int(Priority.P4)))
        if new != p:
            f.reasons.append(f"[downgrade] {p.name}->{new.name} (total -{drop})")
            p = new
    return p


def _set(f: Finding, p: Priority, reason: str) -> Finding:
    f.priority = p
    f.reasons.append(reason)
    return f


# ---------------------------------------------------------------------------
# Per-file grouping (act on the file, not each individual finding)
# ---------------------------------------------------------------------------
@dataclass
class FileGroup:
    path: str
    priority: Priority
    finding_count: int
    any_fp: bool
    rule_ids: list[str]
    reasons: list[str]


def group_by_file(findings: list[Finding]) -> list[FileGroup]:
    from collections import defaultdict
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[f.path].append(f)
    groups = []
    for path, fs in buckets.items():
        top = min(fs, key=lambda x: x.priority)
        groups.append(FileGroup(
            path=path,
            priority=top.priority,
            finding_count=len(fs),
            any_fp=any((x.verdict or "").upper() in CONFIG["fp_verdicts"] for x in fs),
            rule_ids=sorted({x.rule_id for x in fs}),
            reasons=top.reasons,
        ))
    groups.sort(key=lambda g: (g.priority, -g.finding_count))
    return groups


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _sev_bucket(s: str) -> str:
    """Normalize both schemas' severity vocab to critical/high/medium/low."""
    s = (s or "").lower()
    m = {"error": "high", "warning": "medium", "info": "low", "moderate": "medium"}
    s = m.get(s, s)
    return s if s in ("critical", "high", "medium", "low") else "low"


def _render_comparison(findings, sev_bucket) -> str:
    """Shared report: severity counts -> priority counts -> act-now filtered %.
    act-now = (critical+high) before vs (P1+P2) after."""
    from collections import Counter
    sev = Counter(sev_bucket(f.severity) for f in findings)
    pri = Counter(f.priority.name for f in findings)
    total = len(findings) or 1
    sev_order = ["critical", "high", "medium", "low"]
    pri_order = ["P1", "P2", "P3", "P4"]
    rows = ["BEFORE (severity)                   AFTER (priority 1-4)",
            "-" * 64]
    for s, p in zip(sev_order, pri_order):
        left = f"  {s:<10} {sev.get(s,0):>4} ({sev.get(s,0)/total*100:>3.0f}%)"
        right = f"  {p:<4} {pri.get(p,0):>4} ({pri.get(p,0)/total*100:>3.0f}%)"
        rows.append(f"{left:<36}{right}")
    rows.append("-" * 64)
    rows.append(f"  {'TOTAL':<10} {len(findings):>4}          {'TOTAL':<4} {len(findings):>4}")
    before = sev.get("critical", 0) + sev.get("high", 0)
    after = pri.get("P1", 0) + pri.get("P2", 0)
    line = f"  act-now  critical+high: {before}  ->  P1+P2: {after}"
    if before:
        pct = (1 - after / before) * 100
        line += (f"   filtered {pct:.0f}%" if after <= before
                 else f"   expanded {-pct:.0f}% (more promoted than demoted)")
    rows += ["", line]
    return "\n".join(rows)


def comparison_table(findings: list[Finding]) -> str:
    return _render_comparison(findings, _sev_bucket)


def summarize(findings: list[Finding]) -> dict:
    from collections import Counter
    return {
        "total_findings": len(findings),
        "by_priority": dict(Counter(f.priority.name for f in findings)),
        "tp": sum(1 for f in findings if (f.verdict or "").upper() == "TP"),
        "fp": sum(1 for f in findings if (f.verdict or "").upper() in CONFIG["fp_verdicts"]),
        "no_verdict": sum(1 for f in findings if not f.verdict),
    }


def signals_then_verdict(findings: list[Finding]) -> str:
    lines = ["PER-FINDING: SIGNALS -> VERDICT", "=" * 72]
    for f in findings:
        lines.append(f"{f.path}:{','.join(f.lines)}  ({f.rule_id})")
        lines.append(f"    severity   : {f.severity}")
        lines.append(f"    impact     : {f.impact or 'n/a'}")
        lines.append(f"    likelihood : {f.likelihood or 'n/a'}")
        lines.append(f"    confidence : {f.confidence or 'n/a'}")
        lines.append(f"    verdict    : {f.verdict or 'n/a'}")
        lines.append(f"    --> VERDICT: {f.priority.name}  ({f.priority.label})")
        for r in f.reasons:
            lines.append(f"        reason: {r}")
        lines.append("")
    return "\n".join(lines)


# ===========================================================================
# STEP 4 — JSON output (filtered-sast.json)
# ===========================================================================
def finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    d["priority"] = int(f.priority) if f.priority is not None else None
    d["priority_label"] = f.priority.label if f.priority is not None else None
    return d


def write_filtered_json(findings: list[Finding],
                        path: str = "filtered-sast.json") -> str:
    out = {
        "summary": summarize(findings),
        "findings": [finding_to_dict(f) for f in findings],
        "files": [
            {
                "path": g.path,
                "priority": int(g.priority),
                "priority_label": g.priority.label,
                "finding_count": g.finding_count,
                "any_fp": g.any_fp,
                "rule_ids": g.rule_ids,
                "reasons": g.reasons,
            }
            for g in group_by_file(findings)
        ],
    }
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    return path


# ===========================================================================
# Driver
# ===========================================================================
def run(path: str = "results.json") -> list[Finding]:
    report = load_report(path)                 # step 1
    findings = extract_signals(report)         # step 2
    for f in findings:
        assign_priority(f)                     # step 3 (4-stage model)
    findings.sort(key=lambda x: (x.priority, x.path, x.rule_id))
    return findings


# ---------------------------------------------------------------------------
# Self-check — one assertion per stage of the model.
# ---------------------------------------------------------------------------
def demo() -> None:
    def mk(**kw):
        base = dict(rule_id="r", path="routes/x.ts", lines=["1"], severity="ERROR",
                    impact="MEDIUM", likelihood="MEDIUM", confidence="HIGH")
        base.update(kw)
        return Finding(**base)

    # Stage 1: FP verdict floors to P4, even for a high-severity finding
    f = mk(verdict="FP", severity="ERROR", impact="HIGH", likelihood="HIGH")
    assert assign_priority(f).priority == Priority.P4, f.priority

    # Stage 2 (raw matrix): HIGH x HIGH -> P1 ; LOW x LOW -> P4
    assert assign_priority(mk(severity="ERROR", impact="HIGH", likelihood="HIGH")).priority == Priority.P1
    assert assign_priority(mk(severity="INFO", impact="LOW", likelihood="LOW")).priority == Priority.P4
    # matrix, not sum: MEDIUM impact is P4 at LOW likelihood, rises to P2 at HIGH
    assert assign_priority(mk(severity="WARNING", impact="MEDIUM", likelihood="LOW")).priority == Priority.P4
    assert assign_priority(mk(severity="WARNING", impact="MEDIUM", likelihood="HIGH")).priority == Priority.P2
    # Stage 2 (merged): severity word only -> critical=P1, low=P4
    assert assign_priority(mk(impact=None, likelihood=None, severity="critical", verdict="TP")).priority == Priority.P1
    assert assign_priority(mk(impact=None, likelihood=None, severity="low", verdict="TP")).priority == Priority.P4

    # Stage 3: audit subcategory demotes P1->P2
    assert assign_priority(mk(severity="ERROR", impact="HIGH", likelihood="HIGH",
                              subcategory="audit")).priority == Priority.P2
    # Stage 3: confidence=LOW demotes only when there is no verdict
    assert assign_priority(mk(severity="ERROR", impact="HIGH", likelihood="HIGH",
                              confidence="LOW")).priority == Priority.P2
    # Stage 3: downgrades stack (audit + low confidence) P1->P3
    assert assign_priority(mk(severity="ERROR", impact="HIGH", likelihood="HIGH",
                              subcategory="audit", confidence="LOW")).priority == Priority.P3
    # Stage 3: floored at P4 (already low + downgrades can't go past P4)
    assert assign_priority(mk(severity="INFO", impact="LOW", likelihood="LOW",
                              subcategory="audit", confidence="LOW")).priority == Priority.P4
    print("demo: all assertions passed")


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--demo" in argv:
        demo()
        sys.exit(0)

    positional = [a for a in argv if not a.startswith("-")]
    path = positional[0] if positional else "results.json"

    findings = run(path)

    print(json.dumps(summarize(findings), indent=2))
    print()
    print(comparison_table(findings))
    print()
    print(signals_then_verdict(findings))
    print()

    groups = group_by_file(findings)
    print(f"PER-FILE VIEW  ({len(findings)} findings -> {len(groups)} files)")
    print("-" * 64)
    for g in groups:
        flag = " [has FP]" if g.any_fp else ""
        print(f"{g.priority.name} {g.path}  ({g.finding_count} findings){flag}")
        for r in g.reasons:
            print(f"      - {r}")

    out_path = write_filtered_json(findings)
    print()
    print(f"[written] {out_path}")
