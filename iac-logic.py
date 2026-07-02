"""
IaC Misconfiguration Prioritization  (Trivy)
============================================
Post-processes a Trivy misconfiguration scan (Results[].Misconfigurations[] —
Dockerfile / Terraform / CloudFormation / Kubernetes / Helm / Azure ARM / Ansible)
into four ranked tiers (P1-P4), the same 4-stage shape as the other prio-logic
scripts, so the queue answers "which misconfigs need fixing now."

The model — ONE pipeline (IaC is the thinnest scanner; some stages are empty):

    extract(FAIL only) -> [filter] prod vs test -> [base tier] severity -> output

  extract       keep only Status=FAIL (PASS is not a finding).
  [filter]      classify each finding as prod or test by its Target path, using a
                user-supplied list of test folder paths (a .txt, one path per line).
                Test findings are FILTERED OUT of the priority queue and reported
                separately. No heuristic guessing of test dirs — the user declares
                their own layout, which beats any built-in marker list.
  [base tier]   prod findings: Trivy Severity -> tier (CRITICAL->P1 ... LOW->P4).
                Config checks have no CVE / exploitation feed, so severity IS the
                signal (Trivy's rating is CIS-derived).
  [output]      prioritized prod findings + the filtered test list, grouped by file.

No Stage-1 override and no Stage-3 downgrade: config checks have no confirmed-
exploitation fact, and the path is now a *filter*, not a demote. (A cloud-exposure
override — public S3 / open SG -> escalate — would be the future Stage-1 lever, but
Trivy has no exposure field to key it on, only inference from the check ID.)

P1-P4 are the SSVC deployer actions, the same tier scale every prio-logic uses.
"""

from __future__ import annotations
import json
import sys
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Config — tunable, grouped by stage.
# ---------------------------------------------------------------------------
CONFIG = {
    # Base tier straight from Trivy severity. No exploitation feed exists for
    # config checks, so severity IS the signal.
    "severity_tier": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4},
    "default_tier": 4,           # unknown severity -> monitor, don't over-alert
}


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
# Extracted signals per finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    check_id: str               # AVD-AWS-0107, DS-0026
    target: str                 # Dockerfile, test/smoke/Dockerfile, terraform/main.tf
    title: str
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW
    status: str                 # FAIL (PASS is filtered at extract)
    provider: str = ""          # Dockerfile / AWS / Kubernetes ...
    service: str = ""
    resolution: str = ""
    primary_url: str = ""
    config_type: str = ""       # dockerfile / terraform / kubernetes ...
    is_test: bool = False       # set by the prod-vs-test filter
    priority: Optional[Priority] = None
    reasons: list[str] = field(default_factory=list)


# ===========================================================================
# STEP 1 — load the report (default: IAC.json in current directory)
# ===========================================================================
def load_report(path: str = "IAC.json") -> dict:
    with open(path) as fh:
        return json.load(fh)


# ===========================================================================
# STEP 2 — extract signals; keep only Status=FAIL.
# ===========================================================================
def extract_signals(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for r in report.get("Results", []):
        target = r.get("Target", "")
        ctype = r.get("Type", "")
        for m in r.get("Misconfigurations", []):
            if m.get("Status") != "FAIL":
                continue
            cm = m.get("CauseMetadata", {})
            findings.append(Finding(
                check_id=m.get("AVDID") or m.get("ID") or "unknown",
                target=target,
                title=m.get("Title", ""),
                severity=(m.get("Severity") or "UNKNOWN").upper(),
                status=m.get("Status", ""),
                provider=cm.get("Provider", ""),
                service=cm.get("Service", ""),
                resolution=m.get("Resolution", ""),
                primary_url=m.get("PrimaryURL", ""),
                config_type=ctype,
            ))
    return findings


# ===========================================================================
# Test-path filter — the user declares their own test folders in a .txt file.
# ===========================================================================
def load_test_paths(path: Optional[str]) -> list[str]:
    """One path per line; blank lines and # comments ignored. Missing file -> []."""
    if not path:
        return []
    out: list[str] = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def is_test_path(target: str, test_paths: list[str]) -> bool:
    """True if the finding's Target sits under any user-declared test folder.
    Matched as a path segment so 'test' hits 'test/smoke/Dockerfile' but not
    'latest/main.tf'."""
    norm = "/" + target.replace("\\", "/").strip("/").lower() + "/"
    for tp in test_paths:
        seg = "/" + tp.replace("\\", "/").strip("/").lower() + "/"
        if seg in norm:
            return True
    return False


# ===========================================================================
# STEP 3 — base tier: Trivy severity -> tier (prod findings only).
# ===========================================================================
def assign_priority(f: Finding, cfg: dict = CONFIG) -> Finding:
    p = Priority(cfg["severity_tier"].get(f.severity, cfg["default_tier"]))
    f.priority = p
    f.reasons.append(f"[base] severity={f.severity} -> {p.name}")
    return f


def partition(findings: list[Finding], test_paths: list[str]) -> tuple[list[Finding], list[Finding]]:
    """Split into (prod, test). Prod findings get a tier; test findings are
    filtered out of the priority queue but kept for the report."""
    prod, tests = [], []
    for f in findings:
        if test_paths and is_test_path(f.target, test_paths):
            f.is_test = True
            f.reasons.append(f"[filtered] test path '{f.target}' -> excluded from priority queue")
            tests.append(f)
        else:
            assign_priority(f)
            prod.append(f)
    prod.sort(key=lambda x: (x.priority, x.target))
    tests.sort(key=lambda x: x.target)
    return prod, tests


# ---------------------------------------------------------------------------
# Per-file grouping (act on the file)
# ---------------------------------------------------------------------------
@dataclass
class FileGroup:
    target: str
    priority: Priority
    finding_count: int
    top_severity: str
    check_ids: list[str]
    reasons: list[str]


def group_by_file(findings: list[Finding]) -> list[FileGroup]:
    from collections import defaultdict
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[f.target].append(f)
    groups = []
    for tgt, fs in buckets.items():
        top = min(fs, key=lambda x: x.priority)
        groups.append(FileGroup(
            target=tgt,
            priority=top.priority,
            finding_count=len(fs),
            top_severity=top.severity,
            check_ids=sorted({x.check_id for x in fs}),
            reasons=top.reasons,
        ))
    groups.sort(key=lambda g: (g.priority, g.target))
    return groups


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _sev_bucket(s: str) -> str:
    s = (s or "").lower()
    return s if s in ("critical", "high", "medium", "low") else "low"


def _render_comparison(findings, sev_bucket) -> str:
    """severity counts -> priority counts -> act-now line (prod findings only)."""
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
    return "\n".join(rows)


def comparison_table(findings: list[Finding]) -> str:
    return _render_comparison(findings, _sev_bucket)


def summarize(prod: list[Finding], tests: list[Finding]) -> dict:
    from collections import Counter
    return {
        "total_fail": len(prod) + len(tests),
        "prioritized_prod": len(prod),
        "filtered_test": len(tests),
        "by_priority": dict(Counter(f.priority.name for f in prod)),
    }


# ===========================================================================
# STEP 4 — JSON output (filtered-iac.json)
# ===========================================================================
def finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    d["priority"] = int(f.priority) if f.priority is not None else None
    d["priority_label"] = f.priority.label if f.priority is not None else None
    return d


def write_filtered_json(prod: list[Finding], tests: list[Finding],
                        path: str = "filtered-iac.json") -> str:
    out = {
        "summary": summarize(prod, tests),
        "findings": [finding_to_dict(f) for f in prod],
        "filtered_test_findings": [finding_to_dict(f) for f in tests],
        "files": [
            {
                "target": g.target,
                "priority": int(g.priority),
                "priority_label": g.priority.label,
                "finding_count": g.finding_count,
                "top_severity": g.top_severity,
                "check_ids": g.check_ids,
            }
            for g in group_by_file(prod)
        ],
    }
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    return path


# ===========================================================================
# Driver
# ===========================================================================
def run(path: str = "IAC.json", test_paths_file: Optional[str] = None):
    report = load_report(path)                       # step 1
    findings = extract_signals(report)               # step 2 (FAIL only)
    test_paths = load_test_paths(test_paths_file)
    return partition(findings, test_paths)            # step 3 (filter + base tier)


def _parse_test_paths_flag(argv: list[str]) -> Optional[str]:
    for i, a in enumerate(argv):
        if a == "--test-paths" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--test-paths="):
            return a.split("=", 1)[1]
    return None


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------
def demo() -> None:
    def mk(**kw):
        base = dict(check_id="AVD-x", target="terraform/main.tf", title="t",
                    severity="HIGH", status="FAIL")
        base.update(kw)
        return Finding(**base)

    # base tier: severity -> tier
    assert assign_priority(mk(severity="CRITICAL")).priority == Priority.P1
    assert assign_priority(mk(severity="HIGH")).priority == Priority.P2
    assert assign_priority(mk(severity="MEDIUM")).priority == Priority.P3
    assert assign_priority(mk(severity="LOW")).priority == Priority.P4
    assert assign_priority(mk(severity="WAT")).priority == Priority.P4   # unknown -> monitor

    # test-path filter: segment match, not substring
    assert is_test_path("test/smoke/Dockerfile", ["test/"]) is True
    assert is_test_path("Dockerfile", ["test/"]) is False
    assert is_test_path("latest/main.tf", ["test"]) is False            # 'latest' not 'test'
    assert is_test_path("modules/examples/ec2.tf", ["examples"]) is True
    assert is_test_path("test/smoke/Dockerfile", ["test/smoke"]) is True

    # partition: prod graded, test filtered out
    prod, tests = partition(
        [mk(target="Dockerfile", severity="HIGH"),
         mk(target="test/smoke/Dockerfile", severity="HIGH")],
        ["test/"])
    assert len(prod) == 1 and len(tests) == 1
    assert prod[0].priority == Priority.P2 and tests[0].priority is None
    # no test paths -> nothing filtered
    prod2, tests2 = partition([mk(target="test/x.tf")], [])
    assert len(prod2) == 1 and len(tests2) == 0
    print("demo: all assertions passed")


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--demo" in argv:
        demo()
        sys.exit(0)

    tp_file = _parse_test_paths_flag(argv)
    positional = [a for a in argv if not a.startswith("-") and a != tp_file]
    path = positional[0] if positional else "IAC.json"

    prod, tests = run(path, tp_file)

    print(json.dumps(summarize(prod, tests), indent=2))
    print()
    if tp_file:
        print(f"[filter] test paths from '{tp_file}': {load_test_paths(tp_file)}")
    else:
        print("[filter] no --test-paths file given; all findings treated as prod")
    print()
    print(comparison_table(prod))
    print()

    groups = group_by_file(prod)
    print(f"PER-FILE VIEW  ({len(prod)} prod findings -> {len(groups)} files)")
    print("-" * 64)
    for g in groups:
        print(f"{g.priority.name} {g.target}  ({g.finding_count} findings, top={g.top_severity})")

    if tests:
        print()
        print(f"FILTERED AS TEST  ({len(tests)} findings excluded from the priority queue)")
        print("-" * 64)
        for f in tests:
            print(f"  - {f.target}  [{f.severity}] {f.check_id}  {f.title}")

    out_path = write_filtered_json(prod, tests)
    print()
    print(f"[written] {out_path}")
