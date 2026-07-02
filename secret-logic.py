"""
Secret-Leak Prioritization  (Trivy secret scan)
===============================================
Post-processes a Trivy secret scan (Results[].Secrets[] — hardcoded credentials,
API keys, private keys, tokens found in source) into four ranked tiers (P1-P4),
the same 4-stage shape as the other prio-logic scripts, so the queue answers
"which leaked secrets need rotating now."

The model — ONE pipeline (secret scan is thin, like IaC; some stages are empty):

    extract(all secrets) -> [filter] prod vs test -> [base tier] severity -> output

  extract       pull every secret from Results[].Secrets[] (Trivy emits no PASS
                rows for secrets — a row IS a hit).
  [filter]      classify each secret as prod or test by its Target path, using a
                user-supplied list of test folder paths (a .txt, one path per line).
                Test secrets are FILTERED OUT of the priority queue and reported
                separately — they are almost always dummy fixtures (a fake JWT in a
                *.spec.ts, a sample key in examples/). Filter != ignore: they stay
                in the report so a real secret parked in a test file is still visible.
                No heuristic guessing of test dirs — the user declares their layout.
  [base tier]   prod secrets: Trivy Severity -> tier (CRITICAL->P1 ... LOW->P4).
                Severity is per-rule (a private key outranks a generic token), and
                it is the only "how bad" axis available.
  [output]      prioritized prod secrets + the filtered test list, grouped by file.

Scope ceiling (state it, don't paper over it): the scanner does NOT verify whether
a secret is live — there is no liveness/validity check, so we cannot rank by "this
key still works." Every hit is treated as real until a human rotates it. A future
Stage-1 override "verified-live secret -> P1" would slot in if a verifier feed were
added; it is not wired, because this engine has no such field.

No Stage-1 override and no Stage-3 downgrade: there is no confirmed-exploitation
fact, and the path is a *filter*, not a demote.

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
    # Base tier straight from Trivy severity. No liveness/exploitation feed exists
    # for a leaked secret, so severity (per-rule) IS the signal.
    "severity_tier": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4},
    "default_tier": 4,           # unknown severity -> monitor, don't over-alert
}


class Priority(IntEnum):
    P1 = 1   # emergency - rotate now
    P2 = 2   # urgent    - rotate soon
    P3 = 3   # plan      - schedule rotation
    P4 = 4   # monitor   - accept / watch

    @property
    def label(self) -> str:
        return {
            Priority.P1: "Priority 1 - EMERGENCY (rotate now)",
            Priority.P2: "Priority 2 - URGENT (rotate soon)",
            Priority.P3: "Priority 3 - PLAN (schedule rotation)",
            Priority.P4: "Priority 4 - MONITOR (accept/watch)",
        }[self]


# ---------------------------------------------------------------------------
# Extracted signals per secret
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    rule_id: str                # RuleID, e.g. private-key, jwt-token, aws-access-key-id
    target: str                 # Results[].Target — the file the secret was found in
    title: str                  # Title, e.g. "Asymmetric Private Key"
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW
    category: str = ""          # Category, e.g. AsymmetricPrivateKey / JWT / AWS
    start_line: int = 0         # StartLine — where in the file
    match: str = ""             # Match — the matched line (Trivy already redacts it)
    is_test: bool = False       # set by the prod-vs-test filter
    priority: Optional[Priority] = None
    reasons: list[str] = field(default_factory=list)


# ===========================================================================
# STEP 1 — load the report (default: SECRET.json in current directory)
# ===========================================================================
def load_report(path: str = "SECRET.json") -> dict:
    with open(path) as fh:
        return json.load(fh)


# ===========================================================================
# STEP 2 — extract signals from Results[].Secrets[]. Every row is a hit.
# ===========================================================================
def extract_signals(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for r in report.get("Results", []):
        target = r.get("Target", "")
        for s in (r.get("Secrets") or []):
            findings.append(Finding(
                rule_id=s.get("RuleID") or "unknown",
                target=target,
                title=s.get("Title", ""),
                severity=(s.get("Severity") or "UNKNOWN").upper(),
                category=s.get("Category", ""),
                start_line=s.get("StartLine", 0) or 0,
                match=s.get("Match", ""),
            ))
    return findings


# ===========================================================================
# Test-path filter — the user declares their own test folders in a .txt file.
# (Same mechanism as iac-logic; the two scanners can share one --test-paths file.)
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
    """True if the secret's Target sits under any user-declared test folder.
    Matched as a path segment so 'test' hits 'test/smoke/app.ts' but not
    'latest/main.ts'. A bare filename suffix like '.spec.ts' is matched too, so
    spec fixtures get filtered without listing every directory."""
    norm = "/" + target.replace("\\", "/").strip("/").lower() + "/"
    for tp in test_paths:
        t = tp.replace("\\", "/").strip("/").lower()
        seg = "/" + t + "/"
        if seg in norm:
            return True
        # allow a filename-suffix rule like ".spec.ts" or "_test.go"
        if t.startswith(".") or t.startswith("_") or t.startswith("*"):
            if norm.rstrip("/").endswith(t.lstrip("*")):
                return True
    return False


# ===========================================================================
# STEP 3 — base tier: Trivy severity -> tier (prod secrets only).
# ===========================================================================
def assign_priority(f: Finding, cfg: dict = CONFIG) -> Finding:
    p = Priority(cfg["severity_tier"].get(f.severity, cfg["default_tier"]))
    f.priority = p
    f.reasons.append(f"[base] severity={f.severity} -> {p.name}")
    return f


def partition(findings: list[Finding], test_paths: list[str]) -> tuple[list[Finding], list[Finding]]:
    """Split into (prod, test). Prod secrets get a tier; test secrets are filtered
    out of the priority queue but kept for the report."""
    prod, tests = [], []
    for f in findings:
        if test_paths and is_test_path(f.target, test_paths):
            f.is_test = True
            f.reasons.append(f"[filtered] test path '{f.target}' -> excluded from priority queue")
            tests.append(f)
        else:
            assign_priority(f)
            prod.append(f)
    prod.sort(key=lambda x: (x.priority, x.target, x.start_line))
    tests.sort(key=lambda x: x.target)
    return prod, tests


# ---------------------------------------------------------------------------
# Per-file grouping (act on the file — rotate everything leaked from it)
# ---------------------------------------------------------------------------
@dataclass
class FileGroup:
    target: str
    priority: Priority
    secret_count: int
    top_severity: str
    rule_ids: list[str]


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
            secret_count=len(fs),
            top_severity=top.severity,
            rule_ids=sorted({x.rule_id for x in fs}),
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
    """severity counts -> priority counts (prod secrets only)."""
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
        "total_secrets": len(prod) + len(tests),
        "prioritized_prod": len(prod),
        "filtered_test": len(tests),
        "by_priority": dict(Counter(f.priority.name for f in prod)),
    }


# ===========================================================================
# STEP 4 — JSON output (filtered-secret.json)
# ===========================================================================
def finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    d["priority"] = int(f.priority) if f.priority is not None else None
    d["priority_label"] = f.priority.label if f.priority is not None else None
    return d


def write_filtered_json(prod: list[Finding], tests: list[Finding],
                        path: str = "filtered-secret.json") -> str:
    out = {
        "summary": summarize(prod, tests),
        "findings": [finding_to_dict(f) for f in prod],
        "filtered_test_findings": [finding_to_dict(f) for f in tests],
        "files": [
            {
                "target": g.target,
                "priority": int(g.priority),
                "priority_label": g.priority.label,
                "secret_count": g.secret_count,
                "top_severity": g.top_severity,
                "rule_ids": g.rule_ids,
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
def run(path: str = "SECRET.json", test_paths_file: Optional[str] = None):
    report = load_report(path)                       # step 1
    findings = extract_signals(report)               # step 2 (all secrets)
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
        base = dict(rule_id="jwt-token", target="lib/insecurity.ts", title="t",
                    severity="HIGH")
        base.update(kw)
        return Finding(**base)

    # base tier: severity -> tier
    assert assign_priority(mk(severity="CRITICAL")).priority == Priority.P1
    assert assign_priority(mk(severity="HIGH")).priority == Priority.P2
    assert assign_priority(mk(severity="MEDIUM")).priority == Priority.P3
    assert assign_priority(mk(severity="LOW")).priority == Priority.P4
    assert assign_priority(mk(severity="WAT")).priority == Priority.P4   # unknown -> monitor

    # test-path filter: segment match, not substring
    assert is_test_path("test/smoke/app.ts", ["test/"]) is True
    assert is_test_path("lib/insecurity.ts", ["test/"]) is False
    assert is_test_path("latest/main.ts", ["test"]) is False             # 'latest' not 'test'
    assert is_test_path("modules/examples/key.ts", ["examples"]) is True
    # filename-suffix rule filters spec fixtures without listing dirs
    assert is_test_path("frontend/src/app/app.guard.spec.ts", [".spec.ts"]) is True
    assert is_test_path("lib/insecurity.ts", [".spec.ts"]) is False

    # partition: prod graded, test filtered out
    prod, tests = partition(
        [mk(target="lib/insecurity.ts", severity="HIGH"),
         mk(target="frontend/x.spec.ts", severity="MEDIUM")],
        [".spec.ts"])
    assert len(prod) == 1 and len(tests) == 1
    assert prod[0].priority == Priority.P2 and tests[0].priority is None
    # no test paths -> nothing filtered
    prod2, tests2 = partition([mk(target="x.spec.ts")], [])
    assert len(prod2) == 1 and len(tests2) == 0
    print("demo: all assertions passed")


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--demo" in argv:
        demo()
        sys.exit(0)

    tp_file = _parse_test_paths_flag(argv)
    positional = [a for a in argv if not a.startswith("-") and a != tp_file]
    path = positional[0] if positional else "SECRET.json"

    prod, tests = run(path, tp_file)

    print(json.dumps(summarize(prod, tests), indent=2))
    print()
    if tp_file:
        print(f"[filter] test paths from '{tp_file}': {load_test_paths(tp_file)}")
    else:
        print("[filter] no --test-paths file given; all secrets treated as prod")
    print()
    print(comparison_table(prod))
    print()

    groups = group_by_file(prod)
    print(f"PER-FILE VIEW  ({len(prod)} prod secrets -> {len(groups)} files)")
    print("-" * 64)
    for g in groups:
        print(f"{g.priority.name} {g.target}  ({g.secret_count} secrets, top={g.top_severity}) {g.rule_ids}")

    if tests:
        print()
        print(f"FILTERED AS TEST  ({len(tests)} secrets excluded from the priority queue)")
        print("-" * 64)
        for f in tests:
            print(f"  - {f.target}:{f.start_line}  [{f.severity}] {f.rule_id}  {f.title}")

    out_path = write_filtered_json(prod, tests)
    print()
    print(f"[written] {out_path}")
