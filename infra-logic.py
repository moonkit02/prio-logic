"""
Infra Misconfiguration Prioritization  (Prowler / OCSF)
=======================================================
Post-processes a Prowler cloud scan (OCSF JSON, a flat list of findings) into
four ranked tiers (P1-P4), the same 4-stage shape as sca-logic.py, so the queue
answers "which cloud misconfigs need fixing now."

The model — ONE pipeline, four stages (same shape as sca-logic; infra has no CVE
exploitation feed, so the override is a co-occurrence heuristic, not a KEV/EPSS fact):

    extract(FAIL only) -> [account filter] -> [1] OVERRIDES -> [2] BASE TIER
                          -> [3] VOLUME ESCALATION -> output (+ category fix-order)

  extract        keep only status_code=FAIL.
  account filter classify each finding by cloud account; a user-supplied list of
                 non-prod account IDs (a .txt, one per line) is filtered OUT of the
                 priority queue and reported separately. The user declares their
                 own prod/non-prod accounts; we do not guess.
  Stage 1  OVERRIDE    toxic combination: a resource (ARN) carrying BOTH an
                       exposure-leg and a weakness-leg finding forms a known attack
                       path, so its leg findings are pinned to P1 (a confirmed
                       multi-condition risk). Legs are matched on check-ID naming,
                       PROVIDER-AWARE (shared 'common' stems verified against
                       aws/azure/gcp/alibabacloud via --list-checks, + a per-provider
                       hook), with a monitoring/logging exclude list. Catches only
                       single-ARN combos (the CVE / IAM-graph legs need cross-scanner
                       data this script does not hold).
  Stage 2  BASE TIER   Trivy-style severity tier: CRITICAL->P1 ... LOW->P4. Prowler
                       severity is the signal (no CVE / EPSS for config checks).
  Stage 3  VOLUME      a finding whose category is one of the top-N most-failing
           ESCALATION  categories (a systemic weakness) is bumped one tier up, so
                       the worst-offending category is worked first. Capped at P2:
                       volume alone never mints a P1 -- P1 stays reserved for
                       CRITICAL severity (the only confirmed-bad axis). The rejected
                       idea was per-category attack-RELEVANCE weighting (unproven);
                       per-category FAIL VOLUME is observed, not guessed.
  output         priority + reasons, grouped by resource (ARN), CLI + filtered JSON.
                 PLUS a category fix-order view: categories ranked by FAIL count, so
                 the most-failing category (a systemic weakness) is tackled first.

Signals: severity (base tier), status_code (FAIL filter), cloud.account (filter),
cloud.provider (per-provider leg lists), unmapped.categories (volume escalation +
fix-order ranking), metadata.event_code (check-id, toxic leg matching),
resources[].uid (ARN, toxic grouping + resource view).

No network, no CVE: there is no EPSS/KEV/CVE layer here (that is sca/sbom's job).
"""

from __future__ import annotations
import json
import sys
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


# ---------------------------------------------------------------------------
# Config — tunable, grouped by the stage that uses them.
# ---------------------------------------------------------------------------
CONFIG = {
    # Stage 2 — base tier straight from Prowler severity. No exploitation feed
    # exists for config checks, so severity IS the signal.
    "severity_tier": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4},
    "default_tier": 4,           # INFORMATIONAL / unknown -> monitor, don't over-alert
    # Category label normalization (Prowler emits both spellings of some tags).
    "category_aliases": {"trustboundaries": "trust-boundaries"},
    # Stage 3 — category VOLUME escalation. A finding in one of the top-N
    # most-failing categories (a systemic weakness) is bumped up by `bump` tiers,
    # but never past `max_tier` (P2) -- volume alone must not create a P1.
    "category_volume": {
        "enabled": True,
        "top_n": 3,              # the N highest-FAIL categories count as systemic
        "bump": 1,               # tiers to escalate findings in those categories
        "max_tier": 2,           # ceiling for a volume bump (P2; P1 = CRITICAL only)
    },
    # Stage 1 — TOXIC COMBINATION override. When the SAME resource (ARN) carries
    # both an EXPOSURE-leg finding (reachable from outside) and a WEAKNESS-leg
    # finding (data left unprotected), the two together form a known attack path
    # (pattern per DataDog Pathfinding Labs: "public + no-encryption" etc), so the
    # leg findings are pinned to `tier` (P1) — a confirmed multi-condition risk,
    # unlike single-severity or volume. Legs are matched on check-ID NAMING; this
    # is a heuristic on Prowler's own naming, NOT an evidence feed. It only catches
    # combos where BOTH legs are misconfig checks on one ARN — the CVE / sensitive-
    # data / IAM-graph legs need cross-scanner data this script does not hold.
    #
    # PROVIDER-AWARE: leg substrings were verified against `prowler <p> --list-checks`
    # for aws/azure/gcp/alibabacloud. Finding: Prowler reuses the same English stems
    # across all four, so the leg lists are shared (`common`) — the encryption stem
    # 'encrypt' alone covers nearly every at-rest check on every cloud; provider-
    # specific key terms (kms/cmk/cmek/csek) were dropped as REDUNDANT (they always
    # co-occur with 'encrypt') and HARMFUL ('kms' also matches kms_key_not_publicly_
    # accessible = exposure, and kms_cmk_rotation = key hygiene). `by_provider` is the
    # extension point (empty today) for a future cloud that names things differently.
    "toxic_combo": {
        "enabled": True,
        "tier": 1,               # confirmed exposure+weakness path -> emergency
        # A check matching any of these is NEVER a leg, even if it says "public":
        # monitoring/alerting/logging-config checks (verified false positives:
        # azure monitor_alert_*_public_ip_*, aws route53_public_*_logging_enabled).
        "exclude_legs": ["alert", "logging_enabled"],
        # Shared across all providers (verified universal via --list-checks):
        "common": {
            "exposure": ["public", "internet", "exposed", "allow_ingress",
                         "unrestricted", "anonymous"],
            "weakness": ["encrypt", "ssl", "secure_transport", "secure_transfer",
                         "mfa_delete", "object_lock", "tde"],
        },
        # Per-provider EXTRA substrings, merged on top of `common`. Empty because the
        # common stems already cover aws/azure/gcp/alibabacloud; kept as the hook.
        "by_provider": {
            "aws": {"exposure": [], "weakness": []},
            "azure": {"exposure": [], "weakness": []},
            "gcp": {"exposure": [], "weakness": []},
            "alibabacloud": {"exposure": [], "weakness": []},
        },
    },
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
    check_id: str               # metadata.event_code, e.g. s3_bucket_kms_encryption
    resource: str               # resources[0].uid (ARN) — the grouping key
    resource_type: str          # AwsS3Bucket, AwsLambdaFunction, ...
    title: str
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW
    status: str                 # FAIL (PASS is filtered at extract)
    categories: list[str] = field(default_factory=list)   # normalized
    provider: str = ""          # cloud.provider (aws / azure / gcp / alibabacloud)
    account: str = ""           # cloud.account.uid
    region: str = ""
    remediation: str = ""
    excluded: bool = False      # set by the account filter
    priority: Optional[Priority] = None
    reasons: list[str] = field(default_factory=list)


# ===========================================================================
# STEP 1 — load the report (default: INFRA.json in current directory)
# ===========================================================================
def load_report(path: str = "INFRA.json") -> list | dict:
    with open(path) as fh:
        return json.load(fh)


def _norm_cat(c: str, cfg: dict = CONFIG) -> str:
    c = (c or "").strip().lower()
    return cfg["category_aliases"].get(c, c)


# ===========================================================================
# STEP 2 — extract signals from each OCSF finding; keep only FAIL.
# ===========================================================================
def extract_signals(report) -> list[Finding]:
    items = report if isinstance(report, list) else report.get("findings", [])
    findings: list[Finding] = []
    for f in items:
        if f.get("status_code") != "FAIL":
            continue
        res = (f.get("resources") or [{}])[0]
        um = f.get("unmapped") or {}
        rem = f.get("remediation") or {}
        findings.append(Finding(
            check_id=f.get("metadata", {}).get("event_code") or "unknown",
            resource=res.get("uid") or res.get("name") or "",
            resource_type=res.get("type") or "",
            title=f.get("finding_info", {}).get("title") or "",
            severity=(f.get("severity") or "UNKNOWN").upper(),
            status=f.get("status_code") or "",
            categories=[_norm_cat(c) for c in (um.get("categories") or [])],
            provider=((f.get("cloud", {}) or {}).get("provider") or "").lower(),
            account=(f.get("cloud", {}).get("account", {}) or {}).get("uid") or "",
            region=res.get("region") or "",
            remediation=rem.get("desc", "") if isinstance(rem, dict) else "",
        ))
    return findings


# ===========================================================================
# Account filter — the user declares their non-prod accounts in a .txt file.
# ===========================================================================
def load_excluded_accounts(path: Optional[str]) -> set[str]:
    """One account ID per line; blank lines and # comments ignored. Missing -> set()."""
    if not path:
        return set()
    out: set[str] = set()
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(line)
    return out


# ===========================================================================
# Corpus pre-pass — the two corpus-level signals (toxic resources & systemic
# categories) are resolved ONCE over the whole prod set, then fed per-finding.
# (Mirrors sca-logic's KEV/EPSS enricher section that precedes STEP 3.)
# ===========================================================================
def _legs_for(provider: str, kind: str, cfg: dict = CONFIG) -> list[str]:
    """Resolve the leg substrings for a provider: shared `common` list + any
    per-provider extras. `kind` is 'exposure' or 'weakness'."""
    tc = cfg["toxic_combo"]
    extra = tc["by_provider"].get((provider or "").lower(), {}).get(kind, [])
    return tc["common"][kind] + extra


def _is_leg(check_id: str, patterns: list[str], cfg: dict = CONFIG) -> bool:
    """True if the check-id matches a leg substring AND is not on the exclude list
    (monitoring/alerting/logging-config checks that merely mention 'public')."""
    c = (check_id or "").lower()
    if any(x in c for x in cfg["toxic_combo"]["exclude_legs"]):
        return False
    return any(p in c for p in patterns)


def toxic_arns(findings: list[Finding], cfg: dict = CONFIG) -> frozenset:
    """Resources (ARNs) that carry BOTH an exposure-leg and a weakness-leg finding.
    That co-occurrence on one resource is the known attack-path pattern (feeds Stage 1).
    Legs are resolved per the finding's cloud provider."""
    tc = cfg["toxic_combo"]
    if not tc["enabled"]:
        return frozenset()
    from collections import defaultdict
    legs: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        if _is_leg(f.check_id, _legs_for(f.provider, "exposure", cfg), cfg):
            legs[f.resource].add("exposure")
        if _is_leg(f.check_id, _legs_for(f.provider, "weakness", cfg), cfg):
            legs[f.resource].add("weakness")
    return frozenset(arn for arn, kinds in legs.items()
                     if arn and {"exposure", "weakness"} <= kinds)


def systemic_categories(findings: list[Finding], cfg: dict = CONFIG) -> frozenset:
    """The top-N categories by FAIL volume (a systemic weakness, feeds Stage 3).
    '(uncategorized)' is never systemic -- escalating an unlabelled bucket carries
    no signal."""
    vc = cfg["category_volume"]
    if not vc["enabled"]:
        return frozenset()
    ranked = category_failcounts(findings)
    top = [cat for cat, _ in ranked[:vc["top_n"]] if cat != "(uncategorized)"]
    return frozenset(top)


# ===========================================================================
# STEP 3 — assign priority: the 4-stage model
# ===========================================================================
def assign_priority(f: Finding, cfg: dict = CONFIG,
                    systemic_cats: frozenset = frozenset(),
                    toxic_arns: frozenset = frozenset()) -> Finding:
    # Stage 1 — OVERRIDE: same-ARN toxic combination (exposure + weakness).
    override = _stage1_override(f, cfg, toxic_arns)
    if override is not None:
        return _set(f, *override)

    # Stage 2 — BASE TIER: Prowler severity -> tier.
    p = _stage2_base_tier(f, cfg)

    # Stage 3 — VOLUME ESCALATION: bump findings in systemic (high-volume) categories.
    p = _stage3_volume(f, p, cfg, systemic_cats)

    f.priority = p
    return f


def _stage1_override(f: Finding, cfg: dict,
                     toxic_arns: frozenset) -> Optional[tuple[Priority, str]]:
    """Toxic combination: if this finding is one of the two legs (exposure OR
    weakness) on a resource already flagged as toxic, pin it to the toxic tier."""
    tc = cfg["toxic_combo"]
    if not tc["enabled"] or f.resource not in toxic_arns:
        return None
    if _is_leg(f.check_id, _legs_for(f.provider, "exposure", cfg), cfg):
        return Priority(tc["tier"]), f"[toxic] exposure leg on multi-risk resource -> P{tc['tier']}"
    if _is_leg(f.check_id, _legs_for(f.provider, "weakness", cfg), cfg):
        return Priority(tc["tier"]), f"[toxic] weakness leg on multi-risk resource -> P{tc['tier']}"
    return None


def _stage2_base_tier(f: Finding, cfg: dict) -> Priority:
    """Prowler severity -> tier. Severity is the only 'how bad' axis."""
    p = Priority(cfg["severity_tier"].get(f.severity, cfg["default_tier"]))
    f.reasons.append(f"[base] severity={f.severity} -> {p.name}")
    return p


def _stage3_volume(f: Finding, p: Priority, cfg: dict,
                   systemic_cats: frozenset) -> Priority:
    """Escalate findings in a systemic (top-N most-failing) category by one tier,
    capped at max_tier so volume alone never reaches P1. Category attack-RELEVANCE
    weighting was rejected as unproven; this uses observed FAIL VOLUME only."""
    vc = cfg["category_volume"]
    if not vc["enabled"] or not systemic_cats:
        return p
    if any(c in systemic_cats for c in f.categories):
        # lower int = higher priority; don't go below the max_tier ceiling.
        new = Priority(max(vc["max_tier"], int(p) - vc["bump"]))
        if new != p:
            f.reasons.append(f"[volume] systemic category -> {p.name}->{new.name}")
            return new
    return p


def _set(f: Finding, p: Priority, reason: str) -> Finding:
    f.priority = p
    f.reasons.append(reason)
    return f


def partition(findings: list[Finding], excluded_accounts: set[str]) -> tuple[list[Finding], list[Finding]]:
    """Split into (prod, excluded). Prod findings get a tier; findings from a
    user-declared non-prod account are filtered out but kept for the report."""
    prod, excluded = [], []
    for f in findings:
        if excluded_accounts and f.account in excluded_accounts:
            f.excluded = True
            f.reasons.append(f"[filtered] non-prod account {f.account} -> excluded from queue")
            excluded.append(f)
        else:
            prod.append(f)
    # Stage 3 (volume) and Stage 1 (toxic) are corpus-level: rank categories and
    # find multi-risk resources across the whole prod set before grading each one.
    systemic = systemic_categories(prod)
    toxic = toxic_arns(prod)
    for f in prod:
        assign_priority(f, systemic_cats=systemic, toxic_arns=toxic)
    prod.sort(key=lambda x: (x.priority, x.resource))
    excluded.sort(key=lambda x: x.account)
    return prod, excluded


# ---------------------------------------------------------------------------
# Per-resource grouping (act on the resource / ARN)
# ---------------------------------------------------------------------------
@dataclass
class ResourceGroup:
    resource: str
    priority: Priority
    finding_count: int
    top_severity: str
    resource_type: str
    categories: list[str]
    check_ids: list[str]


def group_by_resource(findings: list[Finding]) -> list[ResourceGroup]:
    from collections import defaultdict
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[f.resource].append(f)
    groups = []
    for res, fs in buckets.items():
        top = min(fs, key=lambda x: x.priority)
        cats = sorted({c for f in fs for c in f.categories})
        groups.append(ResourceGroup(
            resource=res,
            priority=top.priority,
            finding_count=len(fs),
            top_severity=top.severity,
            resource_type=top.resource_type,
            categories=cats,
            check_ids=sorted({f.check_id for f in fs}),
        ))
    groups.sort(key=lambda g: (g.priority, -g.finding_count))
    return groups


# ---------------------------------------------------------------------------
# Category fix-order — the headline infra view.
# A category with many FAILs is a systemic weakness; fix that category first.
# ---------------------------------------------------------------------------
def category_failcounts(findings: list[Finding]) -> list[tuple[str, int]]:
    """Count FAIL findings per category, ranked high to low. Uncategorized findings
    are bucketed under '(uncategorized)' so the totals reconcile."""
    from collections import Counter
    c: Counter = Counter()
    for f in findings:
        for cat in (f.categories or ["(uncategorized)"]):
            c[cat] += 1
    return c.most_common()


def render_toxic_combos(findings: list[Finding], cfg: dict = CONFIG) -> str:
    """Show each toxic resource and the two legs (exposure + weakness) on it."""
    tc = cfg["toxic_combo"]
    arns = toxic_arns(findings, cfg)
    rows = [f"TOXIC COMBINATIONS  (same-ARN exposure + weakness -> P{tc['tier']})",
            "-" * 64]
    if not arns:
        rows.append("  none: no resource carries both an exposure and a weakness leg")
        return "\n".join(rows)
    from collections import defaultdict
    exp: dict[str, list[str]] = defaultdict(list)
    wk: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        if f.resource in arns and _is_leg(f.check_id, _legs_for(f.provider, "exposure", cfg), cfg):
            exp[f.resource].append(f.check_id)
        if f.resource in arns and _is_leg(f.check_id, _legs_for(f.provider, "weakness", cfg), cfg):
            wk[f.resource].append(f.check_id)
    for arn in sorted(arns):
        rows.append(f"  {arn}")
        rows.append(f"      exposure: {sorted(set(exp[arn]))}")
        rows.append(f"      weakness: {sorted(set(wk[arn]))}")
    return "\n".join(rows)


def render_category_order(findings: list[Finding]) -> str:
    ranked = category_failcounts(findings)
    systemic = systemic_categories(findings)
    rows = ["FIX-FIRST CATEGORIES  (by FAIL count -- systemic-weakness view)",
            "  * = systemic: findings here escalated one tier (cap P2)",
            "-" * 64]
    for cat, n in ranked:
        mark = " *" if cat in systemic else "  "
        rows.append(f"{mark}{n:>4}  {cat}")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _sev_bucket(s: str) -> str:
    s = (s or "").lower()
    return s if s in ("critical", "high", "medium", "low") else "low"


def _render_comparison(findings, sev_bucket) -> str:
    """severity counts -> priority counts (severity is 1:1 with tier for infra)."""
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


def summarize(prod: list[Finding], excluded: list[Finding]) -> dict:
    from collections import Counter
    return {
        "total_fail": len(prod) + len(excluded),
        "prioritized_prod": len(prod),
        "excluded_nonprod": len(excluded),
        "by_priority": dict(Counter(f.priority.name for f in prod)),
        "categories_by_failcount": dict(category_failcounts(prod)),
        "toxic_combination_resources": sorted(toxic_arns(prod)),
    }


# ===========================================================================
# STEP 5 — JSON output (filtered-infra.json)
# ===========================================================================
def finding_to_dict(f: Finding) -> dict:
    d = asdict(f)
    d["priority"] = int(f.priority) if f.priority is not None else None
    d["priority_label"] = f.priority.label if f.priority is not None else None
    return d


def write_filtered_json(prod: list[Finding], excluded: list[Finding],
                        path: str = "filtered-infra.json") -> str:
    out = {
        "summary": summarize(prod, excluded),
        "findings": [finding_to_dict(f) for f in prod],
        "excluded_nonprod_findings": [finding_to_dict(f) for f in excluded],
        "resources": [
            {
                "resource": g.resource,
                "resource_type": g.resource_type,
                "priority": int(g.priority),
                "priority_label": g.priority.label,
                "finding_count": g.finding_count,
                "top_severity": g.top_severity,
                "categories": g.categories,
                "check_ids": g.check_ids,
            }
            for g in group_by_resource(prod)
        ],
    }
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
    return path


# ===========================================================================
# Driver
# ===========================================================================
def run(path: str = "INFRA.json", accounts_file: Optional[str] = None):
    report = load_report(path)                       # step 1
    findings = extract_signals(report)               # step 2 (FAIL only)
    excluded_accounts = load_excluded_accounts(accounts_file)
    return partition(findings, excluded_accounts)     # step 3 (filter + base tier)


def _parse_accounts_flag(argv: list[str]) -> Optional[str]:
    for i, a in enumerate(argv):
        if a == "--exclude-accounts" and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith("--exclude-accounts="):
            return a.split("=", 1)[1]
    return None


# ---------------------------------------------------------------------------
# Self-check — one assertion per stage / feature.
# ---------------------------------------------------------------------------
def demo() -> None:
    def mk(**kw):
        base = dict(check_id="c", resource="arn:x", resource_type="AwsS3Bucket",
                    title="t", severity="HIGH", status="FAIL")
        base.update(kw)
        return Finding(**base)

    # base tier: severity -> tier
    assert assign_priority(mk(severity="CRITICAL")).priority == Priority.P1
    assert assign_priority(mk(severity="HIGH")).priority == Priority.P2
    assert assign_priority(mk(severity="MEDIUM")).priority == Priority.P3
    assert assign_priority(mk(severity="LOW")).priority == Priority.P4
    assert assign_priority(mk(severity="INFORMATIONAL")).priority == Priority.P4

    # category normalization: both spellings collapse to one
    assert _norm_cat("trustboundaries") == "trust-boundaries"
    assert _norm_cat("Logging") == "logging"

    # category fix-order: most-failing category ranked first
    fs = [mk(categories=["logging"]), mk(categories=["logging"]),
          mk(categories=["encryption"])]
    ranked = category_failcounts(fs)
    assert ranked[0] == ("logging", 2), ranked
    # uncategorized findings still counted
    assert category_failcounts([mk(categories=[])])[0] == ("(uncategorized)", 1)

    # volume escalation: a MEDIUM (P3) in a systemic category -> P2, capped at P2
    sysset = systemic_categories([mk(categories=["logging"]), mk(categories=["logging"])])
    assert "logging" in sysset
    assert assign_priority(mk(severity="MEDIUM", categories=["logging"]),
                           systemic_cats=sysset).priority == Priority.P2   # P3 -> P2
    assert assign_priority(mk(severity="LOW", categories=["logging"]),
                           systemic_cats=sysset).priority == Priority.P3   # P4 -> P3
    # cap: a HIGH (P2) in a systemic category stays P2, never P1 from volume
    assert assign_priority(mk(severity="HIGH", categories=["logging"]),
                           systemic_cats=sysset).priority == Priority.P2
    # non-systemic category untouched
    assert assign_priority(mk(severity="MEDIUM", categories=["other"]),
                           systemic_cats=sysset).priority == Priority.P3
    # uncategorized never systemic
    assert "(uncategorized)" not in systemic_categories([mk(categories=[])])

    # toxic combination: exposure + weakness on the SAME arn -> both legs P1
    tox = [mk(resource="arn:aws:s3:::b", check_id="s3_bucket_public_access", severity="MEDIUM"),
           mk(resource="arn:aws:s3:::b", check_id="s3_bucket_kms_encryption", severity="LOW"),
           mk(resource="arn:aws:s3:::safe", check_id="s3_bucket_kms_encryption", severity="LOW")]
    tset = toxic_arns(tox)
    assert tset == frozenset({"arn:aws:s3:::b"}), tset      # only 'b' has both legs
    p_exp = assign_priority(mk(resource="arn:aws:s3:::b", check_id="s3_bucket_public_access",
                               severity="MEDIUM"), toxic_arns=tset)
    p_wk = assign_priority(mk(resource="arn:aws:s3:::b", check_id="s3_bucket_kms_encryption",
                              severity="LOW"), toxic_arns=tset)
    assert p_exp.priority == Priority.P1 and p_wk.priority == Priority.P1   # both legs -> P1
    # weakness leg on a resource WITHOUT an exposure leg -> normal grading, not P1
    assert assign_priority(mk(resource="arn:aws:s3:::safe", check_id="s3_bucket_kms_encryption",
                              severity="LOW"), toxic_arns=tset).priority == Priority.P4

    # provider-aware: an AZURE toxic pair fires on the shared 'common' stems
    az = [mk(provider="azure", resource="az/store", check_id="storage_blob_public_access_level_is_disabled"),
          mk(provider="azure", resource="az/store", check_id="storage_ensure_encryption_with_customer_managed_keys")]
    assert toxic_arns(az) == frozenset({"az/store"}), toxic_arns(az)
    # ALIBABA tde weakness (no 'encrypt' stem) still recognised via the 'tde' term
    ali = [mk(provider="alibabacloud", resource="ali/db", check_id="rds_instance_no_public_access_whitelist"),
           mk(provider="alibabacloud", resource="ali/db", check_id="rds_instance_tde_enabled")]
    assert toxic_arns(ali) == frozenset({"ali/db"}), toxic_arns(ali)

    # over-match fix: kms_key_not_publicly_accessible is EXPOSURE (has 'public'),
    # NOT weakness ('kms' dropped) -> a lone KMS key is not a toxic combo
    kms = [mk(resource="arn:kms:key", check_id="kms_key_not_publicly_accessible")]
    assert toxic_arns(kms) == frozenset(), toxic_arns(kms)
    assert _is_leg("kms_key_not_publicly_accessible", _legs_for("aws", "exposure"))
    assert not _is_leg("kms_key_not_publicly_accessible", _legs_for("aws", "weakness"))
    assert not _is_leg("kms_cmk_rotation_enabled", _legs_for("aws", "weakness"))  # key hygiene, not weakness

    # exclude list: monitoring/alert checks that merely say 'public' are NOT legs
    assert not _is_leg("monitor_alert_create_update_public_ip_address_rule",
                       _legs_for("azure", "exposure"))
    assert not _is_leg("route53_public_hosted_zones_cloudwatch_logging_enabled",
                       _legs_for("aws", "exposure"))

    # account filter: non-prod account excluded, prod graded
    prod, excl = partition(
        [mk(account="111", severity="HIGH"), mk(account="999", severity="HIGH")],
        {"999"})
    assert len(prod) == 1 and len(excl) == 1
    assert prod[0].priority == Priority.P2 and excl[0].priority is None
    print("demo: all assertions passed")


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--demo" in argv:
        demo()
        sys.exit(0)

    acc_file = _parse_accounts_flag(argv)
    positional = [a for a in argv if not a.startswith("-") and a != acc_file]
    path = positional[0] if positional else "INFRA.json"

    prod, excluded = run(path, acc_file)

    print(json.dumps(summarize(prod, excluded), indent=2))
    print()
    if acc_file:
        print(f"[filter] non-prod accounts from '{acc_file}': {sorted(load_excluded_accounts(acc_file))}")
    else:
        print("[filter] no --exclude-accounts file; all accounts treated as prod")
    print()
    print(comparison_table(prod))
    print()
    print(render_toxic_combos(prod))
    print()
    print(render_category_order(prod))
    print()

    groups = group_by_resource(prod)
    print(f"PER-RESOURCE VIEW  ({len(prod)} prod findings -> {len(groups)} resources)")
    print("-" * 64)
    for g in groups[:20]:
        print(f"{g.priority.name} {g.resource}  ({g.finding_count} findings, "
              f"top={g.top_severity}, type={g.resource_type})")
    if len(groups) > 20:
        print(f"  ... and {len(groups) - 20} more resources")

    if excluded:
        print()
        print(f"EXCLUDED (non-prod accounts)  ({len(excluded)} findings)")

    out_path = write_filtered_json(prod, excluded)
    print()
    print(f"[written] {out_path}")
