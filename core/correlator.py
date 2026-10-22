"""
Correlator: scores findings instead of returning a flat list.

Confidence boosting rules:
1. Multi-source agreement: a finding reported by more than one source scores higher.
2. Cross-link: an email found by theHarvester that also appears in a breach
   is more likely to be real and tied to the target.
3. Decay: the further (depth) from the original input, the lower the weight.

Result: every finding gets a final confidence of 0..1 and a tier
(high/medium/low) so the report is easy to read.
"""
from __future__ import annotations

from .models import EntityType, Finding


def _tier(conf: float) -> str:
    if conf >= 0.75:
        return "high"
    if conf >= 0.5:
        return "medium"
    return "low"


def correlate(results: dict[str, Finding]) -> dict[str, Finding]:
    by_value: dict[str, list[Finding]] = {}
    for f in results.values():
        by_value.setdefault(f.value.lower(), []).append(f)

    # values that appear in a breach (for cross-linking emails/usernames)
    breached_accounts = {
        f.meta.get("account", "").lower()
        for f in results.values()
        if f.type == EntityType.BREACH and f.meta.get("account")
    }

    for f in results.values():
        conf = f.confidence

        # 1. multi-source agreement
        sources = f.meta.get("all_sources", [f.source])
        n_sources = len(set(sources))
        if n_sources >= 3:
            conf += 0.25
        elif n_sources == 2:
            conf += 0.15

        # 2. cross-link with breach
        if f.type in (EntityType.EMAIL, EntityType.USERNAME):
            if f.value.lower() in breached_accounts:
                conf += 0.1

        # 3. depth decay (-0.08 per hop)
        conf -= 0.08 * f.depth

        conf = max(0.0, min(1.0, conf))
        f.confidence = round(conf, 3)
        f.meta["tier"] = _tier(conf)
        f.meta["source_count"] = n_sources

    return results


def summarize(results: dict[str, Finding]) -> dict:
    """Short summary for the top of the report."""
    by_type: dict[str, int] = {}
    by_tier = {"high": 0, "medium": 0, "low": 0}
    for f in results.values():
        if f.source == "input":
            continue
        by_type[f.type] = by_type.get(f.type, 0) + 1
        by_tier[f.meta.get("tier", "low")] += 1
    return {
        "total": sum(1 for f in results.values() if f.source != "input"),
        "by_type": by_type,
        "by_tier": by_tier,
    }
