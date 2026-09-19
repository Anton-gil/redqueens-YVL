"""Empirical validators for the RWA invariant classes.

Each validator replays a candidate invariant against every benign trace in the corpus and returns
{checked, violations, max_observed_bps}. A single violation means the invariant is too tight (it
would reject legitimate activity) and the candidate is rejected. This is empirical checking against
a bounded corpus - never a proof - which is why every result is paired with the coverage report.
"""

ONE = 10**18


def _find(trace, key_exact):
    for e in trace:
        if e["key"] == key_exact:
            return e
    return None


def _find_prefix(trace, prefix, suffix):
    for e in trace:
        if e["key"].startswith(prefix) and e["key"].endswith(suffix):
            return e
    return None


def validate_exchange_rate_delta_bound(corpus, adapter="GoldAdapter", threshold_bps=100):
    """Class 5. For every benign trace touching the adapter's pool/shares, compute the exchange-rate
    delta it caused; a benign deposit moves pool and shares together so the rate should barely move."""
    checked = 0
    violations = 0
    max_bps = 0
    pool_key = "%s.pool.balance" % adapter
    shares_key = "%s.totalShares" % adapter
    for rec in corpus:
        pool = _find(rec.get("trace", []), pool_key)
        shares = _find(rec.get("trace", []), shares_key)
        if not pool or not shares:
            continue
        pre_pool, post_pool = int(pool["pre"]), int(pool["post"])
        pre_sh, post_sh = int(shares["pre"]), int(shares["post"])
        if pre_sh == 0 or post_sh == 0:
            continue
        rate_before = pre_pool * ONE // pre_sh
        rate_after = post_pool * ONE // post_sh
        if rate_before == 0:
            continue
        delta = abs(rate_after - rate_before)
        bps = delta * 10000 // rate_before
        checked += 1
        max_bps = max(max_bps, bps)
        if bps > threshold_bps:
            violations += 1
    return {"class": "ExchangeRateDeltaBound", "checked": checked, "violations": violations,
            "max_observed_bps": max_bps, "threshold_bps": threshold_bps}


def validate_adapter_conversion_integrity(corpus, adapter="GoldAdapter", tolerance_bps=100):
    """Class 1. For every benign deposit, the principal credited must equal tokens_in * price within
    tolerance. Benign deposits credit exactly tokens_in * price, so deviation should be ~0."""
    checked = 0
    violations = 0
    max_bps = 0
    for rec in corpus:
        if rec.get("category") not in ("deposit", "depositAndMint"):
            continue
        if str(rec.get("adapter", "")).lower() != adapter.lower():
            continue
        price_e = _find_prefix(rec.get("trace", []), "PriceRouter.price", "]")
        principal_e = _find_prefix(rec.get("trace", []), "Ledger.principal", "]")
        amount = rec.get("args", {}).get("amount")
        if not price_e or not principal_e or amount is None:
            continue
        price = int(price_e["post"])
        credited = int(principal_e["post"]) - int(principal_e["pre"])
        expected = int(amount) * price // ONE
        if expected <= 0:
            continue
        dev = abs(credited - expected)
        bps = dev * 10000 // expected
        checked += 1
        max_bps = max(max_bps, bps)
        if bps > tolerance_bps:
            violations += 1
    return {"class": "AdapterConversionIntegrity", "checked": checked, "violations": violations,
            "max_observed_bps": max_bps, "tolerance_bps": tolerance_bps}


def validate_accrual_semantic_consistency(corpus, adapter="xStockAdapter", expected_type="Rebase"):
    """Class 2. Rebase-type profile: the rebase multiplier must be monotonic and only change via
    corporate-action events, never as a side effect of a user deposit/withdraw. Checks the corpus's
    multiplier-change events form a monotonic non-decreasing series and that no deposit trace mutates
    the multiplier."""
    mult_key = "%s.rebaseMultiplier" % adapter
    events = []
    violations = 0
    checked = 0
    for rec in corpus:
        e = _find(rec.get("trace", []), mult_key)
        if not e:
            continue
        checked += 1
        if e["op"] == "write":
            if rec.get("category") not in ("xstock_multiplier_change",):
                violations += 1
            events.append(int(e["post"]))
    monotonic = all(events[i] <= events[i + 1] for i in range(len(events) - 1)) if events else True
    if not monotonic:
        violations += 1
    return {"class": "AccrualSemanticConsistency", "checked": checked, "violations": violations,
            "monotonic": monotonic, "events": len(events), "expected_type": expected_type}


VALIDATORS = {
    "ExchangeRateDeltaBound": validate_exchange_rate_delta_bound,
    "AdapterConversionIntegrity": validate_adapter_conversion_integrity,
    "AccrualSemanticConsistency": validate_accrual_semantic_consistency,
}
