"""Trace differ + candidate invariant generator.

1. Extract every state-variable delta from the exploit trace.
2. For each variable, look up the benign distribution (corpus/stats.json: mean/std/p95/p99/max).
3. Rank variables by anomaly score (exploit_delta / max_benign) and z-score.
4. Pattern-match the top anomaly to an RWA invariant class.
5. Set threshold = max_observed_benign * safety_multiplier - or a policy floor when the quantity
   never moves under benign activity (which the coverage report flags explicitly).

This is the doc's compute_invariant, wired to the invariant library and the real corpus stats.
"""

import json

from invariants import generators as gen

_EPS = 1.0  # avoids div-by-zero for quantities that never move benignly


def load_stats(path=None):
    from agent import config
    p = path or (config.PROJECT_ROOT / "corpus" / "stats.json")
    return json.loads(open(p).read())


def _deployment():
    from agent import config
    if config.DEPLOYMENT_PATH.exists():
        return json.loads(config.DEPLOYMENT_PATH.read_text())
    return {"contracts": {}}


def _rank_anomalies(exploit_trace, stats):
    ranked = []
    for key, delta in exploit_trace["per_key_peak_delta"].items():
        st = stats.get(key, {})
        max_benign = st.get("max", 0.0)
        mean = st.get("mean", 0.0)
        std = st.get("std", 0.0)
        anomaly_score = delta / max(max_benign, _EPS)
        z = (delta - mean) / std if std > 0 else (float("inf") if delta > mean else 0.0)
        ranked.append({
            "variable": key, "exploit_delta": delta, "max_benign": max_benign,
            "anomaly_score": anomaly_score, "z_score": z,
            "moves_benignly": max_benign > 0,
        })
    # derived exchangeRate anomaly (benign rate delta is ~0 by construction; see coverage report)
    d = exploit_trace.get("derived")
    if d:
        ranked.append({
            "variable": d["quantity"], "exploit_delta": d["delta_bps"], "max_benign": 0.0,
            "anomaly_score": float("inf"), "z_score": float("inf"), "unit": "bps",
            "moves_benignly": False, "derived": True,
        })
    ranked.sort(key=lambda a: (a["anomaly_score"] == float("inf"), a["anomaly_score"]), reverse=True)
    return ranked


# exploit -> (primary class, alternative class, boundary). ExchangeRateDeltaBound is primary for both
# because it is the only class that actually catches donation-style oracle manipulation: it remembers
# the pre-manipulation rate via a checkpoint rather than trusting the (now-manipulated) live oracle.
# AdapterConversionIntegrity is the documented alternative, but against pure oracle manipulation it
# must be paired with a rate-delta bound (it compares the recorded value to getPrice(), which the
# donation also moves). The two exploits differ only in the entry-point BOUNDARY the guard must sit on
# - which is why advisory #2 (multicall boundary) is exactly the layered defense that closes advisory
# #1's multicall bypass.
_PATTERN_MATCH = {
    "adapter_donation": ("ExchangeRateDeltaBound", "AdapterConversionIntegrity", "deposit"),
    "stale_price_multicall": ("ExchangeRateDeltaBound", "AdapterConversionIntegrity", "depositAndMint"),
}


def _build_candidate(class_name, exploit_trace, safety_multiplier):
    dep = _deployment().get("contracts", {})
    adapter = dep.get("goldAdapter", "0x0000000000000000000000000000000000000A11")
    router = dep.get("PriceRouter", "0x0000000000000000000000000000000000000B22")
    if class_name == "ExchangeRateDeltaBound":
        # benign rate delta is 0 -> threshold is a policy floor, not a fitted bound (1% = 100 bps).
        spec = gen.exchange_rate_delta_bound(adapter, max_delta_bps=100, window_blocks=1)
        threshold_bps = 100
        threshold_note = ("benign exchange-rate delta is 0 across the corpus; 100 bps is a policy "
                          "floor, not a max-benign*safety fit")
        exploit_value_bps = exploit_trace["derived"]["delta_bps"]
        return spec, {"threshold_bps": threshold_bps, "exploit_value_bps": exploit_value_bps,
                      "threshold_note": threshold_note}
    if class_name == "AdapterConversionIntegrity":
        spec = gen.adapter_conversion_integrity(adapter, router, tolerance_bps=100)
        econ = exploit_trace["economics"]
        exploit_dev_bps = (econ["minted"] - econ["fair_value"]) * 10000 // max(econ["fair_value"], 1)
        return spec, {"tolerance_bps": 100, "exploit_deviation_bps": exploit_dev_bps,
                      "threshold_note": "recorded value must be within 1% of tokens_in * oracle price"}
    raise ValueError("unmapped class %s" % class_name)


def compute_candidates(exploit_trace, stats=None, safety_multiplier=10):
    stats = stats if stats is not None else load_stats()
    ranked = _rank_anomalies(exploit_trace, stats)
    primary_cls, alt_cls, boundary = _PATTERN_MATCH.get(
        exploit_trace["name"], ("AdapterConversionIntegrity", "ExchangeRateDeltaBound", "deposit"))
    primary_spec, primary_thr = _build_candidate(primary_cls, exploit_trace, safety_multiplier)
    alt_spec, alt_thr = _build_candidate(alt_cls, exploit_trace, safety_multiplier)
    return {
        "exploit": exploit_trace["name"],
        "vuln_ref": exploit_trace.get("vuln_ref"),
        "boundary": boundary,
        "top_anomaly": ranked[0],
        "ranked_anomalies": ranked,
        "safety_multiplier": safety_multiplier,
        "primary_candidate": {
            "class": primary_cls, "name": primary_spec.name, "params": primary_spec.params,
            "threshold": primary_thr, "solidity": primary_spec.solidity,
            "description": primary_spec.description,
        },
        "alternative_candidate": {
            "class": alt_cls, "name": alt_spec.name, "params": alt_spec.params,
            "threshold": alt_thr, "description": alt_spec.description,
        },
    }


def main():
    from agent import config
    from synthesis import exploit_trace as et
    out = {}
    for name, fn in et.EXPLOIT_TRACES.items():
        cand = compute_candidates(fn())
        out[name] = cand
        top = cand["top_anomaly"]
        print("=== %s (%s) ===" % (name, cand["vuln_ref"]))
        print("  top anomaly: %s  score=%s  delta=%s" % (
            top["variable"], top["anomaly_score"], top["exploit_delta"]))
        print("  primary candidate: %s (%s)" % (cand["primary_candidate"]["class"], cand["primary_candidate"]["name"]))
        print("  threshold: %s" % cand["primary_candidate"]["threshold"])
        print("  alternative: %s" % cand["alternative_candidate"]["class"])
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    slim = {k: {**v, "primary_candidate": {kk: vv for kk, vv in v["primary_candidate"].items() if kk != "solidity"}}
            for k, v in out.items()}
    (config.STATE_DIR / "candidates.json").write_text(json.dumps(slim, indent=2))
    print("\ncandidates -> orchestrator/state/candidates.json")


if __name__ == "__main__":
    main()
