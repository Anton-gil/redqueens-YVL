"""Empirical validation pipeline.

Runs a candidate invariant against every benign trace in the corpus, counts violations, computes
the margin between the threshold and the worst benign observation, and cross-references the coverage
report. Emits the validation report in the plan's format. Never claims "proof" - the confidence is
always qualified as "within covered scenarios" and paired with coverage warnings.
"""

import glob
import json


def load_corpus():
    from agent import config
    records = []
    for fp in sorted(glob.glob(str(config.PROJECT_ROOT / "corpus" / "data" / "*.jsonl"))):
        with open(fp) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return records


def load_coverage():
    from agent import config
    p = config.PROJECT_ROOT / "corpus" / "coverage_report.json"
    if p.exists():
        return json.loads(p.read_text())
    return {"coverage_warnings": []}


def _margin(threshold_bps, max_observed_bps):
    if max_observed_bps <= 0:
        return None, ">1000x (benign activity never moves this quantity in the corpus)"
    return round(threshold_bps / max_observed_bps, 2), "threshold / max_observed"


_FLOOR_BPS = 100  # never fit a threshold tighter than 1%, even if benign never moves


def _observe(cls, corpus):
    """Learn the worst benign observation for the class by validating with an unreachable
    threshold (so violations are impossible and we just read max_observed_bps)."""
    from invariants import validators
    huge = 10**9
    if cls == "ExchangeRateDeltaBound":
        return validators.validate_exchange_rate_delta_bound(corpus, "GoldAdapter", huge)
    if cls == "AdapterConversionIntegrity":
        return validators.validate_adapter_conversion_integrity(corpus, "GoldAdapter", huge)
    raise ValueError("no validator wired for class %s" % cls)


def validate_candidate(candidate, corpus=None, coverage=None, safety_multiplier=10):
    """Fit the threshold to max_observed_benign * safety (never below the 1% floor), then confirm the
    corpus produces zero violations at that fitted threshold. This is the doc's step 5 -> validation
    loop: the differ proposes the class, the corpus sets the number."""
    from invariants import validators
    corpus = corpus if corpus is not None else load_corpus()
    coverage = coverage if coverage is not None else load_coverage()
    cls = candidate["class"]
    thr = candidate["threshold"]
    exploit_bps = thr.get("exploit_value_bps") or thr.get("exploit_deviation_bps")

    observed = _observe(cls, corpus)
    max_obs = observed["max_observed_bps"]
    import math
    fitted_bps = max(math.ceil(max_obs * safety_multiplier), _FLOOR_BPS)

    if cls == "ExchangeRateDeltaBound":
        res = validators.validate_exchange_rate_delta_bound(corpus, "GoldAdapter", fitted_bps)
    else:
        res = validators.validate_adapter_conversion_integrity(corpus, "GoldAdapter", fitted_bps)

    margin, margin_note = _margin(fitted_bps, max_obs)
    rejected = res["violations"] > 0
    warnings = list(coverage.get("coverage_warnings", []))
    if max_obs == 0:
        warnings.append("Threshold is a policy floor: this quantity never moves under benign "
                        "activity in the corpus, so the bound is a floor, not a statistical fit.")
    else:
        warnings.append("Benign max for this quantity is %.2f%% (dust-deposit rounding); threshold "
                        "fitted at %dx safety = %.2f%%." % (max_obs / 100.0, safety_multiplier, fitted_bps / 100.0))

    return {
        "invariant": candidate["name"],
        "class": cls,
        "params": candidate["params"],
        "corpus_size": len(corpus),
        "applicable_traces_checked": res["checked"],
        "violations_in_corpus": res["violations"],
        "max_observed_bps": max_obs,
        "max_observed_value": max_obs / 10000.0,
        "safety_multiplier": safety_multiplier,
        "threshold_bps": fitted_bps,
        "threshold": fitted_bps / 10000.0,
        "margin_ratio": margin,
        "margin_note": margin_note,
        "exploit_value_bps": exploit_bps,
        "exploit_over_threshold_x": (exploit_bps // fitted_bps) if (exploit_bps and fitted_bps) else None,
        "coverage_warnings": warnings,
        "validation_confidence": "REJECTED (too tight - flags benign activity)" if rejected
                                 else "HIGH within covered scenarios",
        "accepted": not rejected,
    }


def main():
    from agent import config
    from synthesis import differ, exploit_trace as et
    corpus = load_corpus()
    coverage = load_coverage()
    out = {}
    for name, fn in et.EXPLOIT_TRACES.items():
        cand = differ.compute_candidates(fn())
        rep = validate_candidate(cand["primary_candidate"], corpus, coverage)
        out[name] = rep
        print("=== %s -> %s ===" % (name, rep["invariant"]))
        print("  corpus=%d checked=%d violations=%d max_observed=%s%% threshold=%s%% margin=%s" % (
            rep["corpus_size"], rep["applicable_traces_checked"], rep["violations_in_corpus"],
            rep["max_observed_value"] * 100, rep["threshold"] * 100, rep["margin_ratio"]))
        print("  exploit was %s bps (%sx over threshold) | %s" % (
            rep["exploit_value_bps"], rep["exploit_over_threshold_x"], rep["validation_confidence"]))
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    (config.STATE_DIR / "validation.json").write_text(json.dumps(out, indent=2))
    print("\nvalidation -> orchestrator/state/validation.json")


if __name__ == "__main__":
    main()
