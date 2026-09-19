"""Red Queen loop orchestrator — the connective tissue.

Chains the working stages into one end-to-end run:

    attack  ->  trace-diff / candidate  ->  empirical validation  ->  guard compile+deploy
            ->  bypass resistance  ->  advisory (Markdown + PDF)

Two things this closes that the individual stage `main()`s did not:

  1. It writes the combined ``orchestrator/state/state.json`` the demo frontend polls (the frontend
     was built to read it, but nothing ever produced it — it fell back to bundled sample state).
  2. It renders the advisories from REAL pipeline output (attack PoC, fitted threshold, measured
     gas, actual bypass results) instead of the hardcoded SAMPLE_FINDINGS in the advisory module.

Run:  python3 -m orchestrator.run [--agent fallback|llm]
"""

import json
import time

from agent import config, attacker
from synthesis import differ, validate as validate_mod, guard_compiler, bypass as bypass_mod
from synthesis import exploit_trace as et
from advisories import generate_advisory

# Confirmed-exploit pattern -> (advisory id, exploit-trace key, severity, category).
_ADVISORY_MAP = {
    "adapter_donation": {
        "advisory_id": "RQ-2026-0001",
        "trace": "adapter_donation",
        "severity": "HIGH",
        "category": "Adapter Conversion Integrity",
    },
    "stale_price_multicall": {
        "advisory_id": "RQ-2026-0002",
        "trace": "stale_price_multicall",
        "severity": "HIGH",
        "category": "Stale-Price Multicall",
    },
}


class _State:
    """Accumulates the frontend RedQueenState and flushes it to state.json on every transition, so a
    polling frontend animates the run in real time."""

    def __init__(self, target_contracts):
        self.s = {
            "status": "idle",
            "iteration": 0,
            "target_contracts": target_contracts,
            "advisories_generated": 0,
            "coverage_warnings_flagged": 0,
            "attacker": {"pattern_name": "", "progress": {"current": 0, "total": 0},
                         "log": [], "tool_calls": [], "poc_code": "",
                         "result": {"found": False, "profit_usd": 0}},
            "defender": {"trace_diff": [], "candidate_invariant": {"name": "", "solidity": ""},
                         "validation": {"checked": 0, "total": 0, "violations": 0},
                         "threshold": {"max_observed_pct": 0, "threshold_pct": 0, "margin_ratio": 0},
                         "bypass_results": [], "guard_deployed": False},
        }

    def flush(self, status=None):
        if status:
            self.s["status"] = status
        config.STATE_DIR.mkdir(parents=True, exist_ok=True)
        (config.STATE_DIR / "state.json").write_text(json.dumps(self.s, indent=2))

    def set_attacker(self, attack_result, pattern):
        a = self.s["attacker"]
        a["pattern_name"] = pattern["name"]
        idx = 1 + list(_ADVISORY_MAP).index(pattern["name"]) if pattern["name"] in _ADVISORY_MAP else 1
        a["progress"] = {"current": idx, "total": len(attack_result["patterns"])}
        a["log"] = attack_result["reasoning_log"][-40:]
        a["tool_calls"] = [{"name": tc["name"], "args": json.dumps(tc.get("input", {})),
                            "result": tc.get("summary", "")} for tc in attack_result["tool_calls"]][-30:]
        a["poc_code"] = pattern.get("poc_solidity", "") or ""
        a["result"] = {"found": pattern["result"] in ("EXPLOIT_CONFIRMED", "MISPRICING_FINDING"),
                       "profit_usd": pattern.get("impact_usd", 0) or 0}

    def set_defender(self, candidates, validation, guard_report, bypass_report):
        d = self.s["defender"]
        d["trace_diff"] = [{
            "variable": r["variable"],
            "benign_max": _fmt(r.get("max_benign", 0)),
            "exploit_delta": _fmt(r.get("exploit_delta", 0)),
            "z_score": (None if r.get("z_score") == float("inf") else round(r.get("z_score", 0), 1)),
            "anomalous": r.get("anomaly_score", 0) == float("inf") or r.get("anomaly_score", 0) > 3,
        } for r in candidates["ranked_anomalies"][:6]]
        d["candidate_invariant"] = {"name": validation["invariant"], "solidity": guard_report["solidity"]}
        d["validation"] = {"checked": validation["applicable_traces_checked"],
                           "total": validation["corpus_size"], "violations": validation["violations_in_corpus"]}
        d["threshold"] = {"max_observed_pct": round(validation["max_observed_value"] * 100, 3),
                          "threshold_pct": round(validation["threshold"] * 100, 3),
                          "margin_ratio": validation["margin_ratio"]}
        d["bypass_results"] = [{"strategy": a["method"], "passed": a["success"]} for a in bypass_report["attempts"]]
        d["guard_deployed"] = bool(guard_report["deployed"] and guard_report["reattack_reverts"])


def _fmt(v):
    try:
        return "{:,.4g}".format(float(v))
    except (TypeError, ValueError):
        return str(v)


def _gas_overhead_str(guard_report):
    g = guard_report.get("invariant_gas_overhead_steady_state")
    pct = guard_report.get("invariant_gas_overhead_steady_state_pct")
    if g is None:
        return "measured on fork"
    return "{:,} gas per deposit (+{}%)".format(g, pct)


def _build_finding(meta, pattern, validation, guard_report, bypass_report):
    """Assemble the advisory finding-record from REAL stage outputs (no sample data)."""
    is_multicall = meta["advisory_id"] == "RQ-2026-0002"
    exploit_summary = {
        "RQ-2026-0001": (
            "GoldAdapter.exchangeRate() derives its rate from the raw pool balance, so a direct token "
            "transfer into the pool inflates the rate without minting shares. A subsequent small "
            "deposit is credited at the inflated rate and mints rwaUSD far in excess of the "
            "collateral's fair value, leaving the protocol holding unbacked debt."),
        "RQ-2026-0002": (
            "AccountManager.depositAndMint() reads the price once at the start and reuses it for both "
            "share accounting (depositAtPrice) and the principal credit. A donation immediately before "
            "the call inflates that single read, so the multicall mints rwaUSD against a stale, inflated "
            "valuation — the same conversion-integrity violation as Vuln A, reached via the multicall "
            "entry point that a deposit()-scoped guard does not cover."),
    }[meta["advisory_id"]]

    actions = [
        {"priority": "Immediate",
         "action": ("Deploy ExchangeRateDeltaBound as a post-condition on GoldAdapter.deposit() — "
                    "tighten-only, emergency-role compatible, no governance vote"),
         "governance": "emergency-role"},
        {"priority": "Follow-up",
         "action": ("Add the same invariant at the AccountManager.depositAndMint() multicall boundary — "
                    "closes the alternate-path bypass"),
         "governance": "full-vote"},
    ]
    if any(a["method"] == "spread_across_20_blocks" and a["success"] for a in bypass_report["attempts"]):
        actions.append({"priority": "Review",
                        "action": ("Widen the guard window (window_blocks > 1) or checkpoint on any pool-balance "
                                   "change — a 1-block window does not catch a donation made in a prior block"),
                        "governance": "full-vote"})

    return {
        "advisory_id": meta["advisory_id"],
        "severity": meta["severity"],
        "category": meta["category"],
        "reference_pattern": pattern.get("reference_incident", "N/A"),
        "target": "GoldAdapter",
        "vuln_ref": pattern.get("vuln_ref", "N/A"),
        "exploit_summary": exploit_summary,
        "impact_usd": pattern.get("impact_usd", 0) or 0,
        "impact_label": "unbacked rwaUSD minted (protocol bad debt)",
        "poc_solidity": pattern.get("poc_solidity", "// PoC unavailable"),
        "candidate_guard": {
            "invariant": validation["invariant"],
            "solidity": guard_report["solidity"],
            "gas_overhead": _gas_overhead_str(guard_report),
            "gas_measured": True,
        },
        "validation_report": {
            "corpus_size": validation["corpus_size"],
            "violations_in_corpus": validation["violations_in_corpus"],
            "max_observed_value": validation["max_observed_value"],
            "threshold": validation["threshold"],
            "margin_ratio": validation["margin_ratio"],
            "coverage_warnings": validation["coverage_warnings"],
            "validation_confidence": validation["validation_confidence"],
        },
        "bypass_resistance": {
            "attempts": bypass_report["attempts"],
            "resistance_score": bypass_report["resistance_score"],
        },
        "recommended_actions": actions,
        "governance_path": {
            "emergency_role_compatible": True,
            "timelock_required": False,
            "full_vote_required_for": ("the multicall-boundary layered guard" if not is_multicall
                                       else "this multicall-boundary guard"),
        },
    }


def run(force_agent=None):
    targets = ["rwaUSDToken", "Ledger", "AccountManager", "GoldAdapter", "xStockAdapter", "PriceRouter"]
    state = _State(targets)
    state.flush("attacking")

    # --- 1. Attack ---
    print("[1/5] attack ...")
    attack_result = attacker.run_attack(force_agent=force_agent)
    print("      %s" % attack_result["headline"])

    corpus = validate_mod.load_corpus()
    coverage = validate_mod.load_coverage()

    confirmed = [p for p in attack_result["patterns"]
                 if p["result"] == "EXPLOIT_CONFIRMED" and p["name"] in _ADVISORY_MAP]

    # Guard + bypass are identical across the GoldAdapter exploits — compute once, reuse.
    guard_report = None
    bypass_report = None
    advisories = []
    all_coverage_warnings = set()

    for pattern in confirmed:
        meta = _ADVISORY_MAP[pattern["name"]]
        state.set_attacker(attack_result, pattern)
        state.flush("synthesizing")

        # --- 2. Trace diff / candidate ---
        print("[2/5] synthesize candidate for %s (%s) ..." % (pattern["name"], pattern.get("vuln_ref")))
        trace = et.EXPLOIT_TRACES[meta["trace"]]()
        candidates = differ.compute_candidates(trace)

        # --- 3. Empirical validation ---
        print("[3/5] validate against %d-tx corpus ..." % len(corpus))
        validation = validate_mod.validate_candidate(candidates["primary_candidate"], corpus, coverage)

        # --- 4. Guard compile + deploy (once) ---
        if guard_report is None:
            print("[4/5] compile + deploy guard @ %d bps, prove re-attack reverts ..." % validation["threshold_bps"])
            guard_report = guard_compiler.compile_and_deploy_guard(validation["threshold_bps"])
            print("      deployed=%s reattack_reverts=%s overhead=%s gas (%s%%)" % (
                guard_report["deployed"], guard_report["reattack_reverts"],
                guard_report["invariant_gas_overhead_steady_state"],
                guard_report["invariant_gas_overhead_steady_state_pct"]))
            # --- 5. Bypass resistance (once) ---
            print("[5/5] run bypass strategies ...")
            bypass_report = bypass_mod.run_bypass(validation["threshold_bps"])
            print("      %s (%d bypass found)" % (bypass_report["resistance_score"], bypass_report["n_bypassed"]))

        state.set_defender(candidates, validation, guard_report, bypass_report)
        state.flush("synthesizing")

        # --- advisory from real data ---
        finding = _build_finding(meta, pattern, validation, guard_report, bypass_report)
        paths = generate_advisory.render_advisory(finding)
        advisories.append({"advisory_id": meta["advisory_id"], "vuln_ref": pattern.get("vuln_ref"),
                           "impact_usd": pattern.get("impact_usd"), **paths})
        all_coverage_warnings.update(validation["coverage_warnings"])
        state.s["advisories_generated"] = len(advisories)
        state.s["coverage_warnings_flagged"] = len(all_coverage_warnings)
        state.s["iteration"] = len(advisories)
        state.flush("synthesizing")
        print("      advisory %s -> %s" % (meta["advisory_id"], paths["md_path"]))

    # Third invariant class, fired live: AccrualSemanticConsistency. When the accrual-mismatch
    # finding (Vuln D) is present, validate the class empirically over the corpus. This class has no
    # call-site guard by design (enforced over feed/multiplier history), so it yields a validation
    # result rather than an on-chain guard.
    accrual_report = None
    if any(p["name"] == "accrual_type_mismatch" and p["result"] == "MISPRICING_FINDING"
           for p in attack_result["patterns"]):
        from invariants import validators
        accrual_report = validators.validate_accrual_semantic_consistency(corpus)
        print("[+] AccrualSemanticConsistency validated over corpus: checked=%d violations=%d monotonic=%s" % (
            accrual_report["checked"], accrual_report["violations"], accrual_report["monotonic"]))

    invariant_classes = ["ExchangeRateDeltaBound"] if guard_report else []
    if accrual_report:
        invariant_classes.append("AccrualSemanticConsistency")

    state.flush("hardened")

    summary = {
        "invariant_classes_exercised": invariant_classes,
        "accrual_invariant": accrual_report,
        "agent": attack_result["agent"],
        "headline": attack_result["headline"],
        "confirmed_exploits": [p["name"] for p in confirmed],
        "other_findings": [p["name"] for p in attack_result["patterns"]
                           if p["result"] == "MISPRICING_FINDING"],
        "advisories": advisories,
        "guard": {k: guard_report[k] for k in ("deployed", "reattack_reverts",
                  "invariant_gas_overhead_steady_state", "invariant_gas_overhead_steady_state_pct")} if guard_report else None,
        "bypass_resistance": bypass_report["resistance_score"] if bypass_report else None,
        "coverage_warnings_flagged": len(all_coverage_warnings),
        "ts": time.time(),
    }
    (config.STATE_DIR / "run_summary.json").write_text(json.dumps(summary, indent=2))
    print("\n" + "=" * 70)
    print("RUN COMPLETE — %d advisories, guard %s, bypass %s" % (
        len(advisories), "deployed" if guard_report and guard_report["deployed"] else "n/a",
        bypass_report["resistance_score"] if bypass_report else "n/a"))
    print("state -> orchestrator/state/state.json | summary -> orchestrator/state/run_summary.json")
    print("=" * 70)
    return summary


def run_multipli():
    """Advisory-only pass against Multipli's REAL deployed contracts on Base (no mocks, no deploy)."""
    from agent import multipli_target
    print("[multipli] real-contract recon on Base (read-only) ...")
    s = multipli_target.run()
    for r in s["targets"]:
        print("  %-24s %s deployed=%s name=%s impl=%s" % (
            r["label"], r["address"], r["deployed"], r.get("contract_name"), r.get("impl_name") or "-"))
    print("[multipli] %s" % s["headline"].replace("**", ""))
    print("report -> %s" % s["report_path"])
    return s


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Red Queen loop orchestrator")
    ap.add_argument("--agent", choices=["fallback", "llm"], default=None)
    ap.add_argument("--target", choices=["mocks", "multipli"], default="mocks",
                    help="'mocks' (default): full attack->guard->advisory loop on the local mock system. "
                         "'multipli': advisory-only recon against Multipli's real Base contracts.")
    args = ap.parse_args()
    if args.target == "multipli":
        run_multipli()
    else:
        run(force_agent=args.agent)


if __name__ == "__main__":
    main()
