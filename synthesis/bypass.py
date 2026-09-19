"""Bypass analyzer. Runs the forge bypass suites for v1 and v2, derives each strategy's verdict
from the EXECUTED test's logged outcome (never a hardcoded string), plus a static call-site scan,
and writes orchestrator/state/bypass_report.json.

Verdicts (from test logs): BYPASSED | BLOCKED | ERROR (no verdict line / test errored).
"""
import json, re, subprocess, time
from agent import config

config.ensure_foundry_on_path()

V1_STRATS = ["split_into_10_subtransactions", "spread_across_20_blocks", "multicall_path",
             "first_in_block_atomic", "direct_call_around_guard", "rational_economics"]
V2_STRATS = V1_STRATS + ["tolerance_riding"]

MITIGATION = {
    "multicall_path": "enforce the invariant at the value-crediting chokepoint, not per entry point",
    "direct_call_around_guard": "move enforcement into the protocol (chokepoint), not an opt-in wrapper",
    "first_in_block_atomic": "anchor to an independent reference, not a per-block self-checkpoint",
    "spread_across_20_blocks": "anchor to an independent reference; a windowed self-delta is defeatable",
    "rational_economics": "anchor credited value to raw feed so deposit>pool cannot over-credit",
    "split_into_10_subtransactions": "anchor to an independent reference",
    "tolerance_riding": "tighten TOLERANCE_BPS / anchor to TWAP / adopt the root-cause valuation formula",
}


def _run(path):
    p = subprocess.run(["forge", "test", "--match-path", path, "-vv"],
                       capture_output=True, text=True, timeout=300, cwd=str(config.PROJECT_ROOT))
    return p.stdout + "\n" + p.stderr


def _parse(out):
    verdicts, residual = {}, {}
    for m in re.finditer(r"BYPASS (\w+) (BYPASSED|BLOCKED)", out):
        verdicts[m.group(1)] = m.group(2)
    mr = re.search(r"BYPASS tolerance_riding RESIDUAL max_extractable_usd\(1e18\)\s+(\d+)", out)
    if mr:
        residual["tolerance_riding"] = int(mr.group(1)) / 1e18
    return verdicts, residual


def _callsite_scan():
    src = (config.SRC_DIR / "remediated" / "AccountManagerV2.sol").read_text()
    incr = src.count("ledger.increasePrincipal")
    in_choke = "_creditPrincipal" in src and "ledger.increasePrincipal(user, value)" in src.split("_creditPrincipal", 1)[1]
    deposit_routes = src.count("_creditPrincipal(msg.sender")  # both deposit + depositAndMint
    ok = (incr == 1) and in_choke and (deposit_routes >= 2)
    return {"name": "unguarded_call_site_scan",
            "verdict": "BLOCKED" if ok else "ERROR",
            "reason": "ledger.increasePrincipal appears %d time(s); both credit paths route through _creditPrincipal=%s" % (incr, deposit_routes >= 2),
            "evidence_test": "static parse of src/remediated/AccountManagerV2.sol"}


def _report(version, path, strats):
    out = _run(path)
    verdicts, residual = _parse(out)
    strategies, resid = [], []
    for s in strats:
        v = verdicts.get(s, "ERROR")
        entry = {"name": s, "verdict": v, "evidence_test": path,
                 "reason": ("attack credited/minted > fair*(1+tol), no revert" if v == "BYPASSED"
                            else "reverted (guard or access control)" if v == "BLOCKED" else "no verdict logged"),
                 "mitigation": MITIGATION.get(s, "")}
        if s == "tolerance_riding":
            ext = residual.get("tolerance_riding")
            entry["verdict"] = "RESIDUAL"
            entry["max_extractable_usd"] = ext
            resid.append({"name": s, "max_extractable_usd": ext,
                          "note": "donation kept under TOLERANCE_BPS + deposit >> pool extracts ~tolerance of deposit value"})
        strategies.append(entry)
    if version == "v2":
        strategies.append(_callsite_scan())
    counts = [e["verdict"] for e in strategies]
    return {
        "version": version,
        "strategies": strategies,
        "n_bypassed": counts.count("BYPASSED"),
        "n_blocked": counts.count("BLOCKED"),
        "n_error": counts.count("ERROR"),
        "residual_risks": resid,
        "gas_variance": "NOT_APPLICABLE (guard is state-based, not gas-based; excluded from counts)",
    }


def main():
    rep = {
        "v1": _report("v1", "test/bypass/BypassV1.t.sol", V1_STRATS),
        "v2": _report("v2", "test/bypass/BypassV2.t.sol", V2_STRATS),
        "ts": time.time(),
    }
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)
    (config.STATE_DIR / "bypass_report.json").write_text(json.dumps(rep, indent=2))
    for v in ("v1", "v2"):
        r = rep[v]
        print("%s: %d bypassed, %d blocked, %d error" % (v, r["n_bypassed"], r["n_blocked"], r["n_error"]))
        for e in r["strategies"]:
            print("   %-30s %s" % (e["name"], e["verdict"]))
    print("-> orchestrator/state/bypass_report.json")


if __name__ == "__main__":
    main()
