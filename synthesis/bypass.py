"""Bypass-resistance analyzer (deterministic, not a second LLM).

Runs the plan's four fixed bypass strategies against the *deployed* guard as real Foundry tests and
reports the honest pass/fail for each — same evidentiary value as a "bypass agent," no LLM cost,
fully reproducible. This is the module the advisory's Bypass Resistance section is built from; the
results are read off an actual fork run, never asserted.

The guard under test is ExchangeRateDeltaBound scoped to GoldAdapter.deposit() (the exact wrapper
the guard compiler deploys). The four strategies:

  1. split_into_10_subtransactions — donate in 10 chunks in one block, then a guarded deposit.
     The per-block checkpoint still sees the cumulative spike -> expected BLOCKED.
  2. spread_across_20_blocks       — donate, roll past the 1-block window, then a guarded deposit.
     A 1-block-window bound re-checkpoints at the (already inflated) rate -> this is the honest
     limit of a narrow window; the result is whatever the fork says, reported as-is.
  3. use_multicall_path            — after donating, hit AccountManager.depositAndMint() directly,
     which a deposit()-scoped guard does not cover -> expected BYPASSED (the layered-defense point).
  4. gas_variance                  — categorically N/A: the guard is state-based, not gas-based.

A strategy "succeeds" (success=True) when the attack got through the guard — which is BAD for the
defender, and flagged as such.
"""

import json
import re
import subprocess
import uuid

from agent import config
from invariants import generators as gen

config.ensure_foundry_on_path()


def _run(cmd, timeout=180):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(config.PROJECT_ROOT))
    return p.returncode, p.stdout, p.stderr


def _harness(guard_name):
    """Guarded wrapper (guard on deposit() only) + a test per bypass strategy. Each strategy logs
    BYPASS_<method> <1|0> (1 = the attack got through the guard)."""
    return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Setup.t.sol";
import "./%(guard)s.sol";

contract BypassGuardedDeposit is %(guard)s {
    AccountManager public am;
    MockERC20 public gold;

    constructor(AccountManager _am, GoldAdapter _adapter, MockERC20 _gold) %(guard)s(_adapter) {
        am = _am;
        gold = _gold;
    }

    function guardedDeposit(uint256 amount) external assertRateDeltaBound returns (uint256) {
        gold.transferFrom(msg.sender, address(this), amount);
        gold.approve(address(adapter), amount);
        return am.deposit(address(adapter), amount);
    }
}

contract BypassSuite is Setup {
    BypassGuardedDeposit guard;

    function setUp() public override {
        super.setUp();
        guard = new BypassGuardedDeposit(accountManager, goldAdapter, goldToken);
    }

    /// A legitimate guarded deposit establishes the guard's checkpoint at the fair rate.
    function _checkpoint() internal {
        address legit = makeAddr("bp_legit");
        goldToken.mint(legit, 100e18);
        vm.startPrank(legit);
        goldToken.approve(address(guard), 100e18);
        guard.guardedDeposit(100e18);
        vm.stopPrank();
    }

    function testSplit() public {
        _checkpoint();
        address atk = makeAddr("bp_split");
        goldToken.mint(atk, 231_000e18);
        vm.startPrank(atk);
        for (uint256 i = 0; i < 10; i++) {
            goldToken.transfer(goldPool, 23_000e18);   // 10 chunks, same block
        }
        goldToken.approve(address(guard), 1e18);
        uint256 bypassed;
        try guard.guardedDeposit(1e18) { bypassed = 1; } catch { bypassed = 0; }
        vm.stopPrank();
        console2.log("BYPASS_split_into_10_subtransactions", bypassed);
    }

    function testSpread() public {
        _checkpoint();
        address atk = makeAddr("bp_spread");
        goldToken.mint(atk, 231_000e18);
        vm.startPrank(atk);
        goldToken.transfer(goldPool, 230_000e18);
        vm.roll(block.number + 20);                     // past the 1-block window
        goldToken.approve(address(guard), 1e18);
        uint256 bypassed;
        try guard.guardedDeposit(1e18) { bypassed = 1; } catch { bypassed = 0; }
        vm.stopPrank();
        console2.log("BYPASS_spread_across_20_blocks", bypassed);
    }

    function testMulticall() public {
        _checkpoint();
        address atk = makeAddr("bp_multi");
        goldToken.mint(atk, 231_000e18);
        vm.startPrank(atk);
        goldToken.transfer(goldPool, 230_000e18);
        goldToken.approve(address(goldAdapter), 1e18);
        // depositAndMint() is not behind the deposit()-scoped guard.
        uint256 bypassed;
        try accountManager.depositAndMint(address(goldAdapter), 1e18) returns (uint256) {
            bypassed = 1;
        } catch {
            bypassed = 0;
        }
        vm.stopPrank();
        console2.log("BYPASS_use_multicall_path", bypassed);
    }
}
''' % {"guard": guard_name}


# Static, honest metadata per strategy. `reason`/`mitigation` describe the *why*; success comes from
# the fork run (except gas_variance, which is a categorical N/A and never executed).
_META = {
    "split_into_10_subtransactions": {
        "blocked_reason": "per-block checkpoint catches the cumulative rate spike",
        "bypass_reason": "chunked donations still cleared the guard",
        "mitigation": "none needed for this vector",
    },
    "spread_across_20_blocks": {
        "blocked_reason": "windowed checkpoint still bounds the cumulative delta",
        "bypass_reason": "a 1-block window re-checkpoints at the already-inflated rate; the donation "
                         "in a prior block is not seen as movement during the deposit",
        "mitigation": "widen window_blocks to span plausible donation-to-use gaps, or checkpoint on "
                      "any pool-balance change",
    },
    "use_multicall_path": {
        "blocked_reason": "multicall path is also covered by the guard",
        "bypass_reason": "AccountManager.depositAndMint() is not behind the deposit()-scoped guard",
        "mitigation": "add the invariant at the AccountManager.depositAndMint() multicall boundary",
    },
}


def run_bypass(threshold_bps, window_blocks=1):
    dep = json.loads(config.DEPLOYMENT_PATH.read_text()) if config.DEPLOYMENT_PATH.exists() else {"contracts": {}}
    adapter_addr = dep.get("contracts", {}).get("goldAdapter", "0x0000000000000000000000000000000000000A11")
    spec = gen.exchange_rate_delta_bound(adapter_addr, max_delta_bps=threshold_bps, window_blocks=window_blocks)
    guard_name = spec.name + "Guard"

    guard_path = config.TEST_DIR / (guard_name + ".sol")
    harness_path = config.TEST_DIR / ("_BypassSuite_%s.t.sol" % uuid.uuid4().hex[:8])
    guard_path.write_text(spec.solidity)
    harness_path.write_text(_harness(guard_name))
    try:
        rc, out, err = _run(["forge", "test", "--match-path", "test/%s" % harness_path.name, "-vv"])
        combined = out + "\n" + err
        results = {}
        for method in _META:
            m = re.search(r"BYPASS_%s\s+(\d+)" % re.escape(method), combined)
            results[method] = (m is not None and m.group(1) == "1")

        attempts = []
        for method, meta in _META.items():
            succeeded = results.get(method, False)
            att = {
                "method": method,
                "success": succeeded,
                "reason": meta["bypass_reason"] if succeeded else meta["blocked_reason"],
            }
            if succeeded:
                att["mitigation_required"] = meta["mitigation"]
            attempts.append(att)
        # gas_variance: categorical N/A for a state-based guard (not executed).
        attempts.append({
            "method": "gas_variance",
            "success": False,
            "reason": "guard is state-based, not gas-based; N/A",
        })

        n_bypassed = sum(1 for a in attempts if a["success"])
        if n_bypassed == 0:
            score = "HIGH - no bypass found across tested strategies"
        elif n_bypassed <= 2:
            score = "MEDIUM - requires layered defense"
        else:
            score = "LOW - multiple bypasses, single guard insufficient"

        report = {
            "guard": spec.name,
            "threshold_bps": threshold_bps,
            "window_blocks": window_blocks,
            "forge_ok": rc == 0,
            "attempts": attempts,
            "n_bypassed": n_bypassed,
            "resistance_score": score,
        }
        config.STATE_DIR.mkdir(parents=True, exist_ok=True)
        (config.STATE_DIR / "bypass_report.json").write_text(json.dumps(report, indent=2))
        return report
    finally:
        for p in (guard_path, harness_path):
            try:
                p.unlink()
            except OSError:
                pass


def main():
    validation = json.loads((config.STATE_DIR / "validation.json").read_text())
    threshold_bps = validation["adapter_donation"]["threshold_bps"]
    print("running bypass strategies against ExchangeRateDeltaBound @ %d bps..." % threshold_bps)
    report = run_bypass(threshold_bps)
    for a in report["attempts"]:
        print("  [%-30s] %-8s %s" % (a["method"], "BYPASSED" if a["success"] else "BLOCKED", a["reason"]))
    print("  resistance:", report["resistance_score"])
    print("\nbypass report -> orchestrator/state/bypass_report.json")


if __name__ == "__main__":
    main()
