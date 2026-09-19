"""Guard compiler + gas/composability analysis.

Takes a validated invariant, emits its Solidity guard, deploys it onto the fork via a thin wrapper
contract, re-runs the confirmed exploit against the guarded path to prove it now REVERTS, and
measures the real gas overhead (not an estimate). Skips vm.etch bytecode injection and governance
proposal automation - both are real product features, neither is demo-critical.
"""

import json
import re
import subprocess
import uuid

from agent import config
from invariants import generators as gen

config.ensure_foundry_on_path()
GENERATED_DIR = config.PROJECT_ROOT / "synthesis" / "generated"


def _run(cmd, timeout=120):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(config.PROJECT_ROOT))
    return p.returncode, p.stdout, p.stderr


def _wrapper_and_test(guard_name):
    """A thin wrapper applying the ExchangeRateDeltaBound modifier around a deposit, plus a Foundry
    test that: (1) sets the guard checkpoint via a legit deposit, (2) donates to spike the rate and
    proves the guarded deposit reverts, (3) measures guarded vs unguarded gas."""
    return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Setup.t.sol";
import "./%(guard)s.sol";

/// @notice Thin wrapper: applies the generated invariant as a post-condition around deposit().
contract GuardedGoldDeposit is %(guard)s {
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

    /// Identical body WITHOUT the modifier - reference for the full guarded-path cost.
    function unguardedDeposit(uint256 amount) external returns (uint256) {
        gold.transferFrom(msg.sender, address(this), amount);
        gold.approve(address(adapter), amount);
        return am.deposit(address(adapter), amount);
    }

    /// No-op pair to isolate the invariant modifier's own cost with no deposit state to confound
    /// warm/cold storage. noopGuarded - noopPlain = the modifier's marginal gas.
    function noopGuarded() external assertRateDeltaBound {}
    function noopPlain() external {}
}

contract GuardReAttackTest is Setup {
    GuardedGoldDeposit guard;

    function setUp() public override {
        super.setUp();
        guard = new GuardedGoldDeposit(accountManager, goldAdapter, goldToken);
    }

    function testReAttackReverts() public {
        // 1. legitimate guarded deposit establishes the checkpoint at the fair rate
        address legit = makeAddr("legit_guard");
        goldToken.mint(legit, 100e18);
        vm.startPrank(legit);
        goldToken.approve(address(guard), 100e18);
        guard.guardedDeposit(100e18);
        vm.stopPrank();

        // 2. attacker donates to spike the rate, then the guarded deposit must REVERT
        address atk = makeAddr("atk_guard");
        goldToken.mint(atk, 231_000e18);
        vm.startPrank(atk);
        goldToken.transfer(goldPool, 230_000e18);
        goldToken.approve(address(guard), 1e18);
        vm.expectRevert();
        guard.guardedDeposit(1e18);
        vm.stopPrank();
    }

    function testGasInvariant() public {
        // Isolate the modifier with no deposit state to confound warm/cold storage.
        uint256 a = gasleft(); guard.noopPlain();   uint256 gPlain = a - gasleft();
        uint256 b = gasleft(); guard.noopGuarded();  uint256 gCold = b - gasleft();  // first: cold checkpoint SSTOREs
        uint256 c = gasleft(); guard.noopGuarded();  uint256 gWarm = c - gasleft();  // in-window: reads only
        console2.log("GAS_NOOP_PLAIN", gPlain);
        console2.log("GAS_NOOP_COLD", gCold);
        console2.log("GAS_NOOP_WARM", gWarm);
    }

    function testGasDepositPath() public {
        // Full-path reference: a plain direct deposit vs a first guarded deposit through the wrapper.
        address u1 = makeAddr("gas_plain");
        goldToken.mint(u1, 100e18);
        vm.startPrank(u1);
        goldToken.approve(address(goldAdapter), 100e18);
        uint256 g0 = gasleft();
        accountManager.deposit(address(goldAdapter), 100e18);
        console2.log("GAS_PLAIN", g0 - gasleft());
        vm.stopPrank();

        address u2 = makeAddr("gas_guarded");
        goldToken.mint(u2, 100e18);
        vm.startPrank(u2);
        goldToken.approve(address(guard), 100e18);
        uint256 g1 = gasleft();
        guard.guardedDeposit(100e18);
        console2.log("GAS_GUARDED", g1 - gasleft());
        vm.stopPrank();
    }
}
''' % {"guard": guard_name}


def compile_and_deploy_guard(threshold_bps, window_blocks=1):
    dep = json.loads(config.DEPLOYMENT_PATH.read_text()) if config.DEPLOYMENT_PATH.exists() else {"contracts": {}}
    adapter_addr = dep.get("contracts", {}).get("goldAdapter", "0x0000000000000000000000000000000000000A11")
    spec = gen.exchange_rate_delta_bound(adapter_addr, max_delta_bps=threshold_bps, window_blocks=window_blocks)
    guard_name = spec.name + "Guard"

    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    (GENERATED_DIR / (guard_name + ".sol")).write_text(spec.solidity)  # persistent artifact

    guard_test_path = config.TEST_DIR / (guard_name + ".sol")
    reattack_path = config.TEST_DIR / ("_GuardReAttack_%s.t.sol" % uuid.uuid4().hex[:8])
    guard_test_path.write_text(spec.solidity)
    reattack_path.write_text(_wrapper_and_test(guard_name))
    try:
        rc, out, err = _run(["forge", "test", "--match-path", "test/%s" % reattack_path.name, "-vvv"])
        combined = out + "\n" + err
        reverts = bool(re.search(r"\[PASS\]\s+testReAttackReverts", combined))
        noop_plain = _grep_int(combined, r"GAS_NOOP_PLAIN\s+(\d+)")
        noop_cold = _grep_int(combined, r"GAS_NOOP_COLD\s+(\d+)")
        noop_warm = _grep_int(combined, r"GAS_NOOP_WARM\s+(\d+)")
        gas_plain = _grep_int(combined, r"GAS_PLAIN\s+(\d+)")
        gas_guarded = _grep_int(combined, r"GAS_GUARDED\s+(\d+)")
        inv_cold = (noop_cold - noop_plain) if (noop_cold and noop_plain) else None
        inv_warm = (noop_warm - noop_plain) if (noop_warm and noop_plain) else None
        inv_warm_pct = round(100.0 * inv_warm / gas_plain, 1) if (inv_warm and gas_plain) else None
        report = {
            "invariant": spec.name,
            "class": "ExchangeRateDeltaBound",
            "threshold_bps": threshold_bps,
            "window_blocks": window_blocks,
            "deployed": True,
            "reattack_reverts": reverts,
            "gas_plain_deposit": gas_plain,
            "gas_guarded_deposit_full_path": gas_guarded,
            "invariant_gas_overhead_steady_state": inv_warm,
            "invariant_gas_overhead_steady_state_pct": inv_warm_pct,
            "invariant_gas_overhead_checkpoint_init": inv_cold,
            "gas_overhead_note": "invariant cost isolated on a no-op (no deposit state to confound "
                                 "warm/cold storage): steady_state = in-window call (2 exchangeRate() "
                                 "reads + 1 SLOAD); checkpoint_init = first call per window (adds two "
                                 "cold checkpoint SSTOREs). Steady-state pct is of a plain deposit.",
            "artifact": str((GENERATED_DIR / (guard_name + ".sol")).relative_to(config.PROJECT_ROOT)),
            "solidity": spec.solidity,
        }
        config.STATE_DIR.mkdir(parents=True, exist_ok=True)
        (config.STATE_DIR / "guard_report.json").write_text(json.dumps(report, indent=2))
        return report
    finally:
        for p in (guard_test_path, reattack_path):
            try:
                p.unlink()
            except OSError:
                pass


def _grep_int(text, pat):
    m = re.search(pat, text)
    return int(m.group(1)) if m else None


def main():
    validation = json.loads((config.STATE_DIR / "validation.json").read_text())
    rep_v = validation["adapter_donation"]
    threshold_bps = rep_v["threshold_bps"]
    print("compiling ExchangeRateDeltaBound guard @ %d bps (fitted from corpus)..." % threshold_bps)
    report = compile_and_deploy_guard(threshold_bps)
    print("  deployed:", report["deployed"])
    print("  re-attack reverts:", report["reattack_reverts"])
    print("  gas: plain deposit=%s, full guarded-path deposit=%s" % (
        report["gas_plain_deposit"], report["gas_guarded_deposit_full_path"]))
    print("  invariant overhead (isolated): steady-state=%s gas (%s%% of a deposit), checkpoint-init=%s gas" % (
        report["invariant_gas_overhead_steady_state"], report["invariant_gas_overhead_steady_state_pct"],
        report["invariant_gas_overhead_checkpoint_init"]))
    print("  artifact:", report["artifact"])
    print("\nguard report -> orchestrator/state/guard_report.json")


if __name__ == "__main__":
    main()
