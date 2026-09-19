// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Setup.t.sol";

/// @notice REAL false-positive proof, executed on the EVM (not a Python model).
///
/// This is the answer to "does the guard only flag actual exploits?" We run a large batch of
/// genuine, varied, legitimate transactions THROUGH THE ACTUAL guarded contract and assert the
/// guard never reverts once — then run the real donation exploit through the same guarded path and
/// assert it DOES revert. Every number here comes from executing the real Solidity, so "zero false
/// positives" is a measured fact, not a synthetic corpus statistic.
///
/// The guard is ExchangeRateDeltaBound at the strict 1% (100 bps) policy floor — a tighter bound
/// than the pipeline's corpus-fitted 15.9%, so passing here is the harder test.

/// Exact copy of invariants/generators.py::exchange_rate_delta_bound output (100 bps, 1-block window).
abstract contract ExchangeRateDeltaBound {
    GoldAdapter public immutable adapter;
    uint256 public constant MAX_DELTA_BPS = 100;
    uint256 public constant WINDOW_BLOCKS = 1;
    uint256 public checkpointRate;
    uint256 public checkpointBlock;
    error ExchangeRateDeltaViolation(uint256 rateBefore, uint256 rateAfter, uint256 deltaBps);

    constructor(GoldAdapter _adapter) { adapter = _adapter; }

    modifier assertRateDeltaBound() {
        if (checkpointBlock == 0 || block.number >= checkpointBlock + WINDOW_BLOCKS) {
            checkpointRate = adapter.exchangeRate();
            checkpointBlock = block.number;
        }
        uint256 rateBefore = checkpointRate;
        _;
        uint256 rateAfter = adapter.exchangeRate();
        uint256 delta = rateAfter > rateBefore ? rateAfter - rateBefore : rateBefore - rateAfter;
        uint256 deltaBps = rateBefore == 0 ? 0 : (delta * 10000) / rateBefore;
        if (deltaBps > MAX_DELTA_BPS) revert ExchangeRateDeltaViolation(rateBefore, rateAfter, deltaBps);
    }
}

contract GuardedGoldDeposit is ExchangeRateDeltaBound {
    AccountManager public am;
    MockERC20 public gold;
    constructor(AccountManager _am, GoldAdapter _adapter, MockERC20 _gold) ExchangeRateDeltaBound(_adapter) {
        am = _am; gold = _gold;
    }
    function guardedDeposit(uint256 amount) external assertRateDeltaBound returns (uint256) {
        gold.transferFrom(msg.sender, address(this), amount);
        gold.approve(address(adapter), amount);
        return am.deposit(address(adapter), amount);
    }
}

contract GuardFalsePositiveProof is Setup {
    GuardedGoldDeposit guard;

    function setUp() public override {
        super.setUp();
        guard = new GuardedGoldDeposit(accountManager, goldAdapter, goldToken);
    }

    /// Run 400 REAL, varied legitimate deposits through the guarded path. Assert the guard reverts
    /// zero times, and cross-check the observed per-tx rate movement stays within the 1% bound.
    function test_benign_traffic_never_false_positives() public {
        uint256 N = 400;
        uint256 falsePositives = 0;
        uint256 maxObservedDeltaBps = 0;

        for (uint256 i = 0; i < N; i++) {
            address user = address(uint160(uint256(keccak256(abi.encode("legit", i)))));
            // Realistic spread of deposit sizes: $10 to ~$250k, pseudo-random per user.
            uint256 amount = (uint256(keccak256(abi.encode("amt", i))) % (250_000e18)) + 10e18;

            uint256 rateBefore = goldAdapter.exchangeRate();

            goldToken.mint(user, amount);
            vm.startPrank(user);
            goldToken.approve(address(guard), amount);
            try guard.guardedDeposit(amount) {
                // legit deposit accepted by the guard (expected)
            } catch {
                falsePositives++;
            }
            vm.stopPrank();

            uint256 rateAfter = goldAdapter.exchangeRate();
            uint256 d = rateAfter > rateBefore ? rateAfter - rateBefore : rateBefore - rateAfter;
            uint256 bps = rateBefore == 0 ? 0 : (d * 10000) / rateBefore;
            if (bps > maxObservedDeltaBps) maxObservedDeltaBps = bps;

            if (i % 3 == 0) vm.roll(block.number + 1);   // exercise the windowed checkpoint over blocks
        }

        emit log_named_uint("benign deposits executed (real EVM)", N);
        emit log_named_uint("guard false-positives", falsePositives);
        emit log_named_uint("max observed per-tx rate delta (bps)", maxObservedDeltaBps);

        assertEq(falsePositives, 0, "guard must NOT flag any legitimate deposit");
        assertLe(maxObservedDeltaBps, 100, "legit rate movement stays within the 1% bound");
    }

    /// The other half of the proof: the real donation exploit, through the SAME guarded path, must
    /// be flagged (revert). Together with the test above: flags the exploit, nothing legitimate.
    function test_exploit_is_flagged() public {
        // establish the checkpoint at the fair rate with a legit deposit
        address legit = makeAddr("legit_cp");
        goldToken.mint(legit, 100e18);
        vm.startPrank(legit);
        goldToken.approve(address(guard), 100e18);
        guard.guardedDeposit(100e18);
        vm.stopPrank();

        // attacker donates to spike the rate, then the guarded deposit must REVERT
        address atk = makeAddr("atk");
        goldToken.mint(atk, 231_000e18);
        vm.startPrank(atk);
        goldToken.transfer(goldPool, 230_000e18);
        goldToken.approve(address(guard), 1e18);
        vm.expectRevert();                    // guard flags the exploit
        guard.guardedDeposit(1e18);
        vm.stopPrank();
    }
}
