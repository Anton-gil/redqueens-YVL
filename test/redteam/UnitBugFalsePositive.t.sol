// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../SetupV2.t.sol";

/// @notice Regression for red-team finding #7 (now FIXED).
/// ORIGINAL BREAK: AccountManagerV2.depositAndMint forwarded pd.price (USD-per-SHARE, ~2000e18)
/// into GoldAdapter.depositAtPrice as if it were the collateral-units-per-share `rate` (~1e18),
/// minting ~2000x too FEW shares. That corrupted exchangeRate = poolBalance/totalShares, and the
/// anchored guard then reverted the NEXT benign deposit -> "benign deposits pass" was false.
/// FIX (lead): depositAndMint now routes share accounting through IAdapter.deposit() (re-derives the
/// rate correctly); the vulnerable VALUATION is unchanged so the guard still blocks donation.
/// These tests now assert the FIXED behavior.
contract UnitBugFalsePositive is SetupV2 {
    function test7_DepositAndMintMintsCorrectShares() public {
        address v = makeAddr("plain_shares");
        goldToken.mint(v, 1000e18);
        vm.startPrank(v);
        goldToken.approve(address(goldAdapter), 1000e18);
        accountManager.deposit(address(goldAdapter), 1000e18);
        vm.stopPrank();
        uint256 lockedViaPlain = ledger.lockedShares(v, address(goldAdapter));

        address u = makeAddr("dm_shares");
        goldToken.mint(u, 1000e18);
        vm.startPrank(u);
        goldToken.approve(address(goldAdapter), 1000e18);
        accountManager.depositAndMint(address(goldAdapter), 1000e18);
        vm.stopPrank();
        uint256 lockedViaDAM = ledger.lockedShares(u, address(goldAdapter));

        // FIXED: depositAndMint now locks the same shares as a plain deposit for the same collateral.
        assertApproxEqRel(lockedViaDAM, lockedViaPlain, 0.01e18, "depositAndMint must mint correct shares");
    }

    function test7_BenignDepositsAllPass() public {
        address alice = makeAddr("alice_benign");
        goldToken.mint(alice, 1000e18);
        vm.startPrank(alice);
        goldToken.approve(address(goldAdapter), 1000e18);
        uint256 minted = accountManager.depositAndMint(address(goldAdapter), 1000e18);
        vm.stopPrank();
        assertGt(minted, 0, "alice's benign depositAndMint passes");

        // FIXED: rate is NOT corrupted; stays ~1e18.
        assertApproxEqRel(goldAdapter.exchangeRate(), 1e18, 0.01e18, "rate must stay ~1.0 after depositAndMint");

        // FIXED: a subsequent benign plain deposit passes (no false positive).
        address bob = makeAddr("bob_benign");
        goldToken.mint(bob, 500e18);
        vm.startPrank(bob);
        goldToken.approve(address(goldAdapter), 500e18);
        accountManager.deposit(address(goldAdapter), 500e18);
        vm.stopPrank();
        assertGt(ledger.principal(bob), 0, "benign deposit after depositAndMint must pass");
    }

    function test7_SecondBenignDepositAndMintPasses() public {
        address alice = makeAddr("a_dam1");
        goldToken.mint(alice, 1000e18);
        vm.startPrank(alice);
        goldToken.approve(address(goldAdapter), 1000e18);
        accountManager.depositAndMint(address(goldAdapter), 1000e18);
        vm.stopPrank();

        address carol = makeAddr("c_dam2");
        goldToken.mint(carol, 1000e18);
        vm.startPrank(carol);
        goldToken.approve(address(goldAdapter), 1000e18);
        uint256 minted = accountManager.depositAndMint(address(goldAdapter), 1000e18);
        vm.stopPrank();
        assertGt(minted, 0, "second benign depositAndMint must pass");
    }
}
