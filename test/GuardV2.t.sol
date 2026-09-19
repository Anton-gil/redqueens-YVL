// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./SetupV2.t.sol";

/// @notice Proof suite for the v2 anchored conversion-integrity chokepoint (AccountManagerV2).
/// Every "blocked" verdict asserts the SPECIFIC error via expectPartialRevert (forge 1.8.3 form
/// for errors with args). Legit flows must pass; every attack class from the review must revert.
contract GuardV2 is SetupV2 {
    // ---- legit flows pass ----
    function testLegitDepositPasses() public {
        address u = makeAddr("legit_g"); goldToken.mint(u, 500e18);
        vm.startPrank(u); goldToken.approve(address(goldAdapter), 500e18);
        accountManager.deposit(address(goldAdapter), 500e18);
        vm.stopPrank();
        assertGt(ledger.principal(u), 0);
    }
    function testLegitStockDepositPasses() public {
        address u = makeAddr("legit_s"); stockToken.mint(u, 500e18);
        vm.startPrank(u); stockToken.approve(address(xstockAdapter), 500e18);
        accountManager.deposit(address(xstockAdapter), 500e18);
        vm.stopPrank();
        assertGt(ledger.principal(u), 0);
    }
    function testLegitDepositAndMintPasses() public {
        address u = makeAddr("legit_dm"); goldToken.mint(u, 500e18);
        vm.startPrank(u); goldToken.approve(address(goldAdapter), 500e18);
        uint256 minted = accountManager.depositAndMint(address(goldAdapter), 500e18);
        vm.stopPrank();
        assertGt(minted, 0);
    }

    // ---- attacks blocked ----
    function testDonationDepositReverts() public {
        address a = makeAddr("a1"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 230_000e18); goldToken.approve(address(goldAdapter), 1e18);
        vm.expectPartialRevert(AccountManagerV2.ConversionIntegrityViolation.selector);
        accountManager.deposit(address(goldAdapter), 1e18);
        vm.stopPrank();
    }
    function testDonationDepositAndMintReverts() public {
        address a = makeAddr("a2"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 230_000e18); goldToken.approve(address(goldAdapter), 1e18);
        vm.expectPartialRevert(AccountManagerV2.ConversionIntegrityViolation.selector);
        accountManager.depositAndMint(address(goldAdapter), 1e18);
        vm.stopPrank();
    }
    function testFreshBlockAtomicReverts() public {
        // the v1 killer: attacker's deposit is the first guarded call in a fresh block. V2 has no
        // per-block checkpoint to fool -> the anchored check still fires.
        vm.roll(block.number + 5);
        address a = makeAddr("a3"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 230_000e18); goldToken.approve(address(goldAdapter), 1e18);
        vm.expectPartialRevert(AccountManagerV2.ConversionIntegrityViolation.selector);
        accountManager.deposit(address(goldAdapter), 1e18);
        vm.stopPrank();
    }
    function testSpread20BlocksReverts() public {
        // spread the donation across 20 blocks (defeats v1's 1-block window); V2's anchor doesn't move.
        address a = makeAddr("a4"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a);
        for (uint256 i = 0; i < 20; i++) { vm.roll(block.number + 1); goldToken.transfer(goldPool, 11_500e18); }
        goldToken.approve(address(goldAdapter), 1e18);
        vm.expectPartialRevert(AccountManagerV2.ConversionIntegrityViolation.selector);
        accountManager.deposit(address(goldAdapter), 1e18);
        vm.stopPrank();
    }
    function testRationalEconomicsReverts() public {
        // rational attack (donate 10k, deposit 100k, deposit>pool) is profitable on v1; V2 blocks it.
        address a = makeAddr("a5"); goldToken.mint(a, 110_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 10_000e18); goldToken.approve(address(goldAdapter), 100_000e18);
        vm.expectPartialRevert(AccountManagerV2.ConversionIntegrityViolation.selector);
        accountManager.deposit(address(goldAdapter), 100_000e18);
        vm.stopPrank();
    }
}
