// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "./SetupV2.t.sol";

/// Regression for red-team finding #7: a benign depositAndMint must NOT corrupt the exchange rate
/// and trip the anchored guard on subsequent benign deposits.
contract RegressionV2 is SetupV2 {
    function testBenignDepositAndMintThenDepositsPass() public {
        uint256 rate0 = goldAdapter.exchangeRate();

        address u1 = makeAddr("dm_first"); goldToken.mint(u1, 500e18);
        vm.startPrank(u1); goldToken.approve(address(goldAdapter), 500e18);
        accountManager.depositAndMint(address(goldAdapter), 500e18);
        vm.stopPrank();

        uint256 rate1 = goldAdapter.exchangeRate();
        // rate must stay ~1e18 (no 2000x share corruption)
        assertApproxEqRel(rate1, rate0, 0.01e18, "depositAndMint corrupted the exchange rate");

        // subsequent benign deposit AND depositAndMint must both still pass
        address u2 = makeAddr("dep_after"); goldToken.mint(u2, 500e18);
        vm.startPrank(u2); goldToken.approve(address(goldAdapter), 500e18);
        accountManager.deposit(address(goldAdapter), 500e18);
        vm.stopPrank();
        assertGt(ledger.principal(u2), 0, "benign deposit after depositAndMint must pass");

        address u3 = makeAddr("dm_after"); goldToken.mint(u3, 500e18);
        vm.startPrank(u3); goldToken.approve(address(goldAdapter), 500e18);
        uint256 minted = accountManager.depositAndMint(address(goldAdapter), 500e18);
        vm.stopPrank();
        assertGt(minted, 0, "benign depositAndMint after depositAndMint must pass");
    }
}
