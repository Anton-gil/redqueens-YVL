// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "./SetupV2.t.sol";
contract ValidationV2 is SetupV2 {
    // 40 varied benign gold deposits (incl. dust) on the EVM; NONE may revert at TOLERANCE_BPS=100,
    // and we measure the actual conversion-ratio deviation the EVM produces.
    function testBenignSequenceNoFalsePositive() public {
        uint256 maxDevBps = 0;
        for (uint256 i = 1; i <= 40; i++) {
            address u = makeAddr(string(abi.encodePacked("benign", vm.toString(i))));
            uint256 amt = (i % 5 == 0) ? 13_000 : (i * 137e18);  // mix dust (13000 wei) and normal
            goldToken.mint(u, amt);
            vm.startPrank(u);
            goldToken.approve(address(goldAdapter), amt);
            uint256 preP = ledger.principal(u);
            accountManager.deposit(address(goldAdapter), amt);   // must NOT revert
            uint256 credited = ledger.principal(u) - preP;
            vm.stopPrank();
            uint256 expected = amt * 2000e18 / 1e18;
            if (expected > 0) {
                uint256 dev = credited > expected ? credited - expected : expected - credited;
                uint256 bps = dev * 10000 / expected;
                if (bps > maxDevBps) maxDevBps = bps;
            }
        }
        console2.log("EVM benign max conversion-ratio deviation (bps)", maxDevBps);
        assertLt(maxDevBps, 100, "benign EVM deviation must be under the 100 bps tolerance");
    }
}
