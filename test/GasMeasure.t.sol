// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "./Setup.t.sol";
import "./SetupV2.t.sol";

contract GasV1 is Setup {
    function testGas() public {
        address u = makeAddr("gv1"); goldToken.mint(u, 1_000e18);
        vm.startPrank(u); goldToken.approve(address(goldAdapter), 1_000e18);
        uint256 g0 = gasleft(); accountManager.deposit(address(goldAdapter), 500e18); console2.log("GAS_V1_DEPOSIT", g0 - gasleft());
        uint256 g1 = gasleft(); accountManager.depositAndMint(address(goldAdapter), 500e18); console2.log("GAS_V1_DAM", g1 - gasleft());
        vm.stopPrank();
    }
}
contract GasV2 is SetupV2 {
    function testGas() public {
        address u = makeAddr("gv2"); goldToken.mint(u, 1_000e18);
        vm.startPrank(u); goldToken.approve(address(goldAdapter), 1_000e18);
        uint256 g0 = gasleft(); accountManager.deposit(address(goldAdapter), 500e18); console2.log("GAS_V2_DEPOSIT", g0 - gasleft());
        uint256 g1 = gasleft(); accountManager.depositAndMint(address(goldAdapter), 500e18); console2.log("GAS_V2_DAM", g1 - gasleft());
        vm.stopPrank();
    }
}
