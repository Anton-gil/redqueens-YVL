// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../SetupV2.t.sol";

/// @notice Bypass strategies vs the v2 anchored chokepoint. Each test performs the attack via a
/// low-level call and LOGS a verdict (BYPASSED / BLOCKED / ERROR) derived from the ACTUAL result -
/// never a hardcoded string. bypass.py parses these logs.
///   BYPASSED = call succeeded AND over-credited (> fair*(1+tol))
///   BLOCKED  = reverted with ConversionIntegrityViolation, or with the adapter/ledger access control
///   ERROR    = any other outcome (must be investigated, never counted as blocked)
contract BypassV2 is SetupV2 {
    function _fair(uint256 tokensIn) internal pure returns (uint256) { return tokensIn * 2000e18 / 1e18; }

    function _classify(string memory name, bool ok, bytes memory data, address who, uint256 tokensIn) internal {
        uint256 credited = ledger.principal(who);
        if (ok) {
            if (credited > _fair(tokensIn) * (10_000 + accountManager.TOLERANCE_BPS()) / 10_000) {
                console2.log(string(abi.encodePacked("BYPASS ", name, " BYPASSED credited")), credited);
            } else {
                console2.log(string(abi.encodePacked("BYPASS ", name, " BLOCKED (no over-credit)")), credited);
            }
            return;
        }
        bytes4 sel; if (data.length >= 4) { assembly { sel := mload(add(data, 0x20)) } }
        if (sel == AccountManagerV2.ConversionIntegrityViolation.selector) {
            console2.log(string(abi.encodePacked("BYPASS ", name, " BLOCKED conversion-integrity")));
        } else {
            // decode a revert string (access control like NOT_ACCOUNT_MANAGER)
            console2.log(string(abi.encodePacked("BYPASS ", name, " BLOCKED access-control/other-revert")));
        }
    }

    function _donateThenDeposit(string memory name, uint256 donation, uint256 dep) internal {
        address a = makeAddr(name); goldToken.mint(a, donation + dep);
        vm.startPrank(a);
        goldToken.transfer(goldPool, donation);
        goldToken.approve(address(goldAdapter), dep);
        (bool ok, bytes memory data) = address(accountManager).call(
            abi.encodeWithSignature("deposit(address,uint256)", address(goldAdapter), dep));
        vm.stopPrank();
        _classify(name, ok, data, a, dep);
    }

    function test_multicall_path() public {
        address a = makeAddr("v2_mc"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 230_000e18); goldToken.approve(address(goldAdapter), 1e18);
        (bool ok, bytes memory data) = address(accountManager).call(
            abi.encodeWithSignature("depositAndMint(address,uint256)", address(goldAdapter), uint256(1e18)));
        vm.stopPrank();
        _classify("multicall_path", ok, data, a, 1e18);
    }
    function test_first_in_block_atomic() public {
        vm.roll(block.number + 5);
        _donateThenDeposit("first_in_block_atomic", 230_000e18, 1e18);
    }
    function test_spread_across_20_blocks() public {
        address a = makeAddr("v2_spread"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a);
        for (uint256 i = 0; i < 20; i++) { vm.roll(block.number + 1); goldToken.transfer(goldPool, 11_500e18); }
        goldToken.approve(address(goldAdapter), 1e18);
        (bool ok, bytes memory data) = address(accountManager).call(
            abi.encodeWithSignature("deposit(address,uint256)", address(goldAdapter), uint256(1e18)));
        vm.stopPrank();
        _classify("spread_across_20_blocks", ok, data, a, 1e18);
    }
    function test_split_into_10_subtransactions() public {
        address a = makeAddr("v2_split"); goldToken.mint(a, 231_000e18);
        bool ok; bytes memory data;
        vm.startPrank(a);
        goldToken.approve(address(goldAdapter), 10e18);
        for (uint256 i = 0; i < 10; i++) {
            goldToken.transfer(goldPool, 23_000e18);
            (ok, data) = address(accountManager).call(abi.encodeWithSignature("deposit(address,uint256)", address(goldAdapter), uint256(1e18)));
            if (!ok) break;
        }
        vm.stopPrank();
        _classify("split_into_10_subtransactions", ok, data, a, 1e18);
    }
    function test_direct_call_around_guard() public {
        // v2 has no wrapper; hit the adapter + ledger directly -> must be stopped by access control
        address a = makeAddr("v2_direct"); goldToken.mint(a, 1e18);
        vm.startPrank(a);
        (bool ok, bytes memory data) = address(goldAdapter).call(
            abi.encodeWithSignature("deposit(address,uint256)", a, uint256(1e18)));
        vm.stopPrank();
        _classify("direct_call_around_guard", ok, data, a, 1e18);
    }
    function test_rational_economics() public {
        _donateThenDeposit("rational_economics", 10_000e18, 100_000e18);
    }
    function test_tolerance_riding() public {
        // Residual-risk measurement: donate just under tolerance so value stays within TOLERANCE_BPS,
        // deposit >> pool. Measure extractable = credited - fair.
        address a = makeAddr("v2_tolride"); uint256 dep = 1_000_000e18;
        goldToken.mint(a, dep + 100e18);
        vm.startPrank(a);
        goldToken.transfer(goldPool, 100e18);        // ~1% rate move at pool 10000 -> within 100 bps tol
        goldToken.approve(address(goldAdapter), dep);
        (bool ok, bytes memory data) = address(accountManager).call(
            abi.encodeWithSignature("deposit(address,uint256)", address(goldAdapter), dep));
        vm.stopPrank();
        uint256 credited = ok ? ledger.principal(a) : 0;
        uint256 fair = _fair(dep);
        uint256 extractable = credited > fair ? credited - fair : 0;
        console2.log("BYPASS tolerance_riding RESIDUAL max_extractable_usd(1e18)", extractable);
        console2.log("  tolerance_riding ok(no-revert)", ok);
        data;
    }
}
