// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../Setup.t.sol";

/// v1 guard (ExchangeRateDeltaBound, 1-block window) as it shipped, applied via an opt-in wrapper.
contract V1Guard {
    GoldAdapter public immutable adapter;
    uint256 public constant MAX_DELTA_BPS = 1590;
    uint256 public constant WINDOW_BLOCKS = 1;
    uint256 public checkpointRate;
    uint256 public checkpointBlock;
    error ExchangeRateDeltaViolation(uint256 rb, uint256 ra, uint256 bps);
    constructor(GoldAdapter a) { adapter = a; }
    modifier assertRateDeltaBound() {
        if (checkpointBlock == 0 || block.number >= checkpointBlock + WINDOW_BLOCKS) {
            checkpointRate = adapter.exchangeRate(); checkpointBlock = block.number;
        }
        uint256 rb = checkpointRate; _; uint256 ra = adapter.exchangeRate();
        uint256 d = ra > rb ? ra - rb : rb - ra; uint256 bps = rb == 0 ? 0 : d * 10000 / rb;
        if (bps > MAX_DELTA_BPS) revert ExchangeRateDeltaViolation(rb, ra, bps);
    }
}
contract GuardedGoldDeposit is V1Guard {
    AccountManager public am; MockERC20 public gold;
    constructor(AccountManager _am, GoldAdapter _a, MockERC20 _g) V1Guard(_a) { am = _am; gold = _g; }
    function guardedDeposit(uint256 amt) external assertRateDeltaBound returns (uint256) {
        gold.transferFrom(msg.sender, address(this), amt); gold.approve(address(adapter), amt);
        return am.deposit(address(adapter), amt);
    }
}

contract BypassV1 is Setup {
    GuardedGoldDeposit guard;
    function setUp() public override { super.setUp(); guard = new GuardedGoldDeposit(accountManager, goldAdapter, goldToken); }
    function _fair(uint256 t) internal pure returns (uint256) { return t * 2000e18 / 1e18; }
    function _log(string memory name, bool ok, uint256 credited, uint256 tokensIn) internal {
        if (ok && credited > _fair(tokensIn) * 11 / 10) console2.log(string(abi.encodePacked("BYPASS ", name, " BYPASSED credited")), credited);
        else if (!ok) console2.log(string(abi.encodePacked("BYPASS ", name, " BLOCKED")));
        else console2.log(string(abi.encodePacked("BYPASS ", name, " BLOCKED (no over-credit)")));
    }

    function test_multicall_path() public {
        address a = makeAddr("v1_mc"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 230_000e18); goldToken.approve(address(goldAdapter), 1e18);
        (bool ok,) = address(accountManager).call(abi.encodeWithSignature("depositAndMint(address,uint256)", address(goldAdapter), uint256(1e18)));
        vm.stopPrank();
        _log("multicall_path", ok, token.balanceOf(a), 1e18);
    }
    function test_direct_call_around_guard() public {
        address a = makeAddr("v1_direct"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 230_000e18); goldToken.approve(address(goldAdapter), 1e18);
        (bool ok,) = address(accountManager).call(abi.encodeWithSignature("deposit(address,uint256)", address(goldAdapter), uint256(1e18)));
        vm.stopPrank();
        _log("direct_call_around_guard", ok, ledger.principal(a), 1e18);
    }
    function test_first_in_block_atomic() public {
        vm.roll(block.number + 5);
        address a = makeAddr("v1_fresh"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 230_000e18); goldToken.approve(address(guard), 1e18);
        (bool ok,) = address(guard).call(abi.encodeWithSignature("guardedDeposit(uint256)", uint256(1e18)));
        vm.stopPrank();
        _log("first_in_block_atomic", ok, ledger.principal(address(guard)), 1e18);
    }
    function test_spread_across_20_blocks() public {
        address a = makeAddr("v1_spread"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.approve(address(guard), 1e18);
        bool ok;
        for (uint256 i = 0; i < 20; i++) { vm.roll(block.number + 1); goldToken.transfer(goldPool, 11_500e18); }
        (ok,) = address(guard).call(abi.encodeWithSignature("guardedDeposit(uint256)", uint256(1e18)));
        vm.stopPrank();
        _log("spread_across_20_blocks", ok, ledger.principal(address(guard)), 1e18);
    }
    function test_split_into_10_subtransactions() public {
        address a = makeAddr("v1_split"); goldToken.mint(a, 231_000e18);
        vm.startPrank(a); goldToken.approve(address(guard), 10e18);
        bool ok;
        for (uint256 i = 0; i < 10; i++) { goldToken.transfer(goldPool, 23_000e18); (ok,) = address(guard).call(abi.encodeWithSignature("guardedDeposit(uint256)", uint256(1e18))); if (!ok) break; }
        vm.stopPrank();
        _log("split_into_10_subtransactions", ok, ledger.principal(address(guard)), 1e18);
    }
    function test_rational_economics() public {
        address a = makeAddr("v1_rat"); goldToken.mint(a, 110_000e18);
        vm.startPrank(a); goldToken.transfer(goldPool, 10_000e18); goldToken.approve(address(goldAdapter), 100_000e18);
        (bool ok,) = address(accountManager).call(abi.encodeWithSignature("deposit(address,uint256)", address(goldAdapter), uint256(100_000e18)));
        vm.stopPrank();
        _log("rational_economics", ok, ledger.principal(a), 100_000e18);
    }
}
