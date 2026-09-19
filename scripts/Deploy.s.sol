// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import "../src/rwaUSDToken.sol";
import "../src/Ledger.sol";
import "../src/AccountManager.sol";
import "../src/GoldAdapter.sol";
import "../src/xStockAdapter.sol";
import "../src/PriceRouter.sol";
import "../src/MockERC20.sol";
import "../src/MockPriceFeed.sol";

/// @notice Live-node deployment of the full Red Queen system. Reproduces the EXACT topology and
/// initial state that test/Setup.t.sol builds, so the attack agent sees an identical system whether
/// it queries this live anvil deployment or runs an ephemeral `forge test`.
///
/// Key design choice for clean broadcasting: the broadcasting deployer (anvil account 0) is also the
/// `admin` for every admin-gated contract. MockERC20.mint is permissionless, and PriceRouter /
/// MockPriceFeed / adapter admin ops are all gated to this single sender, so one broadcasting account
/// can deploy, wire, mint, approve, and seed both pools with no vm.prank needed.
contract Deploy is Script {
    uint256 constant SEED_AMOUNT = 10_000e18;

    function run() external {
        // Deployer == admin == anvil account 0 (the --private-key passed on the CLI).
        address admin = msg.sender;

        // Two fixed, distinct pool addresses (EOAs that just hold collateral tokens), mirroring the
        // makeAddr("goldPool")/makeAddr("stockPool") pattern in Setup.t.sol but deterministic here.
        address goldPool = address(uint160(uint256(keccak256("goldPool"))));
        address stockPool = address(uint160(uint256(keccak256("stockPool"))));

        vm.startBroadcast();

        // --- Core system ---
        rwaUSDToken token = new rwaUSDToken(admin);
        Ledger ledger = new Ledger(token);
        PriceRouter priceRouter = new PriceRouter(admin);
        AccountManager accountManager = new AccountManager(ledger, priceRouter, admin);

        token.setLedger(address(ledger));
        ledger.setAccountManager(address(accountManager));

        // --- Gold collateral leg ---
        MockERC20 goldToken = new MockERC20("Tokenized Gold", "xAU");
        GoldAdapter goldAdapter = new GoldAdapter(goldToken, goldPool);
        goldAdapter.setAccountManager(address(accountManager));
        MockPriceFeed goldUsdFeed = new MockPriceFeed(admin, 2000e18); // $2000/oz
        priceRouter.registerAdapter(address(goldAdapter), PriceRouter.Kind.GOLD, goldUsdFeed);
        accountManager.registerAdapter(address(goldAdapter));

        // --- Stock collateral leg ---
        MockERC20 stockToken = new MockERC20("Tokenized AAPL", "xAAPL");
        xStockAdapter xstockAdapter = new xStockAdapter(stockToken, stockPool, admin);
        xstockAdapter.setAccountManager(address(accountManager));
        MockPriceFeed stockUsdFeed = new MockPriceFeed(admin, 190e18); // $190/share
        priceRouter.registerAdapter(address(xstockAdapter), PriceRouter.Kind.XSTOCK, stockUsdFeed);
        accountManager.registerAdapter(address(xstockAdapter));

        // --- Seed both pools with a legitimate first depositor (10_000e18 each) ---
        // NOTE: approve the ADAPTER, not AccountManager -- the adapter is what calls transferFrom.
        goldToken.mint(admin, SEED_AMOUNT);
        goldToken.approve(address(goldAdapter), SEED_AMOUNT);
        accountManager.deposit(address(goldAdapter), SEED_AMOUNT);

        stockToken.mint(admin, SEED_AMOUNT);
        stockToken.approve(address(xstockAdapter), SEED_AMOUNT);
        accountManager.deposit(address(xstockAdapter), SEED_AMOUNT);

        vm.stopBroadcast();

        // --- Emit every deployed address with a clear NAME=0x... label ---
        console2.log("DEPLOYER=", admin);
        console2.log("rwaUSDToken=", address(token));
        console2.log("Ledger=", address(ledger));
        console2.log("PriceRouter=", address(priceRouter));
        console2.log("AccountManager=", address(accountManager));
        console2.log("goldToken=", address(goldToken));
        console2.log("goldPool=", goldPool);
        console2.log("goldAdapter=", address(goldAdapter));
        console2.log("goldUsdFeed=", address(goldUsdFeed));
        console2.log("stockToken=", address(stockToken));
        console2.log("stockPool=", stockPool);
        console2.log("xstockAdapter=", address(xstockAdapter));
        console2.log("stockUsdFeed=", address(stockUsdFeed));
    }
}
