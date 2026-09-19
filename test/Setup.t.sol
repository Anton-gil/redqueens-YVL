// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/rwaUSDToken.sol";
import "../src/Ledger.sol";
import "../src/AccountManager.sol";
import "../src/GoldAdapter.sol";
import "../src/xStockAdapter.sol";
import "../src/PriceRouter.sol";
import "../src/MockERC20.sol";
import "../src/MockPriceFeed.sol";

/// @notice Deploys the full six-contract system with two collateral types (gold, xStock) so
/// exploit tests, benign corpus generation, and guard-deployment tests all share one topology.
/// Both adapters are seeded with a legitimate first depositor before any test runs: real pools
/// are never empty when an attacker targets them (this is also what the Edel Finance incident
/// actually looked like — an established pool, not a freshly-deployed empty one).
contract Setup is Test {
    address admin = makeAddr("admin");
    address seedUser = makeAddr("seedUser");

    uint256 constant SEED_AMOUNT = 10_000e18;

    rwaUSDToken token;
    Ledger ledger;
    PriceRouter priceRouter;
    AccountManager accountManager;

    MockERC20 goldToken;
    address goldPool;
    GoldAdapter goldAdapter;
    MockPriceFeed goldUsdFeed;

    MockERC20 stockToken;
    address stockPool;
    xStockAdapter xstockAdapter;
    MockPriceFeed stockUsdFeed;

    function setUp() public virtual {
        vm.startPrank(admin);

        token = new rwaUSDToken(admin);
        ledger = new Ledger(token);
        priceRouter = new PriceRouter(admin);
        accountManager = new AccountManager(ledger, priceRouter, admin);

        token.setLedger(address(ledger));
        ledger.setAccountManager(address(accountManager));

        goldToken = new MockERC20("Tokenized Gold", "xAU");
        goldPool = makeAddr("goldPool");
        goldAdapter = new GoldAdapter(goldToken, goldPool);
        goldAdapter.setAccountManager(address(accountManager));
        goldUsdFeed = new MockPriceFeed(admin, 2000e18); // $2000/oz
        priceRouter.registerAdapter(address(goldAdapter), PriceRouter.Kind.GOLD, goldUsdFeed);
        accountManager.registerAdapter(address(goldAdapter));

        stockToken = new MockERC20("Tokenized AAPL", "xAAPL");
        stockPool = makeAddr("stockPool");
        xstockAdapter = new xStockAdapter(stockToken, stockPool, admin);
        xstockAdapter.setAccountManager(address(accountManager));
        stockUsdFeed = new MockPriceFeed(admin, 190e18); // $190/share
        priceRouter.registerAdapter(address(xstockAdapter), PriceRouter.Kind.XSTOCK, stockUsdFeed);
        accountManager.registerAdapter(address(xstockAdapter));

        vm.stopPrank();

        goldToken.mint(seedUser, SEED_AMOUNT);
        vm.startPrank(seedUser);
        goldToken.approve(address(goldAdapter), SEED_AMOUNT);
        accountManager.deposit(address(goldAdapter), SEED_AMOUNT);
        vm.stopPrank();

        stockToken.mint(seedUser, SEED_AMOUNT);
        vm.startPrank(seedUser);
        stockToken.approve(address(xstockAdapter), SEED_AMOUNT);
        accountManager.deposit(address(xstockAdapter), SEED_AMOUNT);
        vm.stopPrank();
    }
}
