// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/rwaUSDToken.sol";
import "../src/Ledger.sol";
import "../src/remediated/AccountManagerV2.sol";
import "../src/GoldAdapter.sol";
import "../src/xStockAdapter.sol";
import "../src/PriceRouter.sol";
import "../src/MockERC20.sol";
import "../src/MockPriceFeed.sol";

/// @notice Same topology as Setup.t.sol, but deploys the remediated AccountManagerV2 (anchored
/// conversion-integrity chokepoint). TOLERANCE_BPS is provisional here; the lead sets it from
/// Agent D's measured benign conversion-ratio deviation (see validation.json / FIX_REPORT.md).
contract SetupV2 is Test {
    address admin = makeAddr("admin");
    address seedUser = makeAddr("seedUser");

    uint256 constant SEED_AMOUNT = 10_000e18;
    uint256 constant TOLERANCE_BPS_V2 = 100; // provisional; overridden by Agent D measurement

    rwaUSDToken token;
    Ledger ledger;
    PriceRouter priceRouter;
    AccountManagerV2 accountManager;

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
        accountManager = new AccountManagerV2(ledger, priceRouter, admin, TOLERANCE_BPS_V2);

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
