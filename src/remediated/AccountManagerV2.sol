// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../Ledger.sol";
import "../PriceRouter.sol";
import "../IAdapter.sol";
import "../xStockAdapter.sol";

/// @notice Remediated AccountManager. Identical constructor + external API and the SAME (vulnerable)
/// valuation formulas as src/AccountManager.sol - so that the GUARD, not a formula change, is what
/// blocks the attack. All principal credit routes through the single chokepoint `_creditPrincipal`,
/// which anchors the credited value to an INDEPENDENT reference (raw USD-per-collateral-token feed),
/// not priceRouter.getPrice() (which already contains the manipulable pool rate).
contract AccountManagerV2 {
    Ledger public immutable ledger;
    PriceRouter public immutable priceRouter;
    address public admin;
    uint256 public immutable TOLERANCE_BPS;

    mapping(address => bool) public isAdapter;

    error ConversionIntegrityViolation(uint256 expected, uint256 recorded);

    event Deposited(address indexed user, address indexed adapter, uint256 amount, uint256 shares);
    event Minted(address indexed user, uint256 amount);
    event DepositedAndMinted(address indexed user, address indexed adapter, uint256 amount, uint256 minted);

    constructor(Ledger _ledger, PriceRouter _priceRouter, address _admin, uint256 _toleranceBps) {
        ledger = _ledger;
        priceRouter = _priceRouter;
        admin = _admin;
        TOLERANCE_BPS = _toleranceBps;
    }

    function registerAdapter(address adapter) external {
        require(msg.sender == admin, "NOT_ADMIN");
        isAdapter[adapter] = true;
    }

    function deposit(address adapter, uint256 amount) public returns (uint256 shares) {
        require(isAdapter[adapter], "UNKNOWN_ADAPTER");
        PriceRouter.PriceData memory pd = priceRouter.getPrice(adapter);
        shares = IAdapter(adapter).deposit(msg.sender, amount);
        ledger.lock(msg.sender, adapter, shares);
        _creditPrincipal(msg.sender, adapter, amount, (amount * pd.price) / 1e18);
        emit Deposited(msg.sender, adapter, amount, shares);
    }

    function mint(uint256 amount) public {
        ledger.decreasePrincipal(msg.sender, amount);
        ledger.mint(msg.sender, amount);
        emit Minted(msg.sender, amount);
    }

    function depositAndMint(address adapter, uint256 amount) external returns (uint256 minted) {
        require(isAdapter[adapter], "UNKNOWN_ADAPTER");
        PriceRouter.PriceData memory pd = priceRouter.getPrice(adapter);
        uint256 shares = IAdapter(adapter).depositAtPrice(msg.sender, amount, pd.price);
        ledger.lock(msg.sender, adapter, shares);
        uint256 value = (amount * pd.price) / 1e18;
        _creditPrincipal(msg.sender, adapter, amount, value);
        minted = value;
        ledger.decreasePrincipal(msg.sender, minted);
        ledger.mint(msg.sender, minted);
        emit DepositedAndMinted(msg.sender, adapter, amount, minted);
    }

    /// @dev The ONE place principal is credited. Anchor = raw USD per collateral TOKEN, independent
    /// of pool balance / share accounting, so donation/rate manipulation cannot inflate `expected`.
    /// Reverts only on OVER-crediting (protocol bad debt); under-crediting (Vuln B, depositor loss)
    /// is out of scope for this solvency guard.
    function _creditPrincipal(address user, address adapter, uint256 tokensIn, uint256 value) internal {
        uint256 expected = tokensIn * priceRouter.usdFeedOf(adapter).latestPrice() / 1e18;
        // XSTOCK: true unit value folds in the corporate-action multiplier the router omits.
        if (priceRouter.kindOf(adapter) == PriceRouter.Kind.XSTOCK) {
            expected = expected * xStockAdapter(adapter).rebaseMultiplier() / 1e18;
        }
        if (value * 10_000 > expected * (10_000 + TOLERANCE_BPS)) {
            revert ConversionIntegrityViolation(expected, value);
        }
        ledger.increasePrincipal(user, value);
    }
}
