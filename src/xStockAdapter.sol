// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockERC20.sol";

/// @notice Wraps a tokenized-equity collateral position. Corporate actions (dividends, splits)
/// are reflected as a cumulative multiplier applied to each holder's recorded shares rather than
/// as balance rebases on the underlying token itself.
contract xStockAdapter {
    MockERC20 public immutable token;
    address public immutable pool;
    address public accountManager;
    address public admin;

    uint256 public totalShares;
    /// @dev 1e18 = no corporate action applied yet. Grows over time as dividends accrue.
    uint256 public rebaseMultiplier = 1e18;

    modifier onlyAccountManager() {
        require(msg.sender == accountManager, "NOT_ACCOUNT_MANAGER");
        _;
    }

    constructor(MockERC20 _token, address _pool, address _admin) {
        token = _token;
        pool = _pool;
        admin = _admin;
    }

    function setAccountManager(address _am) external {
        require(accountManager == address(0), "AM_ALREADY_SET");
        accountManager = _am;
    }

    /// @notice Applied by the admin (or, on Multipli, a keeper) whenever the underlying issuer
    /// posts a corporate action. Purely additive/multiplicative bookkeeping on shares.
    function applyCorporateAction(uint256 newMultiplier) external {
        require(msg.sender == admin, "NOT_ADMIN");
        require(newMultiplier >= rebaseMultiplier, "MULTIPLIER_MONOTONIC");
        rebaseMultiplier = newMultiplier;
    }

    function exchangeRate() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (token.balanceOf(pool) * 1e18) / totalShares;
    }

    function deposit(address user, uint256 amount) external onlyAccountManager returns (uint256 shares) {
        uint256 rate = exchangeRate();
        token.transferFrom(user, pool, amount);
        shares = (amount * 1e18) / rate;
        totalShares += shares;
    }

    function depositAtPrice(address user, uint256 amount, uint256 price) external onlyAccountManager returns (uint256 shares) {
        token.transferFrom(user, pool, amount);
        shares = (amount * 1e18) / price;
        totalShares += shares;
    }
}
