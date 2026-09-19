// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockERC20.sol";

/// @notice Wraps a gold-backed collateral token sitting in a reserve pool. Shares represent
/// a claim on the pool proportional to deposits.
contract GoldAdapter {
    MockERC20 public immutable token;
    address public immutable pool;
    address public accountManager;
    uint256 public totalShares;

    modifier onlyAccountManager() {
        require(msg.sender == accountManager, "NOT_ACCOUNT_MANAGER");
        _;
    }

    constructor(MockERC20 _token, address _pool) {
        token = _token;
        pool = _pool;
    }

    function setAccountManager(address _am) external {
        require(accountManager == address(0), "AM_ALREADY_SET");
        accountManager = _am;
    }

    /// @dev Reserve-ratio price: value of one share in units of the underlying collateral token.
    /// Anything that moves `token.balanceOf(pool)` without minting shares (e.g. a bare transfer
    /// into the pool) moves this rate.
    function exchangeRate() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (token.balanceOf(pool) * 1e18) / totalShares;
    }

    /// @notice Standard entry point: always re-reads the live rate before minting shares.
    function deposit(address user, uint256 amount) external onlyAccountManager returns (uint256 shares) {
        uint256 rate = exchangeRate();
        token.transferFrom(user, pool, amount);
        shares = (amount * 1e18) / rate;
        totalShares += shares;
    }

    /// @notice Fast-path entry point used by AccountManager.depositAndMint(), which has already
    /// looked the price up once via the PriceRouter to avoid a second oracle round-trip. Trusts
    /// the caller-supplied price instead of re-deriving it from pool state.
    function depositAtPrice(address user, uint256 amount, uint256 price) external onlyAccountManager returns (uint256 shares) {
        token.transferFrom(user, pool, amount);
        shares = (amount * 1e18) / price;
        totalShares += shares;
    }

    function redeem(address user, uint256 shares) external onlyAccountManager returns (uint256 amountOut) {
        uint256 rate = exchangeRate();
        amountOut = (shares * rate) / 1e18;
        totalShares -= shares;
        token.transfer(user, amountOut);
    }
}
