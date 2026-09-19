// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./rwaUSDToken.sol";

/// @notice Tracks locked collateral shares and mintable principal per account. The only
/// contract allowed to move rwaUSD supply; AccountManager is the only caller allowed to move
/// Ledger state.
contract Ledger {
    rwaUSDToken public immutable token;
    address public accountManager;

    // account => adapter => shares locked
    mapping(address => mapping(address => uint256)) public lockedShares;
    // account => available-to-mint value credited from deposits, consumed by mint()
    mapping(address => uint256) public principal;

    modifier onlyAccountManager() {
        require(msg.sender == accountManager, "NOT_ACCOUNT_MANAGER");
        _;
    }

    constructor(rwaUSDToken _token) {
        token = _token;
    }

    function setAccountManager(address _am) external {
        require(accountManager == address(0), "AM_ALREADY_SET");
        accountManager = _am;
    }

    function lock(address account, address adapter, uint256 shares) external onlyAccountManager {
        lockedShares[account][adapter] += shares;
    }

    function unlock(address account, address adapter, uint256 shares) external onlyAccountManager {
        lockedShares[account][adapter] -= shares;
    }

    function increasePrincipal(address account, uint256 value) external onlyAccountManager {
        principal[account] += value;
    }

    function decreasePrincipal(address account, uint256 value) external onlyAccountManager {
        principal[account] -= value;
    }

    function mint(address account, uint256 amount) external onlyAccountManager {
        token.mint(account, amount);
    }

    function burn(address account, uint256 amount) external onlyAccountManager {
        token.burn(account, amount);
    }
}
