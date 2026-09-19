// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Common shape shared by GoldAdapter and xStockAdapter so AccountManager can treat
/// either collateral type generically.
interface IAdapter {
    function deposit(address user, uint256 amount) external returns (uint256 shares);
    function depositAtPrice(address user, uint256 amount, uint256 price) external returns (uint256 shares);
}
