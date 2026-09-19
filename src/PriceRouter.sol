// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockPriceFeed.sol";
import "./GoldAdapter.sol";
import "./xStockAdapter.sol";

/// @notice Single getPrice() interface composing per-adapter-type feeds into a USD price per
/// unit of adapter share. Each adapter kind has its own composition path.
contract PriceRouter {
    enum Kind { UNSET, GOLD, XSTOCK }

    struct PriceData {
        uint256 price; // USD per adapter share, 1e18-scaled
        uint256 updatedAt;
    }

    address public admin;
    mapping(address => Kind) public kindOf;
    mapping(address => MockPriceFeed) public usdFeedOf; // gold-spot or per-share-stock feed, depending on kind

    constructor(address _admin) {
        admin = _admin;
    }

    function registerAdapter(address adapter, Kind kind, MockPriceFeed feed) external {
        require(msg.sender == admin, "NOT_ADMIN");
        kindOf[adapter] = kind;
        usdFeedOf[adapter] = feed;
    }

    function getPrice(address adapter) public view returns (PriceData memory) {
        Kind kind = kindOf[adapter];
        require(kind != Kind.UNSET, "UNKNOWN_ADAPTER");

        if (kind == Kind.GOLD) {
            uint256 rate = GoldAdapter(adapter).exchangeRate();       // collateral units per share
            uint256 usdPerUnit = usdFeedOf[adapter].latestPrice();    // USD per collateral unit
            uint256 price = (rate * usdPerUnit) / 1e18;
            return PriceData({price: price, updatedAt: block.timestamp});
        }

        if (kind == Kind.XSTOCK) {
            // Per-share USD price from the equity feed. NOTE: the feed prices the *underlying*
            // share; a holder's position also compounds by rebaseMultiplier via corporate actions,
            // which this composition path does not fold in.
            uint256 usdPerShare = usdFeedOf[adapter].latestPrice();
            return PriceData({price: usdPerShare, updatedAt: block.timestamp});
        }

        revert("UNREACHABLE");
    }
}
