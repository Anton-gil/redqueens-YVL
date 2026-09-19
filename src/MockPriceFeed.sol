// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Stand-in for a Chainlink-style feed. Owner-settable so the corpus generator and
/// attack agent can move prices deterministically on the fork without a live oracle network.
contract MockPriceFeed {
    address public owner;
    uint256 public price; // 1e18-scaled USD price
    uint256 public updatedAt;

    constructor(address _owner, uint256 _initialPrice) {
        owner = _owner;
        price = _initialPrice;
        updatedAt = block.timestamp;
    }

    function setPrice(uint256 _price) external {
        require(msg.sender == owner, "NOT_OWNER");
        price = _price;
        updatedAt = block.timestamp;
    }

    function latestPrice() external view returns (uint256) {
        return price;
    }
}
