// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Ledger.sol";
import "./PriceRouter.sol";
import "./IAdapter.sol";

/// @notice User-facing entry point. Adapters are registered generically so deposit()/mint() work
/// across collateral types; depositAndMint() exists as a gas-saving multicall for the common
/// deposit-then-borrow flow.
contract AccountManager {
    Ledger public immutable ledger;
    PriceRouter public immutable priceRouter;
    address public admin;

    mapping(address => bool) public isAdapter;

    event Deposited(address indexed user, address indexed adapter, uint256 amount, uint256 shares);
    event Minted(address indexed user, uint256 amount);
    event DepositedAndMinted(address indexed user, address indexed adapter, uint256 amount, uint256 minted);

    constructor(Ledger _ledger, PriceRouter _priceRouter, address _admin) {
        ledger = _ledger;
        priceRouter = _priceRouter;
        admin = _admin;
    }

    function registerAdapter(address adapter) external {
        require(msg.sender == admin, "NOT_ADMIN");
        isAdapter[adapter] = true;
    }

    /// @notice Deposit collateral into `adapter` at its live, freshly-read exchange rate.
    function deposit(address adapter, uint256 amount) public returns (uint256 shares) {
        require(isAdapter[adapter], "UNKNOWN_ADAPTER");
        PriceRouter.PriceData memory pd = priceRouter.getPrice(adapter);
        shares = IAdapter(adapter).deposit(msg.sender, amount);
        ledger.lock(msg.sender, adapter, shares);
        ledger.increasePrincipal(msg.sender, (amount * pd.price) / 1e18);
        emit Deposited(msg.sender, adapter, amount, shares);
    }

    /// @notice Mint rwaUSD against previously credited principal.
    function mint(uint256 amount) public {
        ledger.decreasePrincipal(msg.sender, amount);
        ledger.mint(msg.sender, amount);
        emit Minted(msg.sender, amount);
    }

    /// @notice Combined deposit-then-mint in one call. Looks the price up once and reuses it for
    /// both the adapter's share accounting and the principal credit, instead of paying for a
    /// second oracle read.
    function depositAndMint(address adapter, uint256 amount) external returns (uint256 minted) {
        require(isAdapter[adapter], "UNKNOWN_ADAPTER");
        PriceRouter.PriceData memory pd = priceRouter.getPrice(adapter);

        uint256 shares = IAdapter(adapter).depositAtPrice(msg.sender, amount, pd.price);
        ledger.lock(msg.sender, adapter, shares);

        uint256 value = (amount * pd.price) / 1e18;
        ledger.increasePrincipal(msg.sender, value);
        minted = value;
        ledger.decreasePrincipal(msg.sender, minted);
        ledger.mint(msg.sender, minted);

        emit DepositedAndMinted(msg.sender, adapter, amount, minted);
    }
}
