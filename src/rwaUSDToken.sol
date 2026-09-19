// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Protocol stablecoin. Mint/burn authority is gated to the Ledger contract only.
contract rwaUSDToken {
    string public constant name = "Real World Asset USD";
    string public constant symbol = "rwaUSD";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public ledger;
    address public admin;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    modifier onlyLedger() {
        require(msg.sender == ledger, "NOT_LEDGER");
        _;
    }

    constructor(address _admin) {
        admin = _admin;
    }

    function setLedger(address _ledger) external {
        require(msg.sender == admin, "NOT_ADMIN");
        require(ledger == address(0), "LEDGER_ALREADY_SET");
        ledger = _ledger;
    }

    function mint(address to, uint256 amount) external onlyLedger {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(address from, uint256 amount) external onlyLedger {
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}
