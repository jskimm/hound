// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnCounter {
    address public owner;
    bool public initialized;
    uint256 public number;
    mapping(address => uint256) public balances;

    function initialize() external {
        owner = msg.sender;
        initialized = true;
    }

    function setNumber(uint256 newNumber) external {
        number = newNumber;
    }

    function increment() external {
        number += 1;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawAll() external {
        require(tx.origin == owner, "not owner");
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }

    function sweep(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        to.call{value: amount}("");
    }

    function batchBump(address[] calldata users) external {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] += 1;
        }
    }

    function pseudoRandom(address user) external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, user))) % 100;
    }

    function upgrade(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory out) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return out;
    }

    function destroy(address payable to) external {
        selfdestruct(to);
    }
}
