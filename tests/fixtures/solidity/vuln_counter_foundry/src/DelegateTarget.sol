// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DelegateTarget {
    uint256 public touched;

    function smash(uint256 value) external {
        touched = value;
    }
}
