// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Compatibility shim — BaseACPHook was renamed to BaseERC8183Hook.
// Hooks written against the old name compile via this file.
import "./BaseERC8183Hook.sol";

abstract contract BaseACPHook is BaseERC8183Hook {
    // Old field name used by hooks written against BaseACPHook.
    // Points to the same address as erc8183Contract.
    address public immutable acpContract;

    constructor(address acpContract_) BaseERC8183Hook(acpContract_) {
        acpContract = acpContract_;
    }
}
