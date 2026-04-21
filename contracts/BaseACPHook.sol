// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Compatibility shim — BaseACPHook was renamed to BaseERC8183Hook.
// Older hooks (BiddingHook, FundTransferHook) import the old name; this
// alias keeps them compiling without touching the upstream renames.
import "./BaseERC8183Hook.sol";

abstract contract BaseACPHook is BaseERC8183Hook {
    address public immutable acpContract;

    constructor(address acpContract_) BaseERC8183Hook(acpContract_) {
        acpContract = acpContract_;
    }
}
