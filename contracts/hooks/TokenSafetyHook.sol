// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseACPHook.sol";
import "@acp/AgenticCommerce.sol";
import "../interfaces/ITokenSafetyOracle.sol";

/// @title TokenSafetyHook
/// @notice Blocks job funding when the payment token is flagged as unsafe
///         by an external oracle. Standalone policy hook — no router or
///         attestation dependencies.
///
/// @dev Inherits BaseACPHook; only overrides `_preFund`.
///      Reads `paymentToken` from `getJob(jobId)` — never decodes it from
///      hook callback data.
///
///      Token check flow:
///        1. fund(jobId, ...) triggers beforeAction → _preFund
///        2. Read job.paymentToken from AgenticCommerce
///        3. If whitelisted → pass
///        4. Else query oracle → if verdict is blocked → revert
///
/// @custom:security-contact security@erc-8183.org
contract TokenSafetyHook is BaseACPHook {
    // ──────────────────── Storage ────────────────────

    /// @notice Token safety oracle
    ITokenSafetyOracle public oracle;

    /// @notice Bitmask of verdicts to block (bit N = block verdict N)
    uint8 public blockedVerdicts;

    /// @notice Whitelisted tokens bypass oracle checks
    mapping(address => bool) public whitelisted;

    /// @notice Contract owner for admin functions
    address public owner;

    // ──────────────────── Constants ────────────────────

    /// @dev Default blocked: Honeypot(1) | HighTax(2) | Blocked(4) = 0b10110 = 22
    uint8 public constant DEFAULT_BLOCKED_VERDICTS = (1 << 1) | (1 << 2) | (1 << 4);

    // ──────────────────── Errors ────────────────────

    error UnsafeToken(address token, uint8 verdict);
    error ZeroAddress();
    error OnlyOwner();

    // ──────────────────── Events ────────────────────

    event TokenChecked(uint256 indexed jobId, address indexed token, uint8 verdict, bool allowed);
    event TokenWhitelisted(address indexed token, bool status);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event BlockedVerdictsUpdated(uint8 oldMask, uint8 newMask);

    // ──────────────────── Modifiers ────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // ──────────────────── Constructor ────────────────────

    constructor(
        address acpContract_,
        address oracle_,
        uint8 blockedVerdicts_,
        address owner_
    ) BaseACPHook(acpContract_) {
        if (oracle_ == address(0)) revert ZeroAddress();
        if (owner_ == address(0)) revert ZeroAddress();
        oracle = ITokenSafetyOracle(oracle_);
        blockedVerdicts = blockedVerdicts_ > 0 ? blockedVerdicts_ : DEFAULT_BLOCKED_VERDICTS;
        owner = owner_;
    }

    // ──────────────────── Hook: _preFund ────────────────────

    /// @dev Read paymentToken from job state, check via oracle.
    function _preFund(
        uint256 jobId,
        address,
        bytes memory
    ) internal override {
        address token = AgenticCommerce(acpContract).getJob(jobId).paymentToken;

        // No token set yet (budget not configured) — skip
        if (token == address(0)) return;

        // Whitelisted tokens bypass oracle
        if (whitelisted[token]) {
            emit TokenChecked(jobId, token, 0, true);
            return;
        }

        // Query oracle
        ITokenSafetyOracle.TokenSafetyData memory data = oracle.getTokenSafety(token);
        uint8 v = uint8(data.verdict);
        bool blocked = (blockedVerdicts & (1 << v)) != 0;

        emit TokenChecked(jobId, token, v, !blocked);

        if (blocked) revert UnsafeToken(token, v);
    }

    // ──────────────────── Admin ────────────────────

    function setWhitelisted(address token, bool status) external onlyOwner {
        whitelisted[token] = status;
        emit TokenWhitelisted(token, status);
    }

    function setWhitelistedBatch(address[] calldata tokens, bool status) external onlyOwner {
        for (uint256 i; i < tokens.length; ) {
            whitelisted[tokens[i]] = status;
            emit TokenWhitelisted(tokens[i], status);
            unchecked { ++i; }
        }
    }

    function setOracle(address oracle_) external onlyOwner {
        if (oracle_ == address(0)) revert ZeroAddress();
        address old = address(oracle);
        oracle = ITokenSafetyOracle(oracle_);
        emit OracleUpdated(old, oracle_);
    }

    function setBlockedVerdicts(uint8 mask) external onlyOwner {
        uint8 old = blockedVerdicts;
        blockedVerdicts = mask;
        emit BlockedVerdictsUpdated(old, mask);
    }

    // ──────────────────── Views ────────────────────

    function isVerdictBlocked(uint8 verdict) external view returns (bool) {
        return (blockedVerdicts & (1 << verdict)) != 0;
    }
}
