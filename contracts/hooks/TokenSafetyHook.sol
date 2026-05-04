// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";
import "@erc8183/AgenticCommerce.sol";

/// @title ITokenSafetyOracle
/// @notice Minimal interface for querying ERC-20 token safety verdicts.
interface ITokenSafetyOracle {
    /// @dev Safe(0), Honeypot(1), HighTax(2), Unverified(3), Blocked(4)
    enum TokenVerdict {
        Safe,
        Honeypot,
        HighTax,
        Unverified,
        Blocked
    }

    struct TokenSafetyData {
        TokenVerdict verdict;
        uint256 buyTax;
        uint256 sellTax;
        bool verified;
        uint256 lastUpdated;
    }

    function getTokenSafety(address token) external view returns (TokenSafetyData memory data);
}

/// @title TokenSafetyHook
/// @notice Blocks job funding when the payment token is flagged as unsafe
///         by an external oracle. Standalone policy hook - no router or
///         attestation dependencies.
///
/// @dev Inherits BaseERC8183Hook; only overrides `_preFund`.
///      Reads `paymentToken` from `getJob(jobId)` - never decodes it from
///      hook callback data.
///
///      Token check flow:
///        1. fund(jobId, ...) triggers beforeAction -> _preFund
///        2. Read job.paymentToken from AgenticCommerce
///        3. If whitelisted -> pass
///        4. Else query oracle -> if verdict is blocked -> revert
///
///      Use case: protect job clients and providers from unsafe ERC-20 payment
///      tokens before funds enter the escrow lifecycle. When used with
///      MultiHookRouter, configure this hook for the fund selector.
///
/// @custom:security-contact security@erc-8183.org
contract TokenSafetyHook is BaseERC8183Hook, IERC8183HookMetadata {
    // --- Storage -------------------------------------------------------------

    bytes4 private constant SEL_FUND =
        bytes4(keccak256("fund(uint256,uint256,bytes)"));

    /// @notice Token safety oracle
    ITokenSafetyOracle public oracle;

    /// @notice Bitmask of verdicts to block (bit N = block verdict N)
    uint8 public blockedVerdicts;

    /// @notice Whitelisted tokens bypass oracle checks
    mapping(address => bool) public whitelisted;

    /// @notice Contract owner for admin functions
    address public owner;

    // --- Constants -----------------------------------------------------------

    /// @dev Default blocked: Honeypot(1) | HighTax(2) | Blocked(4) = 0b10110 = 22
    uint8 public constant DEFAULT_BLOCKED_VERDICTS = (1 << 1) | (1 << 2) | (1 << 4);

    // --- Errors --------------------------------------------------------------

    error UnsafeToken(address token, uint8 verdict);
    error ZeroAddress();
    error OnlyOwner();

    // --- Events --------------------------------------------------------------

    event TokenChecked(uint256 indexed jobId, address indexed token, uint8 verdict, bool allowed);
    event TokenWhitelisted(address indexed token, bool status);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event BlockedVerdictsUpdated(uint8 oldMask, uint8 newMask);

    // --- Modifiers -----------------------------------------------------------

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // --- Constructor ---------------------------------------------------------

    constructor(
        address erc8183Contract_,
        address oracle_,
        uint8 blockedVerdicts_,
        address owner_
    ) BaseERC8183Hook(erc8183Contract_) {
        if (oracle_ == address(0)) revert ZeroAddress();
        if (owner_ == address(0)) revert ZeroAddress();
        oracle = ITokenSafetyOracle(oracle_);
        blockedVerdicts = blockedVerdicts_ > 0 ? blockedVerdicts_ : DEFAULT_BLOCKED_VERDICTS;
        owner = owner_;
    }

    // --- Hook: _preFund ------------------------------------------------------

    /// @dev Read paymentToken from job state, check via oracle.
    function _preFund(
        uint256 jobId,
        address,
        bytes memory
    ) internal override {
        address token = AgenticCommerce(erc8183Contract).getJob(jobId).paymentToken;

        // No token set yet (budget not configured) - skip
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

    // --- Admin ---------------------------------------------------------------

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

    // --- Views ---------------------------------------------------------------

    function isVerdictBlocked(uint8 verdict) external view returns (bool) {
        return (blockedVerdicts & (1 << verdict)) != 0;
    }

    // --- IERC8183HookMetadata -----------------------------------------------

    function requiredSelectors() external pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](1);
        selectors[0] = SEL_FUND;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(BaseERC8183Hook) returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
