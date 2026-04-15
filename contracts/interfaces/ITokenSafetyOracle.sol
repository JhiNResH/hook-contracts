// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ITokenSafetyOracle
/// @notice Minimal interface for querying ERC-20 token safety verdicts.
/// @dev Implement this to plug in any token safety provider (GoPlus,
///      De.Fi, custom). TokenSafetyHook queries this at fund-time.
/// @custom:security-contact security@erc-8183.org
interface ITokenSafetyOracle {
    /// @notice Token safety verdict
    /// @dev Safe(0), Honeypot(1), HighTax(2), Unverified(3), Blocked(4)
    enum TokenVerdict {
        Safe,
        Honeypot,
        HighTax,
        Unverified,
        Blocked
    }

    /// @notice Token safety data returned by oracle
    struct TokenSafetyData {
        TokenVerdict verdict;
        uint256 buyTax;      // basis points (10000 = 100%)
        uint256 sellTax;     // basis points (10000 = 100%)
        bool verified;
        uint256 lastUpdated;
    }

    /// @notice Get safety data for a token
    /// @param token The token address to check
    /// @return data The token safety data
    function getTokenSafety(address token) external view returns (TokenSafetyData memory data);
}
