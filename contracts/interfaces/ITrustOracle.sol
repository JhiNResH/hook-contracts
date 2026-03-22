// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ITrustOracle
/// @notice Minimal trust oracle interface for ERC-8183 trust-based hooks and evaluators.
/// @dev Shared interface — do not duplicate in individual contracts.
interface ITrustOracle {
    struct UserReputation {
        uint256 reputationScore;
        uint256 totalReviews;
        bool initialized;
        uint256 lastUpdated;
    }

    function getUserData(address user) external view returns (UserReputation memory);
}
