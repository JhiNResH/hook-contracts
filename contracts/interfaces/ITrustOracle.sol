// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ITrustOracle
/// @notice Vendor-neutral trust oracle interface for ERC-8183 hooks and evaluators.
/// @dev Any trust provider can implement this interface. See providers/ for
///      reference implementations.
interface ITrustOracle {
    /// @notice Get the trust score for a user.
    /// @param user The address to query
    /// @return score Trust score in range [0, 100]. Returns 0 for unknown users.
    function getTrustScore(address user) external view returns (uint256 score);
}
