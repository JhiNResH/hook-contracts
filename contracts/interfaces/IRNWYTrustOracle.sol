// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IRNWYTrustOracle
/// @notice Interface for agent-identity-based trust oracles.
/// @dev Lookup key is (agentId, chainId, registry) — supports multi-chain,
///      multi-registry agent identity resolution.
///      Reference implementation deployed on Base mainnet:
///      https://basescan.org/address/0xD5fdccD492bB5568bC7aeB1f1E888e0BbA6276f4
interface IRNWYTrustOracle {

    /// @notice Returns the full trust record for an agent.
    /// @param agentId  Agent ID within the registry
    /// @param chainId  Chain where the agent is registered (e.g., 8453 for Base)
    /// @param registry Registry identifier (e.g., "erc8004", "olas")
    function getScore(
        uint256 agentId,
        uint256 chainId,
        string calldata registry
    ) external view returns (
        uint8  score,
        uint8  tier,
        uint8  sybilSeverity,
        uint40 updatedAt
    );

    /// @notice Returns true if the agent has a recorded trust score.
    function hasScore(
        uint256 agentId,
        uint256 chainId,
        string calldata registry
    ) external view returns (bool);

    /// @notice Returns true if the agent's trust score meets or exceeds the threshold.
    function meetsThreshold(
        uint256 agentId,
        uint256 chainId,
        string calldata registry,
        uint8 threshold
    ) external view returns (bool);

    /// @notice Returns the total number of agents with recorded scores.
    function agentCount() external view returns (uint256);
}
