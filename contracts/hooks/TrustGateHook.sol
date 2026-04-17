// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseERC8183Hook.sol";
import "../interfaces/IRNWYTrustOracle.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title TrustGateHook
 * @notice IACPHook that gates ERC-8183 job lifecycle by on-chain trust score.
 *
 * @dev Inherits BaseERC8183Hook for correct selector routing, data decoding,
 *      and onlyERC8183 caller authentication. Reads from any oracle implementing
 *      IRNWYTrustOracle — an agent-identity-based trust interface using
 *      (agentId, chainId, registry) lookups across multiple chains and registries.
 *
 *      Reference implementation: RNWY Trust Oracle on Base mainnet
 *      (138,000+ agent scores covering ERC-8004, Olas, and Virtuals).
 *
 * Hook points:
 *   - _preFund(fund)      → Check client trust, revert if below threshold
 *   - _preSubmit(submit)  → Check provider trust, revert if below threshold
 *   - _postComplete       → Emit outcome event
 *   - _postReject         → Emit outcome event
 *
 * The hook maps wallet addresses to agent IDs via a registry managed by the
 * hook owner. The oracle does all scoring — the hook is a gate, not a judge.
 */
contract TrustGateHook is BaseERC8183Hook, Ownable {
    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    IRNWYTrustOracle public oracle;
    uint8 public threshold;
    uint256 public defaultChainId;
    string public defaultRegistry;

    /// @notice Wallet address → agent ID
    mapping(address => uint256) public agentIds;

    /// @notice Tracks which wallets have been explicitly registered.
    /// @dev Separate from agentIds so that agentId = 0 is a valid registered value.
    mapping(address => bool) public registered;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event AgentIdSet(address indexed wallet, uint256 agentId);
    event ThresholdUpdated(uint8 oldThreshold, uint8 newThreshold);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event TrustGated(uint256 indexed jobId, address indexed agent, uint256 agentId, bool allowed);
    event OutcomeRecorded(uint256 indexed jobId, bool completed);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error TrustGateHook__NoAgentId(address agent);
    error TrustGateHook__BelowThreshold(uint256 jobId, address agent, uint256 agentId, uint8 threshold);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param erc8183Contract_ Address of the ERC-8183 core (AgenticCommerce) or MultiHookRouter
     * @param oracle_          Address of any IRNWYTrustOracle implementation
     * @param threshold_       Minimum trust score (0-95) to pass the gate
     * @param chainId_         Default chain ID for oracle lookups (e.g., 8453 for Base)
     * @param registry_        Default registry for oracle lookups (e.g., "erc8004")
     */
    constructor(
        address erc8183Contract_,
        address oracle_,
        uint8 threshold_,
        uint256 chainId_,
        string memory registry_
    ) BaseERC8183Hook(erc8183Contract_) Ownable(msg.sender) {
        require(oracle_ != address(0), "TrustGateHook: zero oracle");
        oracle = IRNWYTrustOracle(oracle_);
        threshold = threshold_;
        defaultChainId = chainId_;
        defaultRegistry = registry_;
    }

    /*//////////////////////////////////////////////////////////////
                    BaseERC8183Hook overrides
    //////////////////////////////////////////////////////////////*/

    /// @dev Gates the fund transition by client trust score.
    function _preFund(
        uint256 jobId,
        address caller,
        bytes memory
    ) internal override {
        _checkTrust(jobId, caller);
    }

    /// @dev Gates the submit transition by provider trust score.
    function _preSubmit(
        uint256 jobId,
        address caller,
        bytes32,
        bytes memory
    ) internal override {
        _checkTrust(jobId, caller);
    }

    /// @dev Records completion outcome. Never reverts.
    function _postComplete(
        uint256 jobId,
        address,
        bytes32,
        bytes memory
    ) internal override {
        emit OutcomeRecorded(jobId, true);
    }

    /// @dev Records rejection outcome. Never reverts.
    function _postReject(
        uint256 jobId,
        address,
        bytes32,
        bytes memory
    ) internal override {
        emit OutcomeRecorded(jobId, false);
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a wallet → agent ID mapping.
    function setAgentId(address wallet, uint256 agentId) external onlyOwner {
        agentIds[wallet] = agentId;
        registered[wallet] = true;
        emit AgentIdSet(wallet, agentId);
    }

    /// @notice Batch-register wallet → agent ID mappings.
    function setAgentIds(address[] calldata wallets, uint256[] calldata ids) external onlyOwner {
        require(wallets.length == ids.length, "TrustGateHook: array length mismatch");
        for (uint256 i = 0; i < wallets.length; i++) {
            agentIds[wallets[i]] = ids[i];
            registered[wallets[i]] = true;
            emit AgentIdSet(wallets[i], ids[i]);
        }
    }

    /// @notice Update the minimum trust score threshold.
    function setThreshold(uint8 threshold_) external onlyOwner {
        emit ThresholdUpdated(threshold, threshold_);
        threshold = threshold_;
    }

    /// @notice Update the oracle address (must implement IRNWYTrustOracle).
    function setOracle(address oracle_) external onlyOwner {
        require(oracle_ != address(0), "TrustGateHook: zero oracle");
        emit OracleUpdated(address(oracle), oracle_);
        oracle = IRNWYTrustOracle(oracle_);
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL
    //////////////////////////////////////////////////////////////*/

    function _checkTrust(uint256 jobId, address agent) internal {
        if (!registered[agent]) revert TrustGateHook__NoAgentId(agent);

        uint256 agentId = agentIds[agent];
        bool passes = oracle.meetsThreshold(agentId, defaultChainId, defaultRegistry, threshold);

        if (!passes) {
            emit TrustGated(jobId, agent, agentId, false);
            revert TrustGateHook__BelowThreshold(jobId, agent, agentId, threshold);
        }

        emit TrustGated(jobId, agent, agentId, true);
    }
}
