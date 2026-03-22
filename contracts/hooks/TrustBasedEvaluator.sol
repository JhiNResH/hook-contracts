// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ITrustOracle} from "../interfaces/ITrustOracle.sol";

/**
 * @title TrustBasedEvaluator
 * @notice Example evaluator that uses an external trust oracle to verify
 *         job deliverables. Demonstrates how to build an ERC-8183 evaluator
 *         that goes beyond simple approve/reject.
 *
 * @dev This is a REFERENCE IMPLEMENTATION — adapt for your use case.
 *
 * Pattern:
 *   1. Provider submits deliverable
 *   2. AgenticCommerce calls evaluator.evaluate(jobId) (or off-chain keeper)
 *   3. Evaluator checks provider trust score from oracle
 *   4. Returns complete() or reject() to AgenticCommerce
 *   5. Calls registry.recordOutcome() to update on-chain performance stats
 *
 * Trust oracle interface:
 *   getUserData(address) → { reputationScore, initialized, ... }
 *
 * @custom:security-contact security@maiat.io
 */

/// @notice Minimal AgenticCommerce interface for evaluation
interface IAgenticCommerce {
    enum JobStatus { Open, Funded, Submitted, Completed, Rejected, Expired }

    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        string description;
        uint256 budget;
        uint256 expiredAt;
        JobStatus status;
        address hook;
    }

    function getJob(uint256 jobId) external view returns (Job memory);
    function complete(uint256 jobId, bytes32 reason, bytes calldata optParams) external;
    function reject(uint256 jobId, bytes32 reason, bytes calldata optParams) external;
}

/// @notice EvaluatorRegistry interface — only the methods we need for the feedback loop
interface IEvaluatorRegistry {
    function recordOutcome(address evaluator, bool approved) external;
}

contract TrustBasedEvaluator is OwnableUpgradeable, ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum valid trust score from oracle
    uint256 public constant MAX_TRUST_SCORE = 100;

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    ITrustOracle public oracle;
    IAgenticCommerce public agenticCommerce;

    /// @notice Optional EvaluatorRegistry for on-chain performance feedback loop.
    IEvaluatorRegistry public registry;

    /// @notice Minimum trust score (0-100) to auto-approve
    uint256 public minTrustScore;

    /// @notice Tracks evaluated jobs to prevent double-evaluation
    mapping(uint256 => bool) public evaluated;

    /// @notice Stats
    uint256 public totalEvaluated;
    uint256 public totalApproved;
    uint256 public totalRejected;

    /// @dev Reserved storage gap for future upgrades
    uint256[40] private __gap;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event JobEvaluated(
        uint256 indexed jobId,
        address indexed provider,
        bool approved,
        uint256 trustScore,
        bytes32 reason
    );
    event RegistryUpdated(address indexed oldRegistry, address indexed newRegistry);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event AgenticCommerceUpdated(address indexed oldAC, address indexed newAC);
    event MinTrustScoreUpdated(uint256 oldScore, uint256 newScore);
    event OutcomeReportFailed(address indexed registry, bytes reason);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error TrustBasedEvaluator__AlreadyEvaluated(uint256 jobId);
    error TrustBasedEvaluator__NotSubmitted(uint256 jobId);
    error TrustBasedEvaluator__NotAssignedEvaluator(uint256 jobId);
    error TrustBasedEvaluator__ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZER
    //////////////////////////////////////////////////////////////*/

    function initialize(
        address oracle_,
        address agenticCommerce_,
        uint256 minTrustScore_,
        address owner_
    ) external initializer {
        if (oracle_ == address(0)) revert TrustBasedEvaluator__ZeroAddress();
        if (agenticCommerce_ == address(0)) revert TrustBasedEvaluator__ZeroAddress();

        __Ownable_init(owner_);
        oracle = ITrustOracle(oracle_);
        agenticCommerce = IAgenticCommerce(agenticCommerce_);
        minTrustScore = minTrustScore_;
    }

    /*//////////////////////////////////////////////////////////////
                        CORE: EVALUATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Evaluate a submitted job. Called by anyone (typically off-chain keeper).
     * @param jobId The job to evaluate
     *
     * Flow:
     *   1. Verify job is in Submitted status
     *   2. Verify this contract is the assigned evaluator
     *   3. Check provider trust score
     *   4. Auto-approve if score >= minTrustScore, reject otherwise
     *   5. Record outcome to EvaluatorRegistry (feedback loop)
     *   6. Call complete() or reject() on AgenticCommerce
     */
    function evaluate(uint256 jobId) external nonReentrant {
        if (evaluated[jobId]) revert TrustBasedEvaluator__AlreadyEvaluated(jobId);

        IAgenticCommerce.Job memory job = agenticCommerce.getJob(jobId);

        if (job.status != IAgenticCommerce.JobStatus.Submitted) {
            revert TrustBasedEvaluator__NotSubmitted(jobId);
        }
        if (job.evaluator != address(this)) {
            revert TrustBasedEvaluator__NotAssignedEvaluator(jobId);
        }

        // CEI: all state changes before external calls
        evaluated[jobId] = true;
        totalEvaluated++;

        // Check provider trust
        ITrustOracle.UserReputation memory rep = oracle.getUserData(job.provider);
        uint256 score = rep.initialized ? rep.reputationScore : 0;
        // Sanity bound on oracle score
        if (score > MAX_TRUST_SCORE) score = MAX_TRUST_SCORE;

        bool approved = score >= minTrustScore;
        bytes32 reason = approved
            ? bytes32("trust_approved")
            : bytes32("trust_too_low");

        if (approved) {
            totalApproved++;
        } else {
            totalRejected++;
        }

        // Emit event BEFORE external calls (CEI)
        emit JobEvaluated(jobId, job.provider, approved, score, reason);

        // Report outcome to registry BEFORE AC call (CEI)
        _reportOutcomeToRegistry(approved);

        // External calls last
        if (approved) {
            agenticCommerce.complete(jobId, reason, "");
        } else {
            agenticCommerce.reject(jobId, reason, "");
        }
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN
    //////////////////////////////////////////////////////////////*/

    function setRegistry(address registry_) external onlyOwner {
        address old = address(registry);
        registry = IEvaluatorRegistry(registry_);
        emit RegistryUpdated(old, registry_);
    }

    function setMinTrustScore(uint256 score) external onlyOwner {
        uint256 old = minTrustScore;
        minTrustScore = score;
        emit MinTrustScoreUpdated(old, score);
    }

    function setOracle(address oracle_) external onlyOwner {
        if (oracle_ == address(0)) revert TrustBasedEvaluator__ZeroAddress();
        address old = address(oracle);
        oracle = ITrustOracle(oracle_);
        emit OracleUpdated(old, oracle_);
    }

    function setAgenticCommerce(address agenticCommerce_) external onlyOwner {
        if (agenticCommerce_ == address(0)) revert TrustBasedEvaluator__ZeroAddress();
        address old = address(agenticCommerce);
        agenticCommerce = IAgenticCommerce(agenticCommerce_);
        emit AgenticCommerceUpdated(old, agenticCommerce_);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL
    //////////////////////////////////////////////////////////////*/

    function _reportOutcomeToRegistry(bool approved) internal {
        IEvaluatorRegistry reg = registry;
        if (address(reg) == address(0)) return;

        try reg.recordOutcome(address(this), approved) {
            // success
        } catch (bytes memory reason) {
            emit OutcomeReportFailed(address(reg), reason);
        }
    }
}
