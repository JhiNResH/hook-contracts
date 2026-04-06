// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ITrustOracle} from "../interfaces/ITrustOracle.sol";

/**
 * @title TrustBasedEvaluator
 * @notice Automatically approves or rejects job deliverables based on the
 *         provider's on-chain trust score, eliminating the need for a human
 *         arbitrator on routine jobs.
 *
 * USE CASE
 * --------
 * Many ACP jobs are low-value and routine. Requiring a human evaluator for
 * every outcome is slow and expensive. This evaluator delegates the
 * approve/reject decision to an external trust oracle: providers whose
 * score meets or exceeds a configurable threshold are automatically
 * completed; those below it are rejected. Outcomes are reported back to
 * EvaluatorRegistry so the evaluator's own performance is tracked.
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator=this, expiredAt, description, hook)
 *  2. fund(jobId, optParams) — job moves to Funded state.
 *  3. submit(jobId, deliverable, optParams) — job moves to Submitted state.
 *  4. evaluate(jobId) called by an off-chain keeper or any permissionless
 *     caller:
 *       a. Fetch job from AgenticCommerce; verify status == Submitted and
 *          evaluator == address(this).
 *       b. Query oracle.getUserData(provider) for reputationScore.
 *       c. If score >= minTrustScore → agenticCommerce.complete(jobId, ...)
 *          else → agenticCommerce.reject(jobId, ...)
 *       d. Call registry.recordOutcome(address(this), approved) to update
 *          this evaluator's on-chain performance stats.
 *
 * TRUST MODEL
 * -----------
 * The trust score is read from an immutable oracle reference. The owner
 * controls minTrustScore and oracle address but cannot retroactively
 * change provider scores. Each jobId can only be evaluated once (CEI
 * pattern with evaluated[jobId] guard). External calls to AgenticCommerce
 * and EvaluatorRegistry happen last, after all state changes.
 *
 */

/// @notice Minimal AgenticCommerce interface for evaluation
interface IAgenticCommerce {
    enum JobStatus { Open, Funded, Submitted, Completed, Rejected, Expired }

    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        address hook;        // must match AgenticCommerceHooked.Job field order
        string description;
        uint256 budget;
        uint256 expiredAt;
        JobStatus status;
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

        // Check provider trust via vendor-neutral ITrustOracle
        uint256 score = oracle.getTrustScore(job.provider);
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
