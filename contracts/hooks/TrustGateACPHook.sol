// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../IACPHook.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title TrustGateACPHook
 * @notice IACPHook implementation that gates job lifecycle based on trust scores.
 *         Demonstrates how hooks can enforce pre-conditions and record outcomes.
 *
 * @dev This is a REFERENCE IMPLEMENTATION for the ERC-8183 hook system.
 *
 * Hook points:
 *   - beforeAction(fund)    → Check client trust score (with job-value-aware threshold)
 *   - beforeAction(submit)  → Check provider trust score (with job-value-aware threshold)
 *   - afterAction(complete) → Record positive outcome event
 *   - afterAction(reject)   → Record negative outcome event
 *
 * Revert in beforeAction to block the transition.
 * afterAction should NOT revert (would block legitimate state changes).
 *
 * v1.1 additions:
 *   - Dynamic threshold by job value via a configurable tier system.
 *     Higher-value jobs require a higher trust score from participants.
 *     Tiers are defined by (minValue, requiredScore) pairs; the highest
 *     matching tier wins.
 */

/// @notice Minimal trust oracle interface
interface ITrustOracle {
    struct UserReputation {
        uint256 reputationScore;
        bool initialized;
    }
    function getUserData(address user) external view returns (UserReputation memory);
}

/// @notice Minimal AgenticCommerce interface — enough to read job budget
interface IAgenticCommerce {
    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        address hook;
        string description;
        uint256 budget;
        uint256 expiredAt;
        uint8 status;
    }
    function getJob(uint256 jobId) external view returns (Job memory);
}

contract TrustGateACPHook is IACPHook, OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                            TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice A value tier: jobs with budget >= minValue require >= requiredScore
    struct Tier {
        uint256 minValue;       // minimum job budget (in payment token base units)
        uint256 requiredScore;  // minimum trust score for this tier
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    ITrustOracle public oracle;
    IAgenticCommerce public agenticCommerce;

    /// @notice Baseline trust score for clients (no job-value override)
    uint256 public clientThreshold;

    /// @notice Baseline trust score for providers (no job-value override)
    uint256 public providerThreshold;

    /// @notice Sorted tiers (ascending by minValue). Higher tiers override lower ones.
    Tier[] private _tiers;

    /// @dev Well-known selectors from AgenticCommerce
    bytes4 public constant FUND_SEL     = bytes4(keccak256("fund(uint256,bytes)"));
    bytes4 public constant SUBMIT_SEL   = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 public constant COMPLETE_SEL = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 public constant REJECT_SEL   = bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event TrustGated(uint256 indexed jobId, address indexed agent, uint256 score, bool allowed);
    event OutcomeRecorded(uint256 indexed jobId, bool completed);
    event TierSet(uint256 minValue, uint256 requiredScore);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error TrustGateACPHook__TrustTooLow(uint256 jobId, address agent, uint256 score, uint256 threshold);

    /*//////////////////////////////////////////////////////////////
                            INITIALIZER
    //////////////////////////////////////////////////////////////*/

    function initialize(
        address oracle_,
        address agenticCommerce_,
        uint256 clientThreshold_,
        uint256 providerThreshold_,
        address owner_
    ) external initializer {
        __Ownable_init(owner_);
        oracle = ITrustOracle(oracle_);
        agenticCommerce = IAgenticCommerce(agenticCommerce_);
        clientThreshold = clientThreshold_;
        providerThreshold = providerThreshold_;
    }

    /*//////////////////////////////////////////////////////////////
                    IACPHook: beforeAction
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called before state transitions. Reverts to block.
     * @dev Reads job budget to apply dynamic tier-based threshold overrides.
     *      Falls back to baseline threshold if agenticCommerce is not set or
     *      if the job cannot be looked up (graceful degradation).
     */
    function beforeAction(uint256 jobId, bytes4 selector, bytes calldata data) external override {
        if (selector == FUND_SEL) {
            // data = abi.encode(caller, optParams)
            (address caller,) = abi.decode(data, (address, bytes));
            uint256 threshold = _effectiveThreshold(jobId, clientThreshold);
            _checkTrust(jobId, caller, threshold);
        } else if (selector == SUBMIT_SEL) {
            // data = abi.encode(caller, reason, optParams)
            (address caller,,) = abi.decode(data, (address, bytes32, bytes));
            uint256 threshold = _effectiveThreshold(jobId, providerThreshold);
            _checkTrust(jobId, caller, threshold);
        }
        // Other selectors: pass through
    }

    /*//////////////////////////////////////////////////////////////
                    IACPHook: afterAction
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called after state transitions. Records outcomes (never reverts).
     */
    function afterAction(uint256 jobId, bytes4 selector, bytes calldata) external override {
        if (selector == COMPLETE_SEL) {
            emit OutcomeRecorded(jobId, true);
        } else if (selector == REJECT_SEL) {
            emit OutcomeRecorded(jobId, false);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-165
    //////////////////////////////////////////////////////////////*/

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IACPHook).interfaceId
            || interfaceId == 0x01ffc9a7; // IERC165
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set baseline thresholds for clients and providers.
     * @param client_   Baseline minimum trust score for clients
     * @param provider_ Baseline minimum trust score for providers
     */
    function setThresholds(uint256 client_, uint256 provider_) external onlyOwner {
        clientThreshold = client_;
        providerThreshold = provider_;
    }

    /**
     * @notice Add or update a value-based tier threshold.
     * @dev Jobs with budget >= minValue will require at least requiredScore trust.
     *      Multiple tiers can be set; the highest matching minValue wins.
     *      To remove a tier, set requiredScore = 0 (effectively disables it).
     *
     * Example:
     *   setTierThreshold(1_000e6,  60)   // jobs ≥ $1k  → score ≥ 60
     *   setTierThreshold(10_000e6, 80)   // jobs ≥ $10k → score ≥ 80
     *   setTierThreshold(100_000e6, 95)  // jobs ≥ $100k → score ≥ 95
     *
     * @param minValue      Minimum job budget (inclusive) in payment token base units
     * @param requiredScore Minimum trust score for jobs at this value tier
     */
    function setTierThreshold(uint256 minValue, uint256 requiredScore) external onlyOwner {
        uint256 len = _tiers.length;

        // Update existing tier if minValue matches
        for (uint256 i = 0; i < len; i++) {
            if (_tiers[i].minValue == minValue) {
                _tiers[i].requiredScore = requiredScore;
                emit TierSet(minValue, requiredScore);
                return;
            }
        }

        // Insert new tier, keeping the array sorted ascending by minValue
        _tiers.push(Tier(minValue, requiredScore));
        // Bubble the new entry into the correct sorted position
        uint256 j = _tiers.length - 1;
        while (j > 0 && _tiers[j - 1].minValue > _tiers[j].minValue) {
            Tier memory tmp = _tiers[j - 1];
            _tiers[j - 1] = _tiers[j];
            _tiers[j] = tmp;
            j--;
        }

        emit TierSet(minValue, requiredScore);
    }

    /**
     * @notice Update oracle address.
     * @param oracle_ New trust oracle address
     */
    function setOracle(address oracle_) external onlyOwner {
        oracle = ITrustOracle(oracle_);
    }

    /**
     * @notice Update AgenticCommerce address (used to look up job budgets for tiers).
     * @param agenticCommerce_ New AgenticCommerce address
     */
    function setAgenticCommerce(address agenticCommerce_) external onlyOwner {
        agenticCommerce = IAgenticCommerce(agenticCommerce_);
    }

    /**
     * @notice Return the full list of configured value tiers (sorted ascending by minValue).
     */
    function getTiers() external view returns (Tier[] memory) {
        return _tiers;
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Look up the job budget and find the highest-matching tier threshold.
     *      If no tier matches or agenticCommerce is not set, returns the baseThreshold.
     *      Gracefully degrades on revert (e.g., invalid jobId).
     */
    function _effectiveThreshold(uint256 jobId, uint256 baseThreshold) internal view returns (uint256) {
        if (address(agenticCommerce) == address(0)) return baseThreshold;
        if (_tiers.length == 0) return baseThreshold;

        // Try to read budget. If it fails, fall back to base.
        uint256 budget;
        try agenticCommerce.getJob(jobId) returns (IAgenticCommerce.Job memory job) {
            budget = job.budget;
        } catch {
            return baseThreshold;
        }

        // Walk tiers in descending order — first match (highest qualifying tier) wins
        uint256 len = _tiers.length;
        uint256 result = baseThreshold;
        for (uint256 i = 0; i < len; i++) {
            if (budget >= _tiers[i].minValue && _tiers[i].requiredScore > result) {
                result = _tiers[i].requiredScore;
            }
        }
        return result;
    }

    function _checkTrust(uint256 jobId, address agent, uint256 threshold) internal {
        ITrustOracle.UserReputation memory rep = oracle.getUserData(agent);
        uint256 score = rep.initialized ? rep.reputationScore : 0;

        if (score < threshold) {
            emit TrustGated(jobId, agent, score, false);
            revert TrustGateACPHook__TrustTooLow(jobId, agent, score, threshold);
        }

        emit TrustGated(jobId, agent, score, true);
    }
}
