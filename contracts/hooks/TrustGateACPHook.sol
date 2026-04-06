// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IACPHook} from "../IACPHook.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ITrustOracle} from "../interfaces/ITrustOracle.sol";

/**
 * @title TrustGateACPHook
 * @notice Gates job funding and submission behind configurable trust-score
 *         thresholds, with value-tiered requirements for high-stakes jobs.
 *
 * USE CASE
 * --------
 * A marketplace wants to ensure that only sufficiently-trusted participants
 * can transact. Low-trust clients should not be able to fund jobs, and
 * low-trust providers should not be able to submit deliverables. For
 * high-value jobs the required trust score automatically increases, so the
 * safety bar scales with financial risk.
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this)
 *  2. fund(jobId, optParams)
 *     → _preFund (via beforeAction): query oracle for client trust score,
 *       compute value-aware threshold from _effectiveThreshold(), revert
 *       with InsufficientTrust if score < threshold.
 *  3. submit(jobId, deliverable, optParams)
 *     → _preSubmit (via beforeAction): query oracle for provider trust
 *       score, compute threshold, revert if score < threshold.
 *  4. complete(jobId, reason, optParams)
 *     → _postComplete (via afterAction): emit OutcomeRecorded(jobId, true).
 *  5. reject(jobId, reason, optParams)
 *     → _postReject (via afterAction): emit OutcomeRecorded(jobId, false).
 *
 * TRUST MODEL
 * -----------
 * Trust scores are read from an immutable ITrustOracle reference set at
 * initialisation. The owner can adjust baseline thresholds and per-value
 * tiers at any time, but cannot retroactively alter scores. afterAction
 * callbacks never revert so that legitimate state changes are never
 * blocked by hook side-effects.
 *
 */

contract TrustGateACPHook is IACPHook, OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                            TYPES
    //////////////////////////////////////////////////////////////*/

    struct Tier {
        uint256 minValue;
        uint256 requiredScore;
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Maximum number of tiers to prevent unbounded growth
    uint256 public constant MAX_TIERS = 20;

    /// @notice Maximum valid trust score from oracle
    uint256 public constant MAX_TRUST_SCORE = 100;

    /// @dev Well-known selectors from AgenticCommerce
    bytes4 public constant FUND_SEL     = bytes4(keccak256("fund(uint256,bytes)"));
    bytes4 public constant SUBMIT_SEL   = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 public constant COMPLETE_SEL = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 public constant REJECT_SEL   = bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    ITrustOracle public oracle;

    /// @notice AgenticCommerce contract — used for job budget lookup and access control
    address public agenticCommerce;

    /// @notice Baseline trust score for clients (no job-value override)
    uint256 public clientThreshold;

    /// @notice Baseline trust score for providers (no job-value override)
    uint256 public providerThreshold;

    /// @notice Sorted tiers (ascending by minValue). Higher tiers override lower ones.
    Tier[] private _tiers;

    /// @dev Reserved storage gap for future upgrades
    uint256[44] private __gap;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event TrustGated(uint256 indexed jobId, address indexed agent, uint256 score, bool allowed);
    event OutcomeRecorded(uint256 indexed jobId, bool completed);
    event TierSet(uint256 minValue, uint256 requiredScore);
    event TierRemoved(uint256 minValue);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event AgenticCommerceUpdated(address indexed oldAC, address indexed newAC);
    event ThresholdsUpdated(uint256 clientThreshold, uint256 providerThreshold);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error TrustGateACPHook__TrustTooLow(uint256 jobId, address agent, uint256 score, uint256 threshold);
    error TrustGateACPHook__ZeroAddress();
    error TrustGateACPHook__OnlyAgenticCommerce();
    error TrustGateACPHook__MaxTiersReached();
    error TrustGateACPHook__TierNotFound(uint256 minValue);

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
        uint256 clientThreshold_,
        uint256 providerThreshold_,
        address owner_
    ) external initializer {
        if (oracle_ == address(0)) revert TrustGateACPHook__ZeroAddress();
        if (agenticCommerce_ == address(0)) revert TrustGateACPHook__ZeroAddress();

        __Ownable_init(owner_);
        oracle = ITrustOracle(oracle_);
        agenticCommerce = agenticCommerce_;
        clientThreshold = clientThreshold_;
        providerThreshold = providerThreshold_;
    }

    /*//////////////////////////////////////////////////////////////
                    IACPHook: beforeAction
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called before state transitions. Reverts to block.
     * @dev Only callable by AgenticCommerce.
     */
    function beforeAction(uint256 jobId, bytes4 selector, bytes calldata data) external override {
        if (msg.sender != agenticCommerce) revert TrustGateACPHook__OnlyAgenticCommerce();

        if (selector == FUND_SEL) {
            (address caller,) = abi.decode(data, (address, bytes));
            if (caller == address(0)) return; // Skip trust check for zero address
            uint256 threshold = _effectiveThreshold(jobId, clientThreshold);
            _checkTrust(jobId, caller, threshold);
        } else if (selector == SUBMIT_SEL) {
            (address caller,,) = abi.decode(data, (address, bytes32, bytes));
            if (caller == address(0)) return;
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
     * @dev Only callable by AgenticCommerce.
     */
    function afterAction(uint256 jobId, bytes4 selector, bytes calldata) external override {
        if (msg.sender != agenticCommerce) revert TrustGateACPHook__OnlyAgenticCommerce();

        if (selector == COMPLETE_SEL) {
            emit OutcomeRecorded(jobId, true);
        } else if (selector == REJECT_SEL) {
            emit OutcomeRecorded(jobId, false);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ERC-165
    //////////////////////////////////////////////////////////////*/

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IACPHook).interfaceId
            || interfaceId == 0x01ffc9a7; // IERC165
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN
    //////////////////////////////////////////////////////////////*/

    function setThresholds(uint256 client_, uint256 provider_) external onlyOwner {
        clientThreshold = client_;
        providerThreshold = provider_;
        emit ThresholdsUpdated(client_, provider_);
    }

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

        // New tier — check max
        if (len >= MAX_TIERS) revert TrustGateACPHook__MaxTiersReached();

        // Insert new tier, keeping the array sorted ascending by minValue
        _tiers.push(Tier(minValue, requiredScore));
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
     * @notice Remove a tier by its minValue.
     * @param minValue The minValue of the tier to remove
     */
    function removeTier(uint256 minValue) external onlyOwner {
        uint256 len = _tiers.length;
        for (uint256 i = 0; i < len; i++) {
            if (_tiers[i].minValue == minValue) {
                // Swap with last and pop
                if (i != len - 1) {
                    _tiers[i] = _tiers[len - 1];
                }
                _tiers.pop();

                // Re-sort if we swapped (maintain ascending order)
                if (i != len - 1 && _tiers.length > 1) {
                    _sortTiers();
                }

                emit TierRemoved(minValue);
                return;
            }
        }
        revert TrustGateACPHook__TierNotFound(minValue);
    }

    function setOracle(address oracle_) external onlyOwner {
        if (oracle_ == address(0)) revert TrustGateACPHook__ZeroAddress();
        address old = address(oracle);
        oracle = ITrustOracle(oracle_);
        emit OracleUpdated(old, oracle_);
    }

    function setAgenticCommerce(address agenticCommerce_) external onlyOwner {
        if (agenticCommerce_ == address(0)) revert TrustGateACPHook__ZeroAddress();
        address old = agenticCommerce;
        agenticCommerce = agenticCommerce_;
        emit AgenticCommerceUpdated(old, agenticCommerce_);
    }

    function getTiers() external view returns (Tier[] memory) {
        return _tiers;
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Read job budget from AgenticCommerce via staticcall + abi.decode
    function _effectiveThreshold(uint256 jobId, uint256 baseThreshold) internal view returns (uint256) {
        if (agenticCommerce == address(0)) return baseThreshold;
        if (_tiers.length == 0) return baseThreshold;

        uint256 budget;
        // Use low-level staticcall to avoid interface import dependency
        (bool success, bytes memory data) = agenticCommerce.staticcall(
            abi.encodeWithSignature("getJob(uint256)", jobId)
        );
        if (!success || data.length < 32) return baseThreshold;

        // Use abi.decode for safe extraction — handles dynamic types (string) correctly
        // Job struct: (uint256 id, address client, address provider, address evaluator,
        //              address hook, string description, uint256 budget, uint256 expiredAt, uint8 status)
        (,,,,,, budget,,) = abi.decode(
            data,
            (uint256, address, address, address, address, string, uint256, uint256, uint8)
        );

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
        uint256 score = oracle.getTrustScore(agent);
        // Sanity bound
        if (score > MAX_TRUST_SCORE) score = MAX_TRUST_SCORE;

        if (score < threshold) {
            emit TrustGated(jobId, agent, score, false);
            revert TrustGateACPHook__TrustTooLow(jobId, agent, score, threshold);
        }

        emit TrustGated(jobId, agent, score, true);
    }

    /// @dev Insertion sort for _tiers (max 20 elements, O(n²) is fine)
    function _sortTiers() internal {
        uint256 len = _tiers.length;
        for (uint256 i = 1; i < len; i++) {
            Tier memory key = _tiers[i];
            uint256 j = i;
            while (j > 0 && _tiers[j - 1].minValue > key.minValue) {
                _tiers[j] = _tiers[j - 1];
                j--;
            }
            _tiers[j] = key;
        }
    }
}
