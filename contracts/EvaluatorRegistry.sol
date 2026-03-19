// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title EvaluatorRegistry
 * @notice v1.0 — Trust-ranked evaluator discovery for ERC-8183 AgenticCommerce.
 *
 * @dev Upgrades the original single-evaluator-per-domain registry to a multi-evaluator
 *      system with on-chain performance tracking and trust-ranked discovery.
 *
 *      This solves ACP's evaluator discovery gap: instead of hardcoding evaluator
 *      addresses (which enables wash trading), agents query this registry to discover
 *      the highest-performing evaluator for a given domain dynamically.
 *
 *      Key changes from v0:
 *        - Multiple evaluators per domain (list, not a single overwritten address)
 *        - Per-evaluator performance stats (totalJobs, totalApproved, totalRejected)
 *        - Trust-ranked queries: getEvaluators() returns sorted by success rate (desc)
 *        - Outcome recording: authorized callers update stats on-chain
 *        - Auto-delisting: evaluators below minSuccessRateBP are marked inactive
 *        - Pagination: list queries accept offset+limit to avoid unbounded loops
 *        - Backward compatible: getEvaluator(domain) still works, returns top-ranked
 *
 * Example flow:
 *   1. Maiat registers: registry.register("trust", 0xMaiat...)
 *   2. Client queries: registry.getEvaluator("trust") → top performer's address
 *   3. Job completes → authorized hook calls registry.recordOutcome(evaluator, true)
 *   4. Stats update → rankings adjust → ecosystem self-optimizes over time
 *
 * Domains are free-form strings (e.g., "trust", "code-review", "content-moderation").
 */
contract EvaluatorRegistry is OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                            TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice On-chain performance stats per evaluator (global, across all domains)
    struct EvaluatorStats {
        uint256 totalJobs;
        uint256 totalApproved;
        uint256 totalRejected;
        /// @dev false if below minSuccessRateBP after minJobsForThreshold; set true on register
        bool active;
    }

    /// @notice Return type for getEvaluators() — rich view of an evaluator's standing
    struct EvaluatorView {
        address evaluator;
        uint256 totalJobs;
        uint256 totalApproved;
        uint256 totalRejected;
        uint256 successRateBP; // 0-10000 basis points (10000 = 100%)
        string metadataURI;
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice domain → ordered list of evaluator addresses (including inactive)
    mapping(string => address[]) private _domainEvaluators;

    /// @notice evaluator → domain → 1-indexed position in _domainEvaluators[domain] (0 = not registered)
    mapping(address => mapping(string => uint256)) private _evalDomainIdx;

    /// @notice evaluator → performance stats (shared across all domains)
    mapping(address => EvaluatorStats) private _stats;

    /// @notice evaluator → metadata URI (e.g., IPFS docs, API endpoint)
    mapping(address => string) private _metadataURIs;

    /// @notice All registered domain names (for global enumeration)
    string[] private _domains;

    /// @notice domain → 1-indexed position in _domains (0 = not found)
    mapping(string => uint256) private _domainIndex;

    /// @notice Addresses authorized to call recordOutcome (hooks + AgenticCommerce)
    mapping(address => bool) private _authorized;

    /// @notice Minimum success rate (basis points, 0-10000) to remain listed
    /// @dev Only enforced after minJobsForThreshold jobs have been processed
    uint256 public minSuccessRateBP;

    /// @notice Minimum number of jobs before the performance threshold is enforced
    /// @dev New evaluators with few jobs get benefit-of-the-doubt
    uint256 public minJobsForThreshold;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event EvaluatorRegistered(string indexed domain, address indexed evaluator);
    event EvaluatorRemoved(string indexed domain, address indexed evaluator);
    event EvaluatorDelisted(address indexed evaluator, uint256 successRateBP, uint256 totalJobs);
    event OutcomeRecorded(address indexed evaluator, bool approved, uint256 totalJobs, uint256 successRateBP);
    event MetadataUpdated(address indexed evaluator, string uri);
    event AuthorizedSet(address indexed caller, bool authorized);
    event ThresholdUpdated(uint256 minSuccessRateBP, uint256 minJobsForThreshold);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error EvaluatorRegistry__ZeroAddress();
    error EvaluatorRegistry__EmptyDomain();
    error EvaluatorRegistry__DomainNotFound(string domain);
    error EvaluatorRegistry__AlreadyRegistered(string domain, address evaluator);
    error EvaluatorRegistry__NotRegistered(string domain, address evaluator);
    error EvaluatorRegistry__NotAuthorized();

    /*//////////////////////////////////////////////////////////////
                            INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @param owner_ Initial owner of the registry
     */
    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        minSuccessRateBP = 3000;  // 30% minimum success rate
        minJobsForThreshold = 10; // only enforce threshold after 10 jobs
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC: REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register an evaluator for a domain. Adds to the list — does NOT overwrite.
     * @dev Reverts if the evaluator is already registered for this domain.
     *      For truly new evaluators (no prior job history), sets active = true.
     *      For previously delisted evaluators, keeps them inactive — use reactivate().
     * @param domain Free-form domain string (e.g., "trust", "code-review")
     * @param evaluator Address of the evaluator contract
     */
    function register(string calldata domain, address evaluator) external onlyOwner {
        if (evaluator == address(0)) revert EvaluatorRegistry__ZeroAddress();
        if (bytes(domain).length == 0) revert EvaluatorRegistry__EmptyDomain();
        if (_evalDomainIdx[evaluator][domain] != 0) {
            revert EvaluatorRegistry__AlreadyRegistered(domain, evaluator);
        }

        // Track domain for global enumeration
        if (_domainIndex[domain] == 0) {
            _domains.push(domain);
            _domainIndex[domain] = _domains.length; // 1-indexed
        }

        // Add evaluator to domain list
        _domainEvaluators[domain].push(evaluator);
        _evalDomainIdx[evaluator][domain] = _domainEvaluators[domain].length; // 1-indexed

        // Activate brand-new evaluators (no job history). Preserve delist for returning ones.
        if (_stats[evaluator].totalJobs == 0) {
            _stats[evaluator].active = true;
        }

        emit EvaluatorRegistered(domain, evaluator);
    }

    /**
     * @notice Remove an evaluator from a specific domain.
     * @dev Stats are preserved even after removal (historical record).
     * @param domain Domain to remove from
     * @param evaluator Evaluator address to remove
     */
    function remove(string calldata domain, address evaluator) external onlyOwner {
        if (_evalDomainIdx[evaluator][domain] == 0) {
            revert EvaluatorRegistry__NotRegistered(domain, evaluator);
        }

        _removeFromDomain(domain, evaluator);
        emit EvaluatorRemoved(domain, evaluator);
    }

    /**
     * @notice Set metadata URI for an evaluator (e.g., IPFS docs, API endpoint).
     * @param evaluator Address of the evaluator
     * @param uri Metadata URI
     */
    function setMetadata(address evaluator, string calldata uri) external onlyOwner {
        if (evaluator == address(0)) revert EvaluatorRegistry__ZeroAddress();
        _metadataURIs[evaluator] = uri;
        emit MetadataUpdated(evaluator, uri);
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC: OUTCOME RECORDING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Record the outcome of an evaluation. Updates performance stats.
     * @dev Only callable by authorized addresses (hooks, AgenticCommerce).
     *
     *      If an evaluator's success rate drops below minSuccessRateBP after
     *      minJobsForThreshold jobs, they are automatically marked inactive
     *      (de-listed from all query results). An admin can reactivate() them.
     *
     * @param evaluator The evaluator whose outcome is being recorded
     * @param approved  true = job completed (positive outcome), false = rejected
     */
    function recordOutcome(address evaluator, bool approved) external {
        if (!_authorized[msg.sender]) revert EvaluatorRegistry__NotAuthorized();
        if (evaluator == address(0)) revert EvaluatorRegistry__ZeroAddress();

        EvaluatorStats storage stats = _stats[evaluator];
        stats.totalJobs++;
        if (approved) {
            stats.totalApproved++;
        } else {
            stats.totalRejected++;
        }

        uint256 rateBP = _successRateBP(stats.totalApproved, stats.totalJobs);

        // Auto-delist if below threshold — only enforced after minJobsForThreshold
        if (
            stats.active &&
            stats.totalJobs >= minJobsForThreshold &&
            rateBP < minSuccessRateBP
        ) {
            stats.active = false;
            emit EvaluatorDelisted(evaluator, rateBP, stats.totalJobs);
        }

        emit OutcomeRecorded(evaluator, approved, stats.totalJobs, rateBP);
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC: QUERIES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the top-ranked active evaluator for a domain.
     * @dev Backward-compatible convenience wrapper around getEvaluators().
     *      Returns address(0) if no active evaluator is registered.
     * @param domain Domain to query
     * @return evaluator Address of the best-performing active evaluator
     */
    function getEvaluator(string calldata domain) external view returns (address) {
        address[] storage list = _domainEvaluators[domain];
        uint256 len = list.length;
        if (len == 0) return address(0);

        address best = address(0);
        uint256 bestRate = 0;
        bool found = false;

        for (uint256 i = 0; i < len; i++) {
            address eval = list[i];
            EvaluatorStats storage stats = _stats[eval];
            if (!stats.active) continue;

            uint256 rate = _successRateBP(stats.totalApproved, stats.totalJobs);
            if (!found || rate > bestRate) {
                bestRate = rate;
                best = eval;
                found = true;
            }
        }

        return best;
    }

    /**
     * @notice Get paginated, trust-ranked list of active evaluators for a domain.
     * @dev Filters inactive evaluators, then sorts by success rate descending
     *      using insertion sort (O(n²) — suitable for domains with ≤ ~100 evaluators).
     *      Use offset+limit for pagination to avoid gas issues on large domains.
     *
     * @param domain Domain to query (e.g., "trust")
     * @param offset Starting index (0-based) into the sorted active list
     * @param limit  Maximum results to return (0 = all remaining after offset)
     * @return results Array of EvaluatorView structs, sorted by successRateBP desc
     */
    function getEvaluators(
        string calldata domain,
        uint256 offset,
        uint256 limit
    ) external view returns (EvaluatorView[] memory results) {
        address[] storage list = _domainEvaluators[domain];
        uint256 len = list.length;

        // Collect active evaluators into a memory array
        address[] memory active = new address[](len);
        uint256 activeCount = 0;
        for (uint256 i = 0; i < len; i++) {
            if (_stats[list[i]].active) {
                active[activeCount++] = list[i];
            }
        }

        // Insertion sort — descending by successRateBP
        for (uint256 i = 1; i < activeCount; i++) {
            address key = active[i];
            uint256 keyRate = _successRateBP(_stats[key].totalApproved, _stats[key].totalJobs);
            uint256 j = i;
            while (j > 0) {
                address prev = active[j - 1];
                uint256 prevRate = _successRateBP(_stats[prev].totalApproved, _stats[prev].totalJobs);
                if (prevRate >= keyRate) break; // prev is already higher-ranked
                active[j] = prev; // shift lower-ranked element right
                j--;
            }
            active[j] = key;
        }

        // Apply pagination
        if (offset >= activeCount) {
            return new EvaluatorView[](0);
        }
        uint256 end = (limit == 0 || offset + limit > activeCount) ? activeCount : offset + limit;
        uint256 resultCount = end - offset;

        results = new EvaluatorView[](resultCount);
        for (uint256 i = 0; i < resultCount; i++) {
            address eval = active[offset + i];
            EvaluatorStats storage stats = _stats[eval];
            results[i] = EvaluatorView({
                evaluator: eval,
                totalJobs: stats.totalJobs,
                totalApproved: stats.totalApproved,
                totalRejected: stats.totalRejected,
                successRateBP: _successRateBP(stats.totalApproved, stats.totalJobs),
                metadataURI: _metadataURIs[eval]
            });
        }
    }

    /**
     * @notice Total number of registered evaluators for a domain (including inactive).
     * @param domain Domain to query
     */
    function getEvaluatorCount(string calldata domain) external view returns (uint256) {
        return _domainEvaluators[domain].length;
    }

    /**
     * @notice Get raw performance stats for an evaluator.
     * @param evaluator Address to query
     */
    function getStats(address evaluator) external view returns (
        uint256 totalJobs,
        uint256 totalApproved,
        uint256 totalRejected,
        uint256 successRateBP,
        bool active
    ) {
        EvaluatorStats storage stats = _stats[evaluator];
        totalJobs      = stats.totalJobs;
        totalApproved  = stats.totalApproved;
        totalRejected  = stats.totalRejected;
        successRateBP  = _successRateBP(stats.totalApproved, stats.totalJobs);
        active         = stats.active;
    }

    /**
     * @notice Get metadata URI for an evaluator.
     * @param evaluator Address to query
     * @return uri Metadata URI (empty string if not set)
     */
    function getMetadata(address evaluator) external view returns (string memory) {
        return _metadataURIs[evaluator];
    }

    /**
     * @notice Get all registered domains (for off-chain enumeration).
     * @dev Not paginated — intended for off-chain use with a small domain set.
     */
    function getDomains() external view returns (string[] memory) {
        return _domains;
    }

    /**
     * @notice Total number of registered domains.
     */
    function domainCount() external view returns (uint256) {
        return _domains.length;
    }

    /**
     * @notice Check if an address is authorized to record outcomes.
     * @param caller Address to check
     */
    function isAuthorized(address caller) external view returns (bool) {
        return _authorized[caller];
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Authorize or deauthorize an address to call recordOutcome.
     * @dev Grant to AgenticCommerce and any trusted hook contracts.
     * @param caller Address to update
     * @param authorized Whether to grant or revoke authorization
     */
    function setAuthorized(address caller, bool authorized) external onlyOwner {
        if (caller == address(0)) revert EvaluatorRegistry__ZeroAddress();
        _authorized[caller] = authorized;
        emit AuthorizedSet(caller, authorized);
    }

    /**
     * @notice Update the minimum performance threshold for auto-delisting.
     * @param minSuccessRateBP_    Minimum success rate (basis points, 0-10000)
     * @param minJobsForThreshold_ Minimum jobs before threshold is enforced
     */
    function setThreshold(uint256 minSuccessRateBP_, uint256 minJobsForThreshold_) external onlyOwner {
        minSuccessRateBP = minSuccessRateBP_;
        minJobsForThreshold = minJobsForThreshold_;
        emit ThresholdUpdated(minSuccessRateBP_, minJobsForThreshold_);
    }

    /**
     * @notice Restore an evaluator's active status (admin override).
     * @dev Use after an evaluator has demonstrably improved or appealed delist.
     *      Stats are preserved — their history remains visible.
     * @param evaluator Address to reactivate
     */
    function reactivate(address evaluator) external onlyOwner {
        _stats[evaluator].active = true;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Remove an evaluator from a domain's list using swap-and-pop.
     */
    function _removeFromDomain(string memory domain, address evaluator) internal {
        address[] storage list = _domainEvaluators[domain];
        uint256 idxOneBased = _evalDomainIdx[evaluator][domain];
        uint256 idx = idxOneBased - 1; // 0-indexed
        uint256 lastIdx = list.length - 1;

        if (idx != lastIdx) {
            address last = list[lastIdx];
            list[idx] = last;
            _evalDomainIdx[last][domain] = idxOneBased; // update swapped element's index
        }

        list.pop();
        delete _evalDomainIdx[evaluator][domain];
    }

    /**
     * @dev Compute success rate in basis points (0-10000).
     *      Returns 10000 (100%) if no jobs recorded — benefit of the doubt for new evaluators.
     */
    function _successRateBP(uint256 approved, uint256 total) internal pure returns (uint256) {
        if (total == 0) return 10000;
        return (approved * 10000) / total;
    }
}
