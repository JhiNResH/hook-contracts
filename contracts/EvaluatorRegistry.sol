// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title EvaluatorRegistry
 * @notice Trust-ranked evaluator discovery for ERC-8183 AgenticCommerce.
 *
 * @dev Multi-evaluator system with on-chain performance tracking and
 *      trust-ranked discovery. Solves ACP's evaluator discovery gap.
 *
 * @custom:security-contact security@maiat.io
 */
contract EvaluatorRegistry is OwnableUpgradeable {
    /*//////////////////////////////////////////////////////////////
                            TYPES
    //////////////////////////////////////////////////////////////*/

    struct EvaluatorStats {
        uint256 totalJobs;
        uint256 totalApproved;
        uint256 totalRejected;
        bool active;
        bool registered; // Global flag: has this address ever been registered?
    }

    struct EvaluatorView {
        address evaluator;
        uint256 totalJobs;
        uint256 totalApproved;
        uint256 totalRejected;
        uint256 successRateBP;
        string metadataURI;
    }

    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(string => address[]) private _domainEvaluators;
    mapping(address => mapping(string => uint256)) private _evalDomainIdx;
    mapping(address => EvaluatorStats) private _stats;
    mapping(address => string) private _metadataURIs;
    string[] private _domains;
    mapping(string => uint256) private _domainIndex;
    mapping(address => bool) private _authorized;
    uint256 public minSuccessRateBP;
    uint256 public minJobsForThreshold;

    /// @dev Reserved storage gap for future upgrades
    uint256[40] private __gap;

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
    error EvaluatorRegistry__NotRegisteredAnywhere(address evaluator);

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

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        minSuccessRateBP = 3000;  // 30%
        minJobsForThreshold = 10;
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC: REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function register(string calldata domain, address evaluator) external onlyOwner {
        if (evaluator == address(0)) revert EvaluatorRegistry__ZeroAddress();
        if (bytes(domain).length == 0) revert EvaluatorRegistry__EmptyDomain();
        if (_evalDomainIdx[evaluator][domain] != 0) {
            revert EvaluatorRegistry__AlreadyRegistered(domain, evaluator);
        }

        if (_domainIndex[domain] == 0) {
            _domains.push(domain);
            _domainIndex[domain] = _domains.length;
        }

        _domainEvaluators[domain].push(evaluator);
        _evalDomainIdx[evaluator][domain] = _domainEvaluators[domain].length;

        // Set active + registered flags
        EvaluatorStats storage stats = _stats[evaluator];
        if (!stats.registered) {
            stats.active = true;
            stats.registered = true;
        } else if (stats.totalJobs == 0) {
            // Re-registering with no history → activate
            stats.active = true;
        }
        // Preserve delist for returning evaluators with job history

        emit EvaluatorRegistered(domain, evaluator);
    }

    function remove(string calldata domain, address evaluator) external onlyOwner {
        if (_evalDomainIdx[evaluator][domain] == 0) {
            revert EvaluatorRegistry__NotRegistered(domain, evaluator);
        }

        _removeFromDomain(domain, evaluator);
        emit EvaluatorRemoved(domain, evaluator);
    }

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
     * @dev Only callable by authorized addresses. Evaluator must be registered.
     */
    function recordOutcome(address evaluator, bool approved) external {
        if (!_authorized[msg.sender]) revert EvaluatorRegistry__NotAuthorized();
        if (evaluator == address(0)) revert EvaluatorRegistry__ZeroAddress();
        if (!_stats[evaluator].registered) revert EvaluatorRegistry__NotRegisteredAnywhere(evaluator);

        EvaluatorStats storage stats = _stats[evaluator];
        stats.totalJobs++;
        if (approved) {
            stats.totalApproved++;
        } else {
            stats.totalRejected++;
        }

        uint256 rateBP = _successRateBP(stats.totalApproved, stats.totalJobs);

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

    function getEvaluators(
        string calldata domain,
        uint256 offset,
        uint256 limit
    ) external view returns (EvaluatorView[] memory results) {
        address[] storage list = _domainEvaluators[domain];
        uint256 len = list.length;

        address[] memory active = new address[](len);
        uint256 activeCount = 0;
        for (uint256 i = 0; i < len; i++) {
            if (_stats[list[i]].active) {
                active[activeCount++] = list[i];
            }
        }

        // Insertion sort descending by successRateBP
        for (uint256 i = 1; i < activeCount; i++) {
            address key = active[i];
            uint256 keyRate = _successRateBP(_stats[key].totalApproved, _stats[key].totalJobs);
            uint256 j = i;
            while (j > 0) {
                address prev = active[j - 1];
                uint256 prevRate = _successRateBP(_stats[prev].totalApproved, _stats[prev].totalJobs);
                if (prevRate >= keyRate) break;
                active[j] = prev;
                j--;
            }
            active[j] = key;
        }

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

    function getEvaluatorCount(string calldata domain) external view returns (uint256) {
        return _domainEvaluators[domain].length;
    }

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

    function getMetadata(address evaluator) external view returns (string memory) {
        return _metadataURIs[evaluator];
    }

    function getDomains() external view returns (string[] memory) {
        return _domains;
    }

    function domainCount() external view returns (uint256) {
        return _domains.length;
    }

    function isAuthorized(address caller) external view returns (bool) {
        return _authorized[caller];
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN
    //////////////////////////////////////////////////////////////*/

    function setAuthorized(address caller, bool authorized) external onlyOwner {
        if (caller == address(0)) revert EvaluatorRegistry__ZeroAddress();
        _authorized[caller] = authorized;
        emit AuthorizedSet(caller, authorized);
    }

    function setThreshold(uint256 minSuccessRateBP_, uint256 minJobsForThreshold_) external onlyOwner {
        minSuccessRateBP = minSuccessRateBP_;
        minJobsForThreshold = minJobsForThreshold_;
        emit ThresholdUpdated(minSuccessRateBP_, minJobsForThreshold_);
    }

    /**
     * @notice Restore an evaluator's active status (admin override).
     * @param evaluator Address to reactivate
     */
    function reactivate(address evaluator) external onlyOwner {
        if (!_stats[evaluator].registered) revert EvaluatorRegistry__NotRegisteredAnywhere(evaluator);
        _stats[evaluator].active = true;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL
    //////////////////////////////////////////////////////////////*/

    function _removeFromDomain(string memory domain, address evaluator) internal {
        address[] storage list = _domainEvaluators[domain];
        uint256 idxOneBased = _evalDomainIdx[evaluator][domain];
        uint256 idx = idxOneBased - 1;
        uint256 lastIdx = list.length - 1;

        if (idx != lastIdx) {
            address last = list[lastIdx];
            list[idx] = last;
            _evalDomainIdx[last][domain] = idxOneBased;
        }

        list.pop();
        delete _evalDomainIdx[evaluator][domain];
    }

    function _successRateBP(uint256 approved, uint256 total) internal pure returns (uint256) {
        if (total == 0) return 10000;
        return (approved * 10000) / total;
    }
}
