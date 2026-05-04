// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@erc8183/IERC8183Hook.sol";
import "../interfaces/IERC8183HookMetadata.sol";
import "@erc8183/AgenticCommerce.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

/// @title MultiHookRouter
/// @notice Routes hook callbacks to per-selector ordered lists of sub-hooks per job,
///         with owner-managed global default hooks that apply when a job has no
///         per-job configuration for a given selector.
/// @dev Resolution rule per (jobId, selector):
///        - per-job list non-empty → use per-job list (unchanged V2 behavior)
///        - per-job list empty     → fall back to global defaults for that selector
///        - both empty             → no-op
///
///      Global defaults are owner-only CRUD. Per-job configuration (set by the
///      job client) always takes precedence; the two lists never mix for a given
///      selector, keeping gas predictable.
///
///      All per-hook data dispatch (abi.encode(bytes[])), selector completeness
///      validation, and de-whitelisted resilience apply identically to resolved
///      lists, whether they came from per-job or global configuration.
contract MultiHookRouter is ERC165, IERC8183Hook, ReentrancyGuardTransient, Ownable {
    // ──────────────────── Immutables ────────────────────

    /// @notice The ERC-8183 core contract
    address public immutable erc8183Contract;

    // ──────────────────── Constants ────────────────────

    bytes4 private constant SEL_SET_BUDGET =
        bytes4(keccak256("setBudget(uint256,address,uint256,bytes)"));
    bytes4 private constant SEL_FUND =
        bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 private constant SEL_SUBMIT =
        bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_COMPLETE =
        bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_REJECT =
        bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    // ──────────────────── Storage ────────────────────

    /// @notice Maximum sub-hooks per selector (applies to both per-job and global lists)
    uint256 public maxHooksPerJob;

    /// @notice Per-job, per-selector ordered list of sub-hooks
    mapping(uint256 jobId => mapping(bytes4 selector => address[])) private _jobHooks;

    /// @notice Owner-managed per-selector global default hooks
    mapping(bytes4 selector => address[]) private _globalHooks;

    // ──────────────────── Errors ────────────────────

    error OnlyERC8183Contract();
    error OnlyJobClient();
    error HooksLocked();
    error TooManyHooks();
    error InvalidHook();
    error InvalidSelector();
    error DuplicateHook();
    error HookNotFound();
    error ZeroAddress();
    error EmptyArray();
    error HookSetMismatch();
    error HookDataLengthMismatch();
    error SubHookNotWhitelisted();
    error ArrayLengthMismatch();
    error HookMissingRequiredSelector();

    // ──────────────────── Events ────────────────────

    event HooksConfigured(uint256 indexed jobId, bytes4 indexed selector, address[] hooks);
    event HookAdded(uint256 indexed jobId, bytes4 indexed selector, address indexed hook, uint256 position);
    event HookRemoved(uint256 indexed jobId, bytes4 indexed selector, address indexed hook);
    event HooksReordered(uint256 indexed jobId, bytes4 indexed selector, address[] hooks);
    event MaxHooksPerJobUpdated(uint256 oldMax, uint256 newMax);
    event DewhitelistedHookSkipped(uint256 indexed jobId, bytes4 indexed selector, address indexed hook);

    event GlobalHooksConfigured(bytes4 indexed selector, address[] hooks);
    event GlobalHookAdded(bytes4 indexed selector, address indexed hook, uint256 position);
    event GlobalHookRemoved(bytes4 indexed selector, address indexed hook);
    event GlobalHooksReordered(bytes4 indexed selector, address[] hooks);

    // ──────────────────── Modifiers ────────────────────

    modifier onlyERC8183() {
        if (msg.sender != erc8183Contract) revert OnlyERC8183Contract();
        _;
    }

    modifier onlyJobClient(uint256 jobId) {
        AgenticCommerce.Job memory job = AgenticCommerce(erc8183Contract).getJob(jobId);
        if (msg.sender != job.client) revert OnlyJobClient();
        _;
    }

    modifier hooksNotLocked(uint256 jobId) {
        AgenticCommerce.Job memory job = AgenticCommerce(erc8183Contract).getJob(jobId);
        if (job.status != AgenticCommerce.JobStatus.Open) revert HooksLocked();
        _;
    }

    modifier validSelector(bytes4 selector) {
        if (!_isKnownSelector(selector)) revert InvalidSelector();
        _;
    }

    // ──────────────────── Constructor ────────────────────

    constructor(address erc8183Contract_, address owner_, uint256 maxHooksPerJob_) Ownable(owner_) {
        if (erc8183Contract_ == address(0)) revert ZeroAddress();
        erc8183Contract = erc8183Contract_;
        maxHooksPerJob = maxHooksPerJob_;
    }

    // ──────────────────── Admin ────────────────────

    /// @notice Update the maximum sub-hooks allowed per selector
    function setMaxHooksPerJob(uint256 newMax) external onlyOwner {
        uint256 oldMax = maxHooksPerJob;
        maxHooksPerJob = newMax;
        emit MaxHooksPerJobUpdated(oldMax, newMax);
    }

    // ──────────────────── Global Default Hook Admin ────────────────────

    /// @notice Replace the global default hook list for a selector
    /// @param selector The hookable function selector
    /// @param hooks Ordered array of sub-hook addresses (may be empty to clear)
    function configureGlobalHooks(
        bytes4 selector,
        address[] calldata hooks
    ) external onlyOwner validSelector(selector) {
        _setGlobalHooksForSelector(selector, hooks);
    }

    /// @notice Replace global default hook lists for multiple selectors in a single call
    function batchConfigureGlobalHooks(
        bytes4[] calldata selectors,
        address[][] calldata hooksPerSelector
    ) external onlyOwner {
        if (selectors.length != hooksPerSelector.length) revert ArrayLengthMismatch();
        if (selectors.length == 0) revert EmptyArray();

        for (uint256 s; s < selectors.length; ) {
            if (!_isKnownSelector(selectors[s])) revert InvalidSelector();
            _setGlobalHooksForSelector(selectors[s], hooksPerSelector[s]);
            unchecked { ++s; }
        }
    }

    /// @notice Append a hook to the global default list for a selector
    function addGlobalHook(
        bytes4 selector,
        address hook
    ) external onlyOwner validSelector(selector) {
        _validateSubHook(hook);

        address[] storage hooks = _globalHooks[selector];
        if (hooks.length >= maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            if (hooks[i] == hook) revert DuplicateHook();
            unchecked { ++i; }
        }

        hooks.push(hook);
        emit GlobalHookAdded(selector, hook, hooks.length - 1);
    }

    /// @notice Remove a hook from the global default list for a selector
    function removeGlobalHook(
        bytes4 selector,
        address hook
    ) external onlyOwner validSelector(selector) {
        address[] storage hooks = _globalHooks[selector];
        uint256 len = hooks.length;

        for (uint256 i; i < len; ) {
            if (hooks[i] == hook) {
                hooks[i] = hooks[len - 1];
                hooks.pop();
                emit GlobalHookRemoved(selector, hook);
                return;
            }
            unchecked { ++i; }
        }

        revert HookNotFound();
    }

    /// @notice Replace the global default list with a reordered version (must be a permutation)
    function reorderGlobalHooks(
        bytes4 selector,
        address[] calldata hooks
    ) external onlyOwner validSelector(selector) {
        address[] storage current = _globalHooks[selector];
        if (hooks.length != current.length) revert HookSetMismatch();
        if (hooks.length == 0) revert EmptyArray();

        for (uint256 i; i < hooks.length; ) {
            for (uint256 k; k < i; ) {
                if (hooks[k] == hooks[i]) revert DuplicateHook();
                unchecked { ++k; }
            }
            bool found;
            for (uint256 j; j < current.length; ) {
                if (hooks[i] == current[j]) {
                    found = true;
                    break;
                }
                unchecked { ++j; }
            }
            if (!found) revert HookNotFound();
            unchecked { ++i; }
        }

        _globalHooks[selector] = hooks;
        emit GlobalHooksReordered(selector, hooks);
    }

    // ──────────────────── Per-Job Configuration ────────────────────

    /// @notice Replace the entire hook list for a job's selector
    function configureHooks(
        uint256 jobId,
        bytes4 selector,
        address[] calldata hooks
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        if (hooks.length > maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            _validateSubHook(hooks[i]);
            for (uint256 j; j < i; ) {
                if (hooks[j] == hooks[i]) revert DuplicateHook();
                unchecked { ++j; }
            }
            unchecked { ++i; }
        }

        _jobHooks[jobId][selector] = hooks;
        emit HooksConfigured(jobId, selector, hooks);
    }

    /// @notice Replace hook lists for multiple selectors in a single call
    function batchConfigureHooks(
        uint256 jobId,
        bytes4[] calldata selectors,
        address[][] calldata hooksPerSelector
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        if (selectors.length != hooksPerSelector.length) revert ArrayLengthMismatch();
        if (selectors.length == 0) revert EmptyArray();

        for (uint256 s; s < selectors.length; ) {
            _setHooksForSelector(jobId, selectors[s], hooksPerSelector[s]);
            unchecked { ++s; }
        }

        _validateSelectorCompleteness(jobId);
    }

    /// @notice Append a hook to the end of the per-job list for a selector
    function addHook(
        uint256 jobId,
        bytes4 selector,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        _validateSubHook(hook);

        address[] storage hooks = _jobHooks[jobId][selector];
        if (hooks.length >= maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            if (hooks[i] == hook) revert DuplicateHook();
            unchecked { ++i; }
        }

        hooks.push(hook);
        emit HookAdded(jobId, selector, hook, hooks.length - 1);
    }

    /// @notice Remove a hook from the per-job list for a selector
    /// @param jobId The job ID
    /// @param selector The hookable function selector
    /// @param hook The sub-hook address to remove
    /// @dev Preserves the relative order of the remaining hooks. Order matters
    ///      because beforeAction/afterAction iterate _jobHooks in storage order
    ///      and _splitHookData binds per-hook optParams to hooks by index.
    function removeHook(
        uint256 jobId,
        bytes4 selector,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        address[] storage hooks = _jobHooks[jobId][selector];
        uint256 len = hooks.length;

        for (uint256 i; i < len; ) {
            if (hooks[i] == hook) {
                // Shift remaining elements left so removal is order-preserving.
                for (uint256 j = i; j + 1 < len; ) {
                    hooks[j] = hooks[j + 1];
                    unchecked { ++j; }
                }
                hooks.pop();
                emit HookRemoved(jobId, selector, hook);
                return;
            }
            unchecked { ++i; }
        }

        revert HookNotFound();
    }

    /// @notice Replace the per-job list with a reordered version (must be a permutation)
    function reorderHooks(
        uint256 jobId,
        bytes4 selector,
        address[] calldata hooks
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) validSelector(selector) {
        address[] storage current = _jobHooks[jobId][selector];
        if (hooks.length != current.length) revert HookSetMismatch();
        if (hooks.length == 0) revert EmptyArray();

        for (uint256 i; i < hooks.length; ) {
            for (uint256 k; k < i; ) {
                if (hooks[k] == hooks[i]) revert DuplicateHook();
                unchecked { ++k; }
            }
            bool found;
            for (uint256 j; j < current.length; ) {
                if (hooks[i] == current[j]) {
                    found = true;
                    break;
                }
                unchecked { ++j; }
            }
            if (!found) revert HookNotFound();
            unchecked { ++i; }
        }

        _jobHooks[jobId][selector] = hooks;
        emit HooksReordered(jobId, selector, hooks);
    }

    // ──────────────────── IERC8183Hook Implementation ────────────────────

    /// @inheritdoc IERC8183Hook
    function beforeAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyERC8183 nonReentrant {
        // Validation at FUND runs unconditionally — even when FUND itself has
        // no resolved hooks — so a dependent hook declared on one selector
        // without its counterpart elsewhere is caught before value transfers.
        if (selector == SEL_FUND) {
            _validateSelectorCompleteness(jobId);
        }

        address[] memory hooks = _resolveHooks(jobId, selector);
        uint256 len = hooks.length;
        if (len == 0) return;

        (bool dispatched, bytes[] memory perHookData) = _splitHookData(selector, data, len);

        for (uint256 i; i < len; ) {
            if (!AgenticCommerce(erc8183Contract).whitelistedHooks(hooks[i])) {
                emit DewhitelistedHookSkipped(jobId, selector, hooks[i]);
                unchecked { ++i; }
                continue;
            }
            if (dispatched) {
                IERC8183Hook(hooks[i]).beforeAction(jobId, selector, perHookData[i]);
            } else {
                IERC8183Hook(hooks[i]).beforeAction(jobId, selector, data);
            }
            unchecked { ++i; }
        }
    }

    /// @inheritdoc IERC8183Hook
    function afterAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyERC8183 nonReentrant {
        address[] memory hooks = _resolveHooks(jobId, selector);
        uint256 len = hooks.length;
        if (len == 0) return;

        (bool dispatched, bytes[] memory perHookData) = _splitHookData(selector, data, len);

        for (uint256 i; i < len; ) {
            if (!AgenticCommerce(erc8183Contract).whitelistedHooks(hooks[i])) {
                emit DewhitelistedHookSkipped(jobId, selector, hooks[i]);
                unchecked { ++i; }
                continue;
            }
            if (dispatched) {
                IERC8183Hook(hooks[i]).afterAction(jobId, selector, perHookData[i]);
            } else {
                IERC8183Hook(hooks[i]).afterAction(jobId, selector, data);
            }
            unchecked { ++i; }
        }
    }

    // ──────────────────── Passthrough Views ────────────────────

    function getJob(uint256 jobId) external view returns (AgenticCommerce.Job memory) {
        return AgenticCommerce(erc8183Contract).getJob(jobId);
    }

    // ──────────────────── Views ────────────────────

    function getHooks(uint256 jobId, bytes4 selector) external view returns (address[] memory) {
        return _jobHooks[jobId][selector];
    }

    function hookCount(uint256 jobId, bytes4 selector) external view returns (uint256) {
        return _jobHooks[jobId][selector].length;
    }

    function getGlobalHooks(bytes4 selector) external view returns (address[] memory) {
        return _globalHooks[selector];
    }

    function globalHookCount(bytes4 selector) external view returns (uint256) {
        return _globalHooks[selector].length;
    }

    /// @notice Resolved hook list that would run for (jobId, selector): per-job if non-empty, else global.
    function resolveHooks(uint256 jobId, bytes4 selector) external view returns (address[] memory) {
        return _resolveHooks(jobId, selector);
    }

    // ──────────────────── ERC165 ────────────────────

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC8183Hook).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // ──────────────────── Internal ────────────────────

    function _resolveHooks(uint256 jobId, bytes4 selector) private view returns (address[] memory) {
        address[] storage perJob = _jobHooks[jobId][selector];
        if (perJob.length > 0) {
            return perJob;
        }
        return _globalHooks[selector];
    }

    function _isKnownSelector(bytes4 selector) private pure returns (bool) {
        return selector == SEL_SET_BUDGET
            || selector == SEL_FUND
            || selector == SEL_SUBMIT
            || selector == SEL_COMPLETE
            || selector == SEL_REJECT;
    }

    function _setHooksForSelector(
        uint256 jobId,
        bytes4 selector,
        address[] calldata hooks
    ) private {
        if (!_isKnownSelector(selector)) revert InvalidSelector();
        if (hooks.length > maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            _validateSubHook(hooks[i]);
            for (uint256 j; j < i; ) {
                if (hooks[j] == hooks[i]) revert DuplicateHook();
                unchecked { ++j; }
            }
            unchecked { ++i; }
        }

        _jobHooks[jobId][selector] = hooks;
        emit HooksConfigured(jobId, selector, hooks);
    }

    function _setGlobalHooksForSelector(
        bytes4 selector,
        address[] calldata hooks
    ) private {
        if (hooks.length > maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            _validateSubHook(hooks[i]);
            for (uint256 j; j < i; ) {
                if (hooks[j] == hooks[i]) revert DuplicateHook();
                unchecked { ++j; }
            }
            unchecked { ++i; }
        }

        _globalHooks[selector] = hooks;
        emit GlobalHooksConfigured(selector, hooks);
    }

    function _validateSubHook(address hook) private view {
        if (hook == address(0)) revert ZeroAddress();
        if (!AgenticCommerce(erc8183Contract).whitelistedHooks(hook))
            revert SubHookNotWhitelisted();
        if (!ERC165Checker.supportsInterface(hook, type(IERC8183Hook).interfaceId))
            revert InvalidHook();
        if (!ERC165Checker.supportsInterface(hook, type(IERC8183HookMetadata).interfaceId))
            revert InvalidHook();
    }

    function _splitHookData(
        bytes4 selector,
        bytes calldata data,
        uint256 hookCount_
    ) private pure returns (bool dispatched, bytes[] memory perHookData) {
        bytes memory optParams = _extractOptParams(selector, data);

        if (optParams.length < 64) return (false, perHookData);

        bytes[] memory hookDataArray = abi.decode(optParams, (bytes[]));

        if (hookDataArray.length != hookCount_) revert HookDataLengthMismatch();

        perHookData = new bytes[](hookCount_);
        for (uint256 i; i < hookCount_; ) {
            perHookData[i] = _reEncodeData(selector, data, hookDataArray[i]);
            unchecked { ++i; }
        }
        return (true, perHookData);
    }

    function _extractOptParams(
        bytes4 selector,
        bytes calldata data
    ) private pure returns (bytes memory) {
        if (selector == SEL_SET_BUDGET) {
            (, , , bytes memory optParams) = abi.decode(data, (address, address, uint256, bytes));
            return optParams;
        } else if (selector == SEL_FUND) {
            (, bytes memory optParams) = abi.decode(data, (address, bytes));
            return optParams;
        } else {
            (, , bytes memory optParams) = abi.decode(data, (address, bytes32, bytes));
            return optParams;
        }
    }

    function _reEncodeData(
        bytes4 selector,
        bytes calldata data,
        bytes memory hookOptParams
    ) private pure returns (bytes memory) {
        if (selector == SEL_SET_BUDGET) {
            (address caller, address token, uint256 amount, ) = abi.decode(data, (address, address, uint256, bytes));
            return abi.encode(caller, token, amount, hookOptParams);
        } else if (selector == SEL_FUND) {
            (address caller, ) = abi.decode(data, (address, bytes));
            return abi.encode(caller, hookOptParams);
        } else {
            (address caller, bytes32 field2, ) = abi.decode(data, (address, bytes32, bytes));
            return abi.encode(caller, field2, hookOptParams);
        }
    }

    /// @dev Validates selector completeness using the RESOLVED hook list per selector
    ///      (per-job if non-empty, else global defaults). Every hook in the resolved
    ///      union must be present on all its required selectors.
    function _validateSelectorCompleteness(uint256 jobId) private view {
        bytes4[5] memory sels = [SEL_SET_BUDGET, SEL_FUND, SEL_SUBMIT, SEL_COMPLETE, SEL_REJECT];

        address[][5] memory resolved;
        uint256 maxUnique;
        for (uint256 s; s < 5; ) {
            resolved[s] = _resolveHooks(jobId, sels[s]);
            maxUnique += resolved[s].length;
            unchecked { ++s; }
        }

        address[] memory uniqueHooks = new address[](maxUnique);
        uint256 uniqueCount;

        for (uint256 s; s < 5; ) {
            address[] memory hooksForSel = resolved[s];
            uint256 len = hooksForSel.length;
            for (uint256 i; i < len; ) {
                address hook = hooksForSel[i];
                bool found;
                for (uint256 u; u < uniqueCount; ) {
                    if (uniqueHooks[u] == hook) {
                        found = true;
                        break;
                    }
                    unchecked { ++u; }
                }
                if (!found) {
                    uniqueHooks[uniqueCount] = hook;
                    unchecked { ++uniqueCount; }
                }
                unchecked { ++i; }
            }
            unchecked { ++s; }
        }

        for (uint256 h; h < uniqueCount; ) {
            bytes4[] memory required = IERC8183HookMetadata(uniqueHooks[h]).requiredSelectors();
            uint256 reqLen = required.length;
            for (uint256 r; r < reqLen; ) {
                bool present;
                address[] memory hooksForReqSel;
                for (uint256 si; si < 5; ) {
                    if (sels[si] == required[r]) {
                        hooksForReqSel = resolved[si];
                        break;
                    }
                    unchecked { ++si; }
                }
                uint256 hLen = hooksForReqSel.length;
                for (uint256 k; k < hLen; ) {
                    if (hooksForReqSel[k] == uniqueHooks[h]) {
                        present = true;
                        break;
                    }
                    unchecked { ++k; }
                }
                if (!present) revert HookMissingRequiredSelector();
                unchecked { ++r; }
            }
            unchecked { ++h; }
        }
    }
}
