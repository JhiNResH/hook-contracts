// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@acp/IACPHook.sol";
import "@acp/AgenticCommerce.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

/// @title MultiHookRouter
/// @notice Routes hook callbacks to an ordered list of sub-hooks per job.
/// @dev Implements IACPHook so the core contract sees it as a single hook.
///      Non-upgradeable by design — hooks should be immutable once deployed.
///      Sub-hooks must be whitelisted on the core contract to be used.
///      Exposes passthrough view functions so sub-hooks deployed with
///      acpContract = routerAddress can call _core().getJob() etc.
contract MultiHookRouter is ERC165, IACPHook, ReentrancyGuardTransient, Ownable {
    // ──────────────────── Immutables ────────────────────

    /// @notice The ACP core contract
    address public immutable acpContract;

    // ──────────────────── Storage ────────────────────

    /// @notice Maximum sub-hooks per job (admin-configurable gas safety cap)
    uint256 public maxHooksPerJob;

    /// @notice Per-job ordered list of sub-hooks
    mapping(uint256 jobId => address[] hooks) private _jobHooks;

    // ──────────────────── Errors ────────────────────

    error OnlyACPContract();
    error OnlyJobClient();
    error HooksLocked();
    error TooManyHooks();
    error InvalidHook();
    error DuplicateHook();
    error HookNotFound();
    error ZeroAddress();
    error EmptyArray();
    error HookSetMismatch();
    error SubHookNotWhitelisted();

    // ──────────────────── Events ────────────────────

    event HooksConfigured(uint256 indexed jobId, address[] hooks);
    event HookAdded(uint256 indexed jobId, address indexed hook, uint256 position);
    event HookRemoved(uint256 indexed jobId, address indexed hook);
    event HooksReordered(uint256 indexed jobId, address[] hooks);
    event MaxHooksPerJobUpdated(uint256 oldMax, uint256 newMax);

    // ──────────────────── Modifiers ────────────────────

    modifier onlyACP() {
        if (msg.sender != acpContract) revert OnlyACPContract();
        _;
    }

    modifier onlyJobClient(uint256 jobId) {
        AgenticCommerce.Job memory job = AgenticCommerce(acpContract).getJob(jobId);
        if (msg.sender != job.client) revert OnlyJobClient();
        _;
    }

    modifier hooksNotLocked(uint256 jobId) {
        AgenticCommerce.Job memory job = AgenticCommerce(acpContract).getJob(jobId);
        if (job.status != AgenticCommerce.JobStatus.Open) revert HooksLocked();
        _;
    }

    // ──────────────────── Constructor ────────────────────

    constructor(address acpContract_, address owner_, uint256 maxHooksPerJob_) Ownable(owner_) {
        if (acpContract_ == address(0)) revert ZeroAddress();
        acpContract = acpContract_;
        maxHooksPerJob = maxHooksPerJob_;
    }

    // ──────────────────── Admin ────────────────────

    /// @notice Update the maximum sub-hooks allowed per job
    /// @param newMax New maximum
    function setMaxHooksPerJob(uint256 newMax) external onlyOwner {
        uint256 oldMax = maxHooksPerJob;
        maxHooksPerJob = newMax;
        emit MaxHooksPerJobUpdated(oldMax, newMax);
    }

    // ──────────────────── Configuration ────────────────────

    /// @notice Replace the entire hook list for a job
    /// @param jobId The job ID
    /// @param hooks Ordered array of sub-hook addresses
    function configureHooks(
        uint256 jobId,
        address[] calldata hooks
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        if (hooks.length > maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            _validateSubHook(hooks[i]);
            // O(n) duplicate check — acceptable for max ~10 hooks
            for (uint256 j; j < i; ) {
                if (hooks[j] == hooks[i]) revert DuplicateHook();
                unchecked { ++j; }
            }
            unchecked { ++i; }
        }

        _jobHooks[jobId] = hooks;
        emit HooksConfigured(jobId, hooks);
    }

    /// @notice Append a hook to the end of the list
    /// @param jobId The job ID
    /// @param hook The sub-hook address to add
    function addHook(
        uint256 jobId,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        _validateSubHook(hook);

        address[] storage hooks = _jobHooks[jobId];
        if (hooks.length >= maxHooksPerJob) revert TooManyHooks();

        for (uint256 i; i < hooks.length; ) {
            if (hooks[i] == hook) revert DuplicateHook();
            unchecked { ++i; }
        }

        hooks.push(hook);
        emit HookAdded(jobId, hook, hooks.length - 1);
    }

    /// @notice Remove a hook from the list
    /// @param jobId The job ID
    /// @param hook The sub-hook address to remove
    function removeHook(
        uint256 jobId,
        address hook
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        address[] storage hooks = _jobHooks[jobId];
        uint256 len = hooks.length;

        for (uint256 i; i < len; ) {
            if (hooks[i] == hook) {
                hooks[i] = hooks[len - 1];
                hooks.pop();
                emit HookRemoved(jobId, hook);
                return;
            }
            unchecked { ++i; }
        }

        revert HookNotFound();
    }

    /// @notice Replace the hook list with a reordered version (must be a permutation)
    /// @param jobId The job ID
    /// @param hooks New ordering (must contain the same hooks)
    function reorderHooks(
        uint256 jobId,
        address[] calldata hooks
    ) external onlyJobClient(jobId) hooksNotLocked(jobId) {
        address[] storage current = _jobHooks[jobId];
        if (hooks.length != current.length) revert HookSetMismatch();
        if (hooks.length == 0) revert EmptyArray();

        // Verify permutation: every new entry exists in current, no duplicates
        for (uint256 i; i < hooks.length; ) {
            // Check no duplicates in new array
            for (uint256 k; k < i; ) {
                if (hooks[k] == hooks[i]) revert DuplicateHook();
                unchecked { ++k; }
            }
            // Check exists in current array
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

        _jobHooks[jobId] = hooks;
        emit HooksReordered(jobId, hooks);
    }

    // ──────────────────── IACPHook Implementation ────────────────────

    /// @inheritdoc IACPHook
    function beforeAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyACP nonReentrant {
        address[] storage hooks = _jobHooks[jobId];
        uint256 len = hooks.length;
        for (uint256 i; i < len; ) {
            IACPHook(hooks[i]).beforeAction(jobId, selector, data);
            unchecked { ++i; }
        }
    }

    /// @inheritdoc IACPHook
    function afterAction(
        uint256 jobId,
        bytes4 selector,
        bytes calldata data
    ) external override onlyACP nonReentrant {
        address[] storage hooks = _jobHooks[jobId];
        uint256 len = hooks.length;
        for (uint256 i; i < len; ) {
            IACPHook(hooks[i]).afterAction(jobId, selector, data);
            unchecked { ++i; }
        }
    }

    // ──────────────────── Passthrough Views ────────────────────

    /// @notice Passthrough to core getJob — allows sub-hooks to call _core().getJob()
    function getJob(uint256 jobId) external view returns (AgenticCommerce.Job memory) {
        return AgenticCommerce(acpContract).getJob(jobId);
    }

    // ──────────────────── Views ────────────────────

    /// @notice Get the ordered hook list for a job
    function getHooks(uint256 jobId) external view returns (address[] memory) {
        return _jobHooks[jobId];
    }

    /// @notice Get the number of hooks configured for a job
    function hookCount(uint256 jobId) external view returns (uint256) {
        return _jobHooks[jobId].length;
    }

    // ──────────────────── ERC165 ────────────────────

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IACPHook).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // ──────────────────── Internal ────────────────────

    /// @dev Validate a sub-hook: non-zero, whitelisted on core, supports IACPHook
    function _validateSubHook(address hook) private view {
        if (hook == address(0)) revert ZeroAddress();
        if (!AgenticCommerce(acpContract).whitelistedHooks(hook))
            revert SubHookNotWhitelisted();
        if (!ERC165Checker.supportsInterface(hook, type(IACPHook).interfaceId))
            revert InvalidHook();
    }
}
