// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/hooks/MultiHookRouter.sol";
import "../contracts/interfaces/IERC8183HookMetadata.sol";
import "@erc8183/IACPHook.sol";
import "@erc8183/AgenticCommerce.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/// @dev Minimal mock hook — counts calls, declares no required selectors.
contract MockHook is ERC165, IACPHook, IERC8183HookMetadata {
    uint256 public beforeCalls;
    uint256 public afterCalls;
    uint256 public lastJobId;
    bytes4 public lastSelector;
    bytes public lastData;

    function beforeAction(uint256 jobId, bytes4 selector, bytes calldata data) external override {
        beforeCalls++;
        lastJobId = jobId;
        lastSelector = selector;
        lastData = data;
    }

    function afterAction(uint256 jobId, bytes4 selector, bytes calldata data) external override {
        afterCalls++;
        lastJobId = jobId;
        lastSelector = selector;
        lastData = data;
    }

    function requiredSelectors() external view virtual override returns (bytes4[] memory) {
        return new bytes4[](0);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IACPHook).interfaceId ||
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}

/// @dev Mock hook declaring a cross-selector dependency (e.g. SUBMIT ↔ COMPLETE).
contract DependentMockHook is MockHook {
    bytes4[] private _required;

    constructor(bytes4[] memory required_) {
        for (uint256 i; i < required_.length; ++i) _required.push(required_[i]);
    }

    function requiredSelectors() external view override returns (bytes4[] memory out) {
        out = new bytes4[](_required.length);
        for (uint256 i; i < _required.length; ++i) out[i] = _required[i];
    }
}

contract MultiHookRouterGlobalTest is Test {
    MultiHookRouter router;
    AgenticCommerce acp;

    MockHook globalHook1;
    MockHook globalHook2;
    MockHook jobHook;

    address owner = makeAddr("owner");
    address treasury = makeAddr("treasury");
    address client = makeAddr("client");
    address provider = makeAddr("provider");
    address evaluator = makeAddr("evaluator");

    bytes4 constant SEL_SET_BUDGET = bytes4(keccak256("setBudget(uint256,address,uint256,bytes)"));
    bytes4 constant SEL_FUND = bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 constant SEL_SUBMIT = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 constant SEL_COMPLETE = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 constant SEL_REJECT = bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    function setUp() public {
        // Deploy ACP via proxy
        AgenticCommerce impl = new AgenticCommerce();
        bytes memory initData = abi.encodeCall(AgenticCommerce.initialize, (treasury));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        acp = AgenticCommerce(address(proxy));

        // Deploy router (owner = this test contract for simpler whitelist control)
        router = new MultiHookRouter(address(acp), owner, 10);

        globalHook1 = new MockHook();
        globalHook2 = new MockHook();
        jobHook = new MockHook();

        acp.setHookWhitelist(address(router), true);
        acp.setHookWhitelist(address(globalHook1), true);
        acp.setHookWhitelist(address(globalHook2), true);
        acp.setHookWhitelist(address(jobHook), true);
    }

    // ──────────────────── Helpers ────────────────────

    function _createJob() internal returns (uint256 jobId) {
        vm.prank(client);
        jobId = acp.createJob(provider, evaluator, block.timestamp + 1 days, "test", address(router), 0);
    }

    function _asArray(address a) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = a;
    }

    function _asArray(address a, address b) internal pure returns (address[] memory arr) {
        arr = new address[](2);
        arr[0] = a;
        arr[1] = b;
    }

    // ──────────────────── Global Hook Admin ────────────────────

    function test_addGlobalHook() public {
        vm.prank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));

        assertEq(router.globalHookCount(SEL_SUBMIT), 1);
        address[] memory hooks = router.getGlobalHooks(SEL_SUBMIT);
        assertEq(hooks.length, 1);
        assertEq(hooks[0], address(globalHook1));
    }

    function test_addGlobalHook_perSelectorIndependent() public {
        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        router.addGlobalHook(SEL_COMPLETE, address(globalHook2));
        vm.stopPrank();

        assertEq(router.globalHookCount(SEL_SUBMIT), 1);
        assertEq(router.globalHookCount(SEL_COMPLETE), 1);
        assertEq(router.globalHookCount(SEL_FUND), 0);
    }

    function test_addGlobalHook_revertDuplicate() public {
        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        vm.expectRevert(MultiHookRouter.DuplicateHook.selector);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        vm.stopPrank();
    }

    function test_addGlobalHook_revertNonOwner() public {
        vm.prank(client);
        vm.expectRevert();
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
    }

    function test_addGlobalHook_revertInvalidSelector() public {
        bytes4 bogus = bytes4(keccak256("notAFunction()"));
        vm.prank(owner);
        vm.expectRevert(MultiHookRouter.InvalidSelector.selector);
        router.addGlobalHook(bogus, address(globalHook1));
    }

    function test_addGlobalHook_revertNotWhitelisted() public {
        MockHook stray = new MockHook();
        vm.prank(owner);
        vm.expectRevert(MultiHookRouter.SubHookNotWhitelisted.selector);
        router.addGlobalHook(SEL_SUBMIT, address(stray));
    }

    function test_addGlobalHook_revertMaxCap() public {
        vm.prank(owner);
        router.setMaxHooksPerJob(1);

        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        vm.expectRevert(MultiHookRouter.TooManyHooks.selector);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook2));
        vm.stopPrank();
    }

    function test_removeGlobalHook() public {
        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        router.addGlobalHook(SEL_SUBMIT, address(globalHook2));
        router.removeGlobalHook(SEL_SUBMIT, address(globalHook1));
        vm.stopPrank();

        assertEq(router.globalHookCount(SEL_SUBMIT), 1);
        assertEq(router.getGlobalHooks(SEL_SUBMIT)[0], address(globalHook2));
    }

    function test_removeGlobalHook_revertNotFound() public {
        vm.prank(owner);
        vm.expectRevert(MultiHookRouter.HookNotFound.selector);
        router.removeGlobalHook(SEL_SUBMIT, address(globalHook1));
    }

    function test_configureGlobalHooks_replaces() public {
        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        router.configureGlobalHooks(SEL_SUBMIT, _asArray(address(globalHook2)));
        vm.stopPrank();

        assertEq(router.globalHookCount(SEL_SUBMIT), 1);
        assertEq(router.getGlobalHooks(SEL_SUBMIT)[0], address(globalHook2));
    }

    function test_configureGlobalHooks_emptyClears() public {
        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        address[] memory empty = new address[](0);
        router.configureGlobalHooks(SEL_SUBMIT, empty);
        vm.stopPrank();

        assertEq(router.globalHookCount(SEL_SUBMIT), 0);
    }

    function test_reorderGlobalHooks() public {
        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));
        router.addGlobalHook(SEL_SUBMIT, address(globalHook2));

        router.reorderGlobalHooks(SEL_SUBMIT, _asArray(address(globalHook2), address(globalHook1)));
        vm.stopPrank();

        address[] memory hooks = router.getGlobalHooks(SEL_SUBMIT);
        assertEq(hooks[0], address(globalHook2));
        assertEq(hooks[1], address(globalHook1));
    }

    function test_batchConfigureGlobalHooks() public {
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = SEL_SUBMIT;
        sels[1] = SEL_COMPLETE;

        address[][] memory perSel = new address[][](2);
        perSel[0] = _asArray(address(globalHook1));
        perSel[1] = _asArray(address(globalHook2));

        vm.prank(owner);
        router.batchConfigureGlobalHooks(sels, perSel);

        assertEq(router.getGlobalHooks(SEL_SUBMIT)[0], address(globalHook1));
        assertEq(router.getGlobalHooks(SEL_COMPLETE)[0], address(globalHook2));
    }

    function test_batchConfigureGlobalHooks_revertLengthMismatch() public {
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = SEL_SUBMIT;
        sels[1] = SEL_COMPLETE;

        address[][] memory perSel = new address[][](1);
        perSel[0] = _asArray(address(globalHook1));

        vm.prank(owner);
        vm.expectRevert(MultiHookRouter.ArrayLengthMismatch.selector);
        router.batchConfigureGlobalHooks(sels, perSel);
    }

    // ──────────────────── Resolution ────────────────────

    function test_resolveHooks_usesGlobalWhenNoPerJob() public {
        uint256 jobId = _createJob();

        vm.prank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));

        address[] memory resolved = router.resolveHooks(jobId, SEL_SUBMIT);
        assertEq(resolved.length, 1);
        assertEq(resolved[0], address(globalHook1));
    }

    function test_resolveHooks_perJobOverridesGlobal() public {
        uint256 jobId = _createJob();

        vm.prank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));

        vm.prank(client);
        router.configureHooks(jobId, SEL_SUBMIT, _asArray(address(jobHook)));

        address[] memory resolved = router.resolveHooks(jobId, SEL_SUBMIT);
        assertEq(resolved.length, 1);
        assertEq(resolved[0], address(jobHook));
    }

    function test_resolveHooks_emptyWhenNeither() public {
        uint256 jobId = _createJob();
        address[] memory resolved = router.resolveHooks(jobId, SEL_SUBMIT);
        assertEq(resolved.length, 0);
    }

    // ──────────────────── Runtime dispatch ────────────────────
    //
    // We drive beforeAction via the ACP itself (via submit/complete would
    // require full job funding). Instead, we verify resolution routes to
    // globalHook1 by simulating a call from the ACP address directly.

    function test_beforeAction_invokesGlobalDefault() public {
        uint256 jobId = _createJob();

        vm.prank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));

        // Data shape for submit: (caller, field2, optParams) with empty optParams → broadcast
        bytes memory data = abi.encode(client, bytes32(0), bytes(""));

        vm.prank(address(acp));
        router.beforeAction(jobId, SEL_SUBMIT, data);

        assertEq(globalHook1.beforeCalls(), 1);
        assertEq(globalHook1.lastJobId(), jobId);
    }

    function test_beforeAction_perJobTakesPrecedence() public {
        uint256 jobId = _createJob();

        vm.prank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));

        vm.prank(client);
        router.configureHooks(jobId, SEL_SUBMIT, _asArray(address(jobHook)));

        bytes memory data = abi.encode(client, bytes32(0), bytes(""));

        vm.prank(address(acp));
        router.beforeAction(jobId, SEL_SUBMIT, data);

        assertEq(globalHook1.beforeCalls(), 0);
        assertEq(jobHook.beforeCalls(), 1);
    }

    function test_beforeAction_noHooks_isNoOp() public {
        uint256 jobId = _createJob();
        bytes memory data = abi.encode(client, bytes32(0), bytes(""));

        vm.prank(address(acp));
        router.beforeAction(jobId, SEL_SUBMIT, data);

        assertEq(globalHook1.beforeCalls(), 0);
        assertEq(jobHook.beforeCalls(), 0);
    }

    function test_beforeAction_skipsDeWhitelistedGlobal() public {
        uint256 jobId = _createJob();

        vm.prank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(globalHook1));

        // De-whitelist after configuration
        acp.setHookWhitelist(address(globalHook1), false);

        bytes memory data = abi.encode(client, bytes32(0), bytes(""));
        vm.prank(address(acp));
        router.beforeAction(jobId, SEL_SUBMIT, data);

        assertEq(globalHook1.beforeCalls(), 0);
    }

    // ──────────────────── Selector completeness with globals ────────────────────

    function test_validation_globalHookDeclaringRequired_mustBeOnAllResolvedSelectors() public {
        // Dependent hook requires SUBMIT + COMPLETE
        bytes4[] memory required = new bytes4[](2);
        required[0] = SEL_SUBMIT;
        required[1] = SEL_COMPLETE;
        DependentMockHook depHook = new DependentMockHook(required);
        acp.setHookWhitelist(address(depHook), true);

        uint256 jobId = _createJob();

        // Admin configures dep hook ONLY on SUBMIT globally → missing COMPLETE → revert at FUND
        vm.prank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(depHook));

        bytes memory fundData = abi.encode(client, bytes(""));
        vm.prank(address(acp));
        vm.expectRevert(MultiHookRouter.HookMissingRequiredSelector.selector);
        router.beforeAction(jobId, SEL_FUND, fundData);
    }

    function test_validation_globalHookOnAllRequired_passes() public {
        bytes4[] memory required = new bytes4[](2);
        required[0] = SEL_SUBMIT;
        required[1] = SEL_COMPLETE;
        DependentMockHook depHook = new DependentMockHook(required);
        acp.setHookWhitelist(address(depHook), true);

        uint256 jobId = _createJob();

        vm.startPrank(owner);
        router.addGlobalHook(SEL_SUBMIT, address(depHook));
        router.addGlobalHook(SEL_COMPLETE, address(depHook));
        vm.stopPrank();

        bytes memory fundData = abi.encode(client, bytes(""));
        vm.prank(address(acp));
        router.beforeAction(jobId, SEL_FUND, fundData);
        // no revert = pass
    }
}
