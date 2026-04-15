// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/hooks/MultiHookRouter.sol";
import "@acp/IACPHook.sol";
import "@acp/AgenticCommerce.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

/// @dev Minimal mock hook that records calls
contract MockHook is ERC165, IACPHook {
    uint256 public beforeCalls;
    uint256 public afterCalls;
    uint256 public lastJobId;

    function beforeAction(uint256 jobId, bytes4, bytes calldata) external override {
        beforeCalls++;
        lastJobId = jobId;
    }

    function afterAction(uint256 jobId, bytes4, bytes calldata) external override {
        afterCalls++;
        lastJobId = jobId;
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IACPHook).interfaceId || super.supportsInterface(interfaceId);
    }
}

contract MultiHookRouterGlobalTest is Test {
    MultiHookRouter router;
    AgenticCommerce acp;

    MockHook globalHook1;
    MockHook globalHook2;
    MockHook jobHook;

    address owner = makeAddr("owner");
    address client = makeAddr("client");
    address provider = makeAddr("provider");

    function setUp() public {
        // Deploy ACP via proxy — msg.sender (this) gets ADMIN_ROLE
        vm.startPrank(owner);
        AgenticCommerce impl = new AgenticCommerce();
        bytes memory initData = abi.encodeCall(
            AgenticCommerce.initialize,
            (owner)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        acp = AgenticCommerce(address(proxy));

        // Deploy router
        router = new MultiHookRouter(address(acp), owner, 10);

        // Deploy mock hooks
        globalHook1 = new MockHook();
        globalHook2 = new MockHook();
        jobHook = new MockHook();

        // Whitelist hooks on ACP
        acp.setHookWhitelist(address(router), true);
        acp.setHookWhitelist(address(globalHook1), true);
        acp.setHookWhitelist(address(globalHook2), true);
        acp.setHookWhitelist(address(jobHook), true);
        vm.stopPrank();
    }

    // ──────── Global hook admin ────────

    function test_addGlobalHook() public {
        vm.prank(owner);
        router.addGlobalHook(address(globalHook1));

        assertEq(router.globalHookCount(), 1);
        assertTrue(router.isGlobalHook(address(globalHook1)));
    }

    function test_addGlobalHook_revertDuplicate() public {
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        vm.expectRevert(MultiHookRouter.GlobalHookAlreadyRegistered.selector);
        router.addGlobalHook(address(globalHook1));
        vm.stopPrank();
    }

    function test_addGlobalHook_revertNonOwner() public {
        vm.prank(client);
        vm.expectRevert();
        router.addGlobalHook(address(globalHook1));
    }

    function test_removeGlobalHook() public {
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        router.addGlobalHook(address(globalHook2));
        router.removeGlobalHook(address(globalHook1));
        vm.stopPrank();

        assertEq(router.globalHookCount(), 1);
        assertFalse(router.isGlobalHook(address(globalHook1)));
        assertTrue(router.isGlobalHook(address(globalHook2)));
    }

    function test_removeGlobalHook_revertNotFound() public {
        vm.prank(owner);
        vm.expectRevert(MultiHookRouter.GlobalHookNotFound.selector);
        router.removeGlobalHook(address(globalHook1));
    }

    function test_reorderGlobalHooks() public {
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        router.addGlobalHook(address(globalHook2));

        address[] memory reordered = new address[](2);
        reordered[0] = address(globalHook2);
        reordered[1] = address(globalHook1);
        router.reorderGlobalHooks(reordered);
        vm.stopPrank();

        address[] memory result = router.getGlobalHooks();
        assertEq(result[0], address(globalHook2));
        assertEq(result[1], address(globalHook1));
    }

    function test_maxGlobalHooks() public {
        vm.startPrank(owner);
        for (uint256 i; i < 10; i++) {
            MockHook h = new MockHook();
            acp.setHookWhitelist(address(h), true);
            router.addGlobalHook(address(h));
        }
        MockHook extra = new MockHook();
        acp.setHookWhitelist(address(extra), true);
        vm.expectRevert(MultiHookRouter.TooManyGlobalHooks.selector);
        router.addGlobalHook(address(extra));
        vm.stopPrank();
    }

    // ──────── Resolution: global fallback ────────

    function test_beforeAction_usesGlobalHooks() public {
        // Setup global hooks
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        router.addGlobalHook(address(globalHook2));
        vm.stopPrank();

        // Create a job with router as hook
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(router), 0);

        // Trigger beforeAction via ACP — fund triggers hooks
        // We simulate ACP calling router directly since it's the expected path
        vm.prank(address(acp));
        router.beforeAction(jobId, bytes4(keccak256("fund(uint256,uint256,bytes)")), "");

        assertEq(globalHook1.beforeCalls(), 1);
        assertEq(globalHook2.beforeCalls(), 1);
    }

    function test_afterAction_usesGlobalHooks() public {
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        vm.stopPrank();

        vm.prank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(router), 0);

        // createJob calls afterAction once, so afterCalls starts at 1
        uint256 callsBefore = globalHook1.afterCalls();

        vm.prank(address(acp));
        router.afterAction(jobId, bytes4(keccak256("complete(uint256,bytes)")), "");

        assertEq(globalHook1.afterCalls(), callsBefore + 1);
    }

    // ──────── Resolution: per-job overrides global ────────

    function test_perJobHooks_overrideGlobal() public {
        // Setup global hook
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        vm.stopPrank();

        // Create job
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(router), 0);

        // Configure per-job hook
        address[] memory perJob = new address[](1);
        perJob[0] = address(jobHook);
        vm.prank(client);
        router.configureHooks(jobId, perJob);

        // Trigger — should use per-job, not global
        vm.prank(address(acp));
        router.beforeAction(jobId, bytes4(keccak256("fund(uint256,uint256,bytes)")), "");

        assertEq(jobHook.beforeCalls(), 1);
        assertEq(globalHook1.beforeCalls(), 0, "global hook should NOT be called when per-job is set");
    }

    // ──────── Resolution: no hooks = no-op ────────

    function test_noHooks_noop() public {
        vm.prank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(router), 0);

        // No global hooks, no per-job hooks — should not revert
        vm.prank(address(acp));
        router.beforeAction(jobId, bytes4(keccak256("fund(uint256,uint256,bytes)")), "");
    }

    // ──────── resolveHooks view ────────

    function test_resolveHooks_returnsGlobalWhenNoPerJob() public {
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        router.addGlobalHook(address(globalHook2));
        vm.stopPrank();

        vm.prank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(router), 0);

        address[] memory resolved = router.resolveHooks(jobId);
        assertEq(resolved.length, 2);
        assertEq(resolved[0], address(globalHook1));
        assertEq(resolved[1], address(globalHook2));
    }

    function test_resolveHooks_returnsPerJobWhenSet() public {
        vm.startPrank(owner);
        router.addGlobalHook(address(globalHook1));
        vm.stopPrank();

        vm.prank(client);
        uint256 jobId = acp.createJob(provider, owner, block.timestamp + 1 days, "test", address(router), 0);

        address[] memory perJob = new address[](1);
        perJob[0] = address(jobHook);
        vm.prank(client);
        router.configureHooks(jobId, perJob);

        address[] memory resolved = router.resolveHooks(jobId);
        assertEq(resolved.length, 1);
        assertEq(resolved[0], address(jobHook));
    }
}
