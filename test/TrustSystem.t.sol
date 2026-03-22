// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TrustBasedEvaluator, IAgenticCommerce, IEvaluatorRegistry} from "../contracts/hooks/TrustBasedEvaluator.sol";
import {TrustGateACPHook} from "../contracts/hooks/TrustGateACPHook.sol";
import {EvaluatorRegistry} from "../contracts/EvaluatorRegistry.sol";
import {ITrustOracle} from "../contracts/interfaces/ITrustOracle.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/*//////////////////////////////////////////////////////////////
                        MOCKS
//////////////////////////////////////////////////////////////*/

contract MockOracle is ITrustOracle {
    mapping(address => UserReputation) public reps;

    function setRep(address user, uint256 score, bool initialized) external {
        reps[user] = UserReputation(score, 0, initialized, block.timestamp);
    }

    function getUserData(address user) external view override returns (UserReputation memory) {
        return reps[user];
    }
}

contract MockAC {
    IAgenticCommerce.Job[] public jobs;
    address public hook;
    uint256 public lastCompletedJobId;
    uint256 public lastRejectedJobId;

    function setHook(address hook_) external { hook = hook_; }

    function addJob(
        uint256 id, address client, address provider, address evaluator, uint256 budget
    ) external {
        jobs.push(IAgenticCommerce.Job({
            id: id, client: client, provider: provider, evaluator: evaluator,
            description: "", budget: budget,
            expiredAt: block.timestamp + 1 days,
            status: IAgenticCommerce.JobStatus.Submitted, hook: hook
        }));
    }

    function getJob(uint256 jobId) external view returns (IAgenticCommerce.Job memory) {
        for (uint256 i = 0; i < jobs.length; i++) {
            if (jobs[i].id == jobId) return jobs[i];
        }
        revert("JOB_NOT_FOUND");
    }

    function complete(uint256 jobId, bytes32, bytes calldata) external {
        lastCompletedJobId = jobId;
    }

    function reject(uint256 jobId, bytes32, bytes calldata) external {
        lastRejectedJobId = jobId;
    }
}

/*//////////////////////////////////////////////////////////////
                TRUST BASED EVALUATOR TESTS
//////////////////////////////////////////////////////////////*/

contract TrustBasedEvaluatorTest is Test {
    TrustBasedEvaluator public impl;
    TrustBasedEvaluator public evaluator;
    MockOracle public oracle;
    MockAC public ac;
    EvaluatorRegistry public regImpl;
    EvaluatorRegistry public registry;

    address public owner = makeAddr("owner");
    address public provider = makeAddr("provider");
    address public client = makeAddr("client");

    function setUp() public {
        oracle = new MockOracle();
        ac = new MockAC();

        // Deploy evaluator behind proxy
        impl = new TrustBasedEvaluator();
        bytes memory initData = abi.encodeCall(
            TrustBasedEvaluator.initialize,
            (address(oracle), address(ac), 50, owner)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        evaluator = TrustBasedEvaluator(address(proxy));

        // Deploy registry behind proxy
        regImpl = new EvaluatorRegistry();
        bytes memory regInit = abi.encodeCall(EvaluatorRegistry.initialize, (owner));
        ERC1967Proxy regProxy = new ERC1967Proxy(address(regImpl), regInit);
        registry = EvaluatorRegistry(address(regProxy));

        // Wire up
        ac.setHook(address(evaluator));
        ac.addJob(1, client, provider, address(evaluator), 100 ether);

        // Set registry + authorize evaluator
        vm.startPrank(owner);
        evaluator.setRegistry(address(registry));
        registry.register("trust", address(evaluator));
        registry.setAuthorized(address(evaluator), true);
        vm.stopPrank();
    }

    // --- Constructor ---

    function test_impl_cannotBeInitialized() public {
        vm.expectRevert();
        impl.initialize(address(oracle), address(ac), 50, owner);
    }

    function test_initialize_zeroOracle() public {
        TrustBasedEvaluator newImpl = new TrustBasedEvaluator();
        vm.expectRevert(TrustBasedEvaluator.TrustBasedEvaluator__ZeroAddress.selector);
        new ERC1967Proxy(address(newImpl), abi.encodeCall(
            TrustBasedEvaluator.initialize, (address(0), address(ac), 50, owner)
        ));
    }

    function test_initialize_zeroAC() public {
        TrustBasedEvaluator newImpl = new TrustBasedEvaluator();
        vm.expectRevert(TrustBasedEvaluator.TrustBasedEvaluator__ZeroAddress.selector);
        new ERC1967Proxy(address(newImpl), abi.encodeCall(
            TrustBasedEvaluator.initialize, (address(oracle), address(0), 50, owner)
        ));
    }

    // --- Evaluate ---

    function test_evaluate_approved() public {
        oracle.setRep(provider, 80, true);

        evaluator.evaluate(1);

        assertEq(ac.lastCompletedJobId(), 1);
        assertEq(evaluator.totalEvaluated(), 1);
        assertEq(evaluator.totalApproved(), 1);
        assertTrue(evaluator.evaluated(1));
    }

    function test_evaluate_rejected() public {
        oracle.setRep(provider, 30, true);

        evaluator.evaluate(1);

        assertEq(ac.lastRejectedJobId(), 1);
        assertEq(evaluator.totalRejected(), 1);
    }

    function test_evaluate_uninitializedOracle_rejectsWithZeroScore() public {
        // provider not set in oracle → initialized=false → score=0 → rejected
        evaluator.evaluate(1);
        assertEq(ac.lastRejectedJobId(), 1);
    }

    function test_evaluate_revertAlreadyEvaluated() public {
        oracle.setRep(provider, 80, true);
        evaluator.evaluate(1);

        vm.expectRevert(abi.encodeWithSelector(
            TrustBasedEvaluator.TrustBasedEvaluator__AlreadyEvaluated.selector, 1
        ));
        evaluator.evaluate(1);
    }

    function test_evaluate_revertNotAssignedEvaluator() public {
        // Job with different evaluator
        ac.addJob(99, client, provider, makeAddr("otherEval"), 100 ether);
        vm.expectRevert(abi.encodeWithSelector(
            TrustBasedEvaluator.TrustBasedEvaluator__NotAssignedEvaluator.selector, 99
        ));
        evaluator.evaluate(99);
    }

    function test_evaluate_oracleScoreCappedAtMax() public {
        // Oracle returns 999 → should be capped to 100
        oracle.setRep(provider, 999, true);
        evaluator.evaluate(1);
        assertEq(ac.lastCompletedJobId(), 1); // Still approved (100 >= 50)
    }

    function test_evaluate_recordsToRegistry() public {
        oracle.setRep(provider, 80, true);
        evaluator.evaluate(1);

        (uint256 totalJobs,,,,) = registry.getStats(address(evaluator));
        assertEq(totalJobs, 1);
    }

    // --- Admin ---

    function test_setOracle_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(TrustBasedEvaluator.TrustBasedEvaluator__ZeroAddress.selector);
        evaluator.setOracle(address(0));
    }

    function test_setAgenticCommerce_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(TrustBasedEvaluator.TrustBasedEvaluator__ZeroAddress.selector);
        evaluator.setAgenticCommerce(address(0));
    }

    function test_setOracle_emitsEvent() public {
        address newOracle = makeAddr("newOracle");
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit TrustBasedEvaluator.OracleUpdated(address(oracle), newOracle);
        evaluator.setOracle(newOracle);
    }

    function test_setMinTrustScore_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit TrustBasedEvaluator.MinTrustScoreUpdated(50, 75);
        evaluator.setMinTrustScore(75);
    }

    function test_admin_revertNotOwner() public {
        vm.prank(makeAddr("rando"));
        vm.expectRevert();
        evaluator.setOracle(makeAddr("x"));
    }

    // --- Fuzz ---

    function testFuzz_evaluate_scoreThreshold(uint256 score, uint256 threshold) public {
        score = bound(score, 0, 100);
        threshold = bound(threshold, 0, 100);

        oracle.setRep(provider, score, true);
        vm.prank(owner);
        evaluator.setMinTrustScore(threshold);

        // Need fresh job each fuzz run
        uint256 jobId = uint256(keccak256(abi.encode(score, threshold)));
        ac.addJob(jobId, client, provider, address(evaluator), 1 ether);

        evaluator.evaluate(jobId);

        if (score >= threshold) {
            assertEq(ac.lastCompletedJobId(), jobId);
        } else {
            assertEq(ac.lastRejectedJobId(), jobId);
        }
    }
}

/*//////////////////////////////////////////////////////////////
                TRUST GATE ACP HOOK TESTS
//////////////////////////////////////////////////////////////*/

contract TrustGateACPHookTest is Test {
    TrustGateACPHook public impl;
    TrustGateACPHook public hook;
    MockOracle public oracle;
    MockAC public ac;

    address public owner = makeAddr("owner");
    address public client = makeAddr("client");
    address public provider = makeAddr("provider");

    bytes4 public constant FUND_SEL = bytes4(keccak256("fund(uint256,bytes)"));
    bytes4 public constant SUBMIT_SEL = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 public constant COMPLETE_SEL = bytes4(keccak256("complete(uint256,bytes32,bytes)"));

    function setUp() public {
        oracle = new MockOracle();
        ac = new MockAC();

        impl = new TrustGateACPHook();
        bytes memory initData = abi.encodeCall(
            TrustGateACPHook.initialize,
            (address(oracle), address(ac), 50, 60, owner)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        hook = TrustGateACPHook(address(proxy));
    }

    // --- Constructor ---

    function test_impl_cannotBeInitialized() public {
        vm.expectRevert();
        impl.initialize(address(oracle), address(ac), 50, 60, owner);
    }

    function test_initialize_zeroOracle() public {
        TrustGateACPHook newImpl = new TrustGateACPHook();
        vm.expectRevert(TrustGateACPHook.TrustGateACPHook__ZeroAddress.selector);
        new ERC1967Proxy(address(newImpl), abi.encodeCall(
            TrustGateACPHook.initialize, (address(0), address(ac), 50, 60, owner)
        ));
    }

    // --- Access Control ---

    function test_beforeAction_revertNotAC() public {
        vm.prank(makeAddr("rando"));
        vm.expectRevert(TrustGateACPHook.TrustGateACPHook__OnlyAgenticCommerce.selector);
        hook.beforeAction(1, FUND_SEL, abi.encode(client, bytes("")));
    }

    function test_afterAction_revertNotAC() public {
        vm.prank(makeAddr("rando"));
        vm.expectRevert(TrustGateACPHook.TrustGateACPHook__OnlyAgenticCommerce.selector);
        hook.afterAction(1, COMPLETE_SEL, bytes(""));
    }

    // --- beforeAction ---

    function test_beforeAction_fund_passes() public {
        oracle.setRep(client, 80, true);
        vm.prank(address(ac));
        hook.beforeAction(1, FUND_SEL, abi.encode(client, bytes("")));
        // No revert = pass
    }

    function test_beforeAction_fund_reverts_lowTrust() public {
        oracle.setRep(client, 30, true);
        vm.prank(address(ac));
        vm.expectRevert();
        hook.beforeAction(1, FUND_SEL, abi.encode(client, bytes("")));
    }

    function test_beforeAction_submit_passes() public {
        oracle.setRep(provider, 80, true);
        vm.prank(address(ac));
        hook.beforeAction(1, SUBMIT_SEL, abi.encode(provider, bytes32(0), bytes("")));
    }

    function test_beforeAction_submit_reverts_lowTrust() public {
        oracle.setRep(provider, 40, true);
        vm.prank(address(ac));
        vm.expectRevert();
        hook.beforeAction(1, SUBMIT_SEL, abi.encode(provider, bytes32(0), bytes("")));
    }

    // --- afterAction ---

    function test_afterAction_emitsOutcomeRecorded() public {
        vm.prank(address(ac));
        vm.expectEmit(true, false, false, true);
        emit TrustGateACPHook.OutcomeRecorded(1, true);
        hook.afterAction(1, COMPLETE_SEL, bytes(""));
    }

    // --- Tiers ---

    function test_setTierThreshold() public {
        vm.prank(owner);
        hook.setTierThreshold(1000 ether, 70);

        TrustGateACPHook.Tier[] memory tiers = hook.getTiers();
        assertEq(tiers.length, 1);
        assertEq(tiers[0].minValue, 1000 ether);
        assertEq(tiers[0].requiredScore, 70);
    }

    function test_setTierThreshold_maxTiers() public {
        vm.startPrank(owner);
        for (uint256 i = 0; i < 20; i++) {
            hook.setTierThreshold(i * 1000, 50 + i);
        }
        // 21st should revert
        vm.expectRevert(TrustGateACPHook.TrustGateACPHook__MaxTiersReached.selector);
        hook.setTierThreshold(99999, 99);
        vm.stopPrank();
    }

    function test_removeTier() public {
        vm.startPrank(owner);
        hook.setTierThreshold(1000, 60);
        hook.setTierThreshold(5000, 80);
        hook.removeTier(1000);
        vm.stopPrank();

        TrustGateACPHook.Tier[] memory tiers = hook.getTiers();
        assertEq(tiers.length, 1);
        assertEq(tiers[0].minValue, 5000);
    }

    function test_removeTier_notFound() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(
            TrustGateACPHook.TrustGateACPHook__TierNotFound.selector, 9999
        ));
        hook.removeTier(9999);
    }

    // --- Admin ---

    function test_setOracle_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(TrustGateACPHook.TrustGateACPHook__ZeroAddress.selector);
        hook.setOracle(address(0));
    }

    function test_setAgenticCommerce_zeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(TrustGateACPHook.TrustGateACPHook__ZeroAddress.selector);
        hook.setAgenticCommerce(address(0));
    }

    function test_setThresholds_emitsEvent() public {
        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit TrustGateACPHook.ThresholdsUpdated(70, 80);
        hook.setThresholds(70, 80);
    }

    // --- ERC-165 ---

    function test_supportsInterface() public view {
        // IACPHook has beforeAction + afterAction but no interfaceId constant
        // Just check ERC-165 itself
        assertTrue(hook.supportsInterface(0x01ffc9a7));
    }
}

/*//////////////////////////////////////////////////////////////
                EVALUATOR REGISTRY TESTS
//////////////////////////////////////////////////////////////*/

contract EvaluatorRegistryTest is Test {
    EvaluatorRegistry public impl;
    EvaluatorRegistry public registry;

    address public owner = makeAddr("owner");
    address public eval1 = makeAddr("eval1");
    address public eval2 = makeAddr("eval2");
    address public authorized = makeAddr("authorized");

    function setUp() public {
        impl = new EvaluatorRegistry();
        bytes memory initData = abi.encodeCall(EvaluatorRegistry.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        registry = EvaluatorRegistry(address(proxy));

        vm.startPrank(owner);
        registry.register("trust", eval1);
        registry.setAuthorized(authorized, true);
        vm.stopPrank();
    }

    // --- Constructor ---

    function test_impl_cannotBeInitialized() public {
        vm.expectRevert();
        impl.initialize(owner);
    }

    // --- Registration ---

    function test_register_success() public {
        assertEq(registry.getEvaluatorCount("trust"), 1);
        (,,,, bool active) = registry.getStats(eval1);
        assertTrue(active);
    }

    function test_register_revertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(EvaluatorRegistry.EvaluatorRegistry__ZeroAddress.selector);
        registry.register("trust", address(0));
    }

    function test_register_revertEmpty() public {
        vm.prank(owner);
        vm.expectRevert(EvaluatorRegistry.EvaluatorRegistry__EmptyDomain.selector);
        registry.register("", eval2);
    }

    function test_register_revertDuplicate() public {
        vm.prank(owner);
        vm.expectRevert();
        registry.register("trust", eval1);
    }

    // --- Remove ---

    function test_remove_success() public {
        vm.prank(owner);
        registry.remove("trust", eval1);
        assertEq(registry.getEvaluatorCount("trust"), 0);
    }

    function test_remove_revertNotRegistered() public {
        vm.prank(owner);
        vm.expectRevert();
        registry.remove("trust", eval2);
    }

    // --- recordOutcome ---

    function test_recordOutcome_success() public {
        vm.prank(authorized);
        registry.recordOutcome(eval1, true);
        (uint256 totalJobs, uint256 totalApproved,,,) = registry.getStats(eval1);
        assertEq(totalJobs, 1);
        assertEq(totalApproved, 1);
    }

    function test_recordOutcome_revertNotAuthorized() public {
        vm.prank(makeAddr("rando"));
        vm.expectRevert(EvaluatorRegistry.EvaluatorRegistry__NotAuthorized.selector);
        registry.recordOutcome(eval1, true);
    }

    function test_recordOutcome_revertNotRegistered() public {
        vm.prank(authorized);
        vm.expectRevert(abi.encodeWithSelector(
            EvaluatorRegistry.EvaluatorRegistry__NotRegisteredAnywhere.selector,
            makeAddr("phantom")
        ));
        registry.recordOutcome(makeAddr("phantom"), true);
    }

    function test_recordOutcome_autoDelist() public {
        // Set threshold: 50% after 5 jobs
        vm.prank(owner);
        registry.setThreshold(5000, 5);

        vm.startPrank(authorized);
        // Record 5 rejections → 0% success → delist
        for (uint256 i = 0; i < 5; i++) {
            registry.recordOutcome(eval1, false);
        }
        vm.stopPrank();

        (,,,, bool active) = registry.getStats(eval1);
        assertFalse(active);
    }

    // --- reactivate ---

    function test_reactivate_success() public {
        // Delist first
        vm.prank(owner);
        registry.setThreshold(5000, 1);
        vm.prank(authorized);
        registry.recordOutcome(eval1, false);
        (,,,, bool active1) = registry.getStats(eval1);
        assertFalse(active1);

        // Reactivate
        vm.prank(owner);
        registry.reactivate(eval1);
        (,,,, bool active2) = registry.getStats(eval1);
        assertTrue(active2);
    }

    function test_reactivate_revertNotRegistered() public {
        vm.prank(owner);
        vm.expectRevert();
        registry.reactivate(makeAddr("phantom"));
    }

    // --- getEvaluator ---

    function test_getEvaluator_returnsBest() public {
        vm.prank(owner);
        registry.register("trust", eval2);

        vm.startPrank(authorized);
        // eval1: 1 approve = 100%
        registry.recordOutcome(eval1, true);
        // eval2: 1 reject = 0%
        registry.recordOutcome(eval2, false);
        vm.stopPrank();

        assertEq(registry.getEvaluator("trust"), eval1);
    }

    function test_getEvaluator_emptyDomain() public view {
        assertEq(registry.getEvaluator("nonexistent"), address(0));
    }

    // --- Domains ---

    function test_getDomains() public {
        vm.prank(owner);
        registry.register("code-review", eval2);

        string[] memory domains = registry.getDomains();
        assertEq(domains.length, 2);
    }

    // --- Fuzz ---

    function testFuzz_recordOutcome_neverReverts(bool approved) public {
        vm.prank(authorized);
        registry.recordOutcome(eval1, approved);
        (uint256 totalJobs,,,,) = registry.getStats(eval1);
        assertEq(totalJobs, 1);
    }

    function testFuzz_register_multipleEvaluators(uint8 count) public {
        count = uint8(bound(count, 1, 20));
        vm.startPrank(owner);
        for (uint8 i = 0; i < count; i++) {
            address eval = makeAddr(string(abi.encodePacked("eval", i)));
            registry.register("fuzz-domain", eval);
        }
        vm.stopPrank();
        assertEq(registry.getEvaluatorCount("fuzz-domain"), count);
    }
}
