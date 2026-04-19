// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/hooks/TrustGateHook.sol";
import "../contracts/interfaces/IRNWYTrustOracle.sol";
import "@erc8183/AgenticCommerce.sol";
import "@erc8183/IACPHook.sol";

// ─── Mocks ────────────────────────────────────────────────────────────────────

/// @dev Minimal ACP stand-in — stores a job and can invoke hook callbacks.
contract MockACP {
    mapping(uint256 => AgenticCommerce.Job) private _jobs;

    function setJob(uint256 id, AgenticCommerce.Job memory job) external {
        _jobs[id] = job;
    }

    function getJob(uint256 id) external view returns (AgenticCommerce.Job memory) {
        return _jobs[id];
    }

    function triggerBefore(address hook, uint256 jobId, bytes4 selector, bytes memory data) external {
        IACPHook(hook).beforeAction(jobId, selector, data);
    }

    function triggerAfter(address hook, uint256 jobId, bytes4 selector, bytes memory data) external {
        IACPHook(hook).afterAction(jobId, selector, data);
    }
}

/// @dev Controllable trust oracle — owner sets pass/fail per agentId.
contract MockOracle is IRNWYTrustOracle {
    mapping(uint256 => bool) public passes;

    function setScore(uint256 agentId, bool pass_) external {
        passes[agentId] = pass_;
    }

    function getScore(uint256 agentId, uint256, string calldata)
        external view returns (uint8 score, uint8 tier, uint8 sybilSeverity, uint40 updatedAt)
    {
        score = passes[agentId] ? 80 : 20;
        tier = 0;
        sybilSeverity = 0;
        updatedAt = 0;
    }

    function hasScore(uint256, uint256, string calldata) external pure returns (bool) {
        return true;
    }

    function meetsThreshold(uint256 agentId, uint256, string calldata, uint8)
        external view returns (bool)
    {
        return passes[agentId];
    }

    function agentCount() external pure returns (uint256) { return 100; }
}

// ─── Test suite ───────────────────────────────────────────────────────────────

contract TrustGateHookTest is Test {
    MockACP    internal acp;
    MockOracle internal oracle;
    TrustGateHook internal hook;

    address internal CLIENT   = address(0x1001);
    address internal PROVIDER = address(0x1002);
    address internal EVALUATOR = address(0x1003);
    address internal STRANGER = address(0x9999);

    uint256 internal CLIENT_AGENT_ID   = 100;
    uint256 internal PROVIDER_AGENT_ID = 200;
    uint256 internal JOB_ID            = 1;
    uint8   internal THRESHOLD         = 50;

    bytes4 constant FUND_SEL     = bytes4(keccak256("fund(uint256,uint256,bytes)"));
    bytes4 constant SUBMIT_SEL   = bytes4(keccak256("submit(uint256,bytes32,bytes)"));
    bytes4 constant COMPLETE_SEL = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 constant REJECT_SEL   = bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    function setUp() public {
        acp    = new MockACP();
        oracle = new MockOracle();
        hook   = new TrustGateHook(
            address(acp),
            address(oracle),
            THRESHOLD,
            8453,
            "erc8004"
        );

        // Register agents
        hook.setAgentId(CLIENT,   CLIENT_AGENT_ID);
        hook.setAgentId(PROVIDER, PROVIDER_AGENT_ID);

        // Both pass by default
        oracle.setScore(CLIENT_AGENT_ID,   true);
        oracle.setScore(PROVIDER_AGENT_ID, true);
    }

    // ─── helpers ────────────────────────────────────────────────────────────

    function _fundedJob() internal view returns (AgenticCommerce.Job memory) {
        return AgenticCommerce.Job({
            id: JOB_ID,
            client: CLIENT,
            provider: PROVIDER,
            evaluator: EVALUATOR,
            description: "",
            budget: 100e6,
            expiredAt: block.timestamp + 1 days,
            status: AgenticCommerce.JobStatus.Funded,
            hook: address(hook),
            paymentToken: address(0),
            providerAgentId: PROVIDER_AGENT_ID,
            submittedAt: 0
        });
    }

    function _openZeroBudgetJob() internal view returns (AgenticCommerce.Job memory) {
        AgenticCommerce.Job memory j = _fundedJob();
        j.status = AgenticCommerce.JobStatus.Open;
        j.budget = 0;
        return j;
    }

    // ─── fund (preFund / client trust) ──────────────────────────────────────

    function test_fund_registeredAndTrusted_succeeds() public {
        bytes memory data = abi.encode(CLIENT, bytes(""));
        // Should not revert
        acp.triggerBefore(address(hook), JOB_ID, FUND_SEL, data);
    }

    function test_fund_unregistered_reverts() public {
        bytes memory data = abi.encode(STRANGER, bytes(""));
        vm.expectRevert(abi.encodeWithSelector(TrustGateHook.TrustGateHook__NoAgentId.selector, STRANGER));
        acp.triggerBefore(address(hook), JOB_ID, FUND_SEL, data);
    }

    function test_fund_belowThreshold_reverts() public {
        oracle.setScore(CLIENT_AGENT_ID, false);
        bytes memory data = abi.encode(CLIENT, bytes(""));
        vm.expectRevert(
            abi.encodeWithSelector(
                TrustGateHook.TrustGateHook__BelowThreshold.selector,
                JOB_ID, CLIENT, CLIENT_AGENT_ID, THRESHOLD
            )
        );
        acp.triggerBefore(address(hook), JOB_ID, FUND_SEL, data);
    }

    // ─── submit — funded path (only provider checked) ───────────────────────

    function test_submit_funded_providerTrusted_succeeds() public {
        acp.setJob(JOB_ID, _fundedJob());
        bytes memory data = abi.encode(PROVIDER, bytes32(0), bytes(""));
        // provider passes, job is Funded so client is NOT re-checked
        acp.triggerBefore(address(hook), JOB_ID, SUBMIT_SEL, data);
    }

    function test_submit_funded_providerBelowThreshold_reverts() public {
        acp.setJob(JOB_ID, _fundedJob());
        oracle.setScore(PROVIDER_AGENT_ID, false);
        bytes memory data = abi.encode(PROVIDER, bytes32(0), bytes(""));
        vm.expectRevert(
            abi.encodeWithSelector(
                TrustGateHook.TrustGateHook__BelowThreshold.selector,
                JOB_ID, PROVIDER, PROVIDER_AGENT_ID, THRESHOLD
            )
        );
        acp.triggerBefore(address(hook), JOB_ID, SUBMIT_SEL, data);
    }

    // ─── submit — zero-budget path (provider + client both checked) ──────────

    function test_submit_zeroBudget_bothTrusted_succeeds() public {
        acp.setJob(JOB_ID, _openZeroBudgetJob());
        bytes memory data = abi.encode(PROVIDER, bytes32(0), bytes(""));
        acp.triggerBefore(address(hook), JOB_ID, SUBMIT_SEL, data);
    }

    function test_submit_zeroBudget_clientUnregistered_reverts() public {
        AgenticCommerce.Job memory j = _openZeroBudgetJob();
        j.client = STRANGER; // not registered
        acp.setJob(JOB_ID, j);
        bytes memory data = abi.encode(PROVIDER, bytes32(0), bytes(""));
        vm.expectRevert(abi.encodeWithSelector(TrustGateHook.TrustGateHook__NoAgentId.selector, STRANGER));
        acp.triggerBefore(address(hook), JOB_ID, SUBMIT_SEL, data);
    }

    function test_submit_zeroBudget_clientBelowThreshold_reverts() public {
        acp.setJob(JOB_ID, _openZeroBudgetJob());
        oracle.setScore(CLIENT_AGENT_ID, false);
        bytes memory data = abi.encode(PROVIDER, bytes32(0), bytes(""));
        vm.expectRevert(
            abi.encodeWithSelector(
                TrustGateHook.TrustGateHook__BelowThreshold.selector,
                JOB_ID, CLIENT, CLIENT_AGENT_ID, THRESHOLD
            )
        );
        acp.triggerBefore(address(hook), JOB_ID, SUBMIT_SEL, data);
    }

    // ─── caller auth ─────────────────────────────────────────────────────────

    function test_beforeAction_nonACP_reverts() public {
        bytes memory data = abi.encode(CLIENT, bytes(""));
        vm.prank(STRANGER);
        vm.expectRevert(BaseERC8183Hook.OnlyERC8183Contract.selector);
        hook.beforeAction(JOB_ID, FUND_SEL, data);
    }

    function test_afterAction_nonACP_reverts() public {
        bytes memory data = abi.encode(CLIENT, bytes(""));
        vm.prank(STRANGER);
        vm.expectRevert(BaseERC8183Hook.OnlyERC8183Contract.selector);
        hook.afterAction(JOB_ID, COMPLETE_SEL, data);
    }

    // ─── outcome events ───────────────────────────────────────────────────────

    function test_complete_emitsOutcomeRecorded() public {
        bytes memory data = abi.encode(EVALUATOR, bytes32(0), bytes(""));
        vm.expectEmit(true, false, false, true, address(hook));
        emit TrustGateHook.OutcomeRecorded(JOB_ID, true);
        acp.triggerAfter(address(hook), JOB_ID, COMPLETE_SEL, data);
    }

    function test_reject_emitsOutcomeRecorded() public {
        bytes memory data = abi.encode(EVALUATOR, bytes32(0), bytes(""));
        vm.expectEmit(true, false, false, true, address(hook));
        emit TrustGateHook.OutcomeRecorded(JOB_ID, false);
        acp.triggerAfter(address(hook), JOB_ID, REJECT_SEL, data);
    }

    // ─── agentId = 0 correctness ─────────────────────────────────────────────

    function test_setAgentId_zeroId_registeredCorrectly() public {
        address wallet = address(0x5555);
        hook.setAgentId(wallet, 0); // agentId = 0 is valid
        oracle.setScore(0, true);

        bytes memory data = abi.encode(wallet, bytes(""));
        // Should not revert — wallet is registered (registered=true) even with agentId=0
        acp.triggerBefore(address(hook), JOB_ID, FUND_SEL, data);
    }

    function test_unregistered_agentIdZero_doesNotPassAsRegistered() public {
        // address never registered — despite mapping default being 0, should revert
        address newWallet = address(0x6666);
        bytes memory data = abi.encode(newWallet, bytes(""));
        vm.expectRevert(abi.encodeWithSelector(TrustGateHook.TrustGateHook__NoAgentId.selector, newWallet));
        acp.triggerBefore(address(hook), JOB_ID, FUND_SEL, data);
    }

    // ─── admin ────────────────────────────────────────────────────────────────

    function test_setOracle_zero_reverts() public {
        vm.expectRevert("TrustGateHook: zero oracle");
        hook.setOracle(address(0));
    }

    function test_setOracle_emitsEvent() public {
        MockOracle newOracle = new MockOracle();
        vm.expectEmit(true, true, false, false, address(hook));
        emit TrustGateHook.OracleUpdated(address(oracle), address(newOracle));
        hook.setOracle(address(newOracle));
    }

    function test_setThreshold_emitsEvent() public {
        vm.expectEmit(false, false, false, true, address(hook));
        emit TrustGateHook.ThresholdUpdated(THRESHOLD, 70);
        hook.setThreshold(70);
    }

    function test_setAgentId_emitsEvent() public {
        address wallet = address(0x7777);
        vm.expectEmit(true, false, false, true, address(hook));
        emit TrustGateHook.AgentIdSet(wallet, 999);
        hook.setAgentId(wallet, 999);
    }

    function test_setAgentIds_batchWorks() public {
        address[] memory wallets = new address[](2);
        uint256[] memory ids     = new uint256[](2);
        wallets[0] = address(0xAAAA);
        wallets[1] = address(0xBBBB);
        ids[0] = 300;
        ids[1] = 400;
        hook.setAgentIds(wallets, ids);
        assertEq(hook.agentIds(address(0xAAAA)), 300);
        assertEq(hook.agentIds(address(0xBBBB)), 400);
        assertTrue(hook.registered(address(0xAAAA)));
    }

    function test_constructor_zeroOracle_reverts() public {
        vm.expectRevert("TrustGateHook: zero oracle");
        new TrustGateHook(address(acp), address(0), THRESHOLD, 8453, "erc8004");
    }
}
