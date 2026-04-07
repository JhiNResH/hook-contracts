// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/hooks/MutualAttestationHook.sol";
import "../contracts/interfaces/IAttestationService.sol";

/// @notice Mock attestation service (stands in for EAS / BAS / SimpleAttestation)
contract MockAttestationService {
    uint256 public attestCount;
    mapping(uint256 => bytes) public attestData;

    function attest(IAttestationService.AttestationRequest calldata request) external payable returns (bytes32) {
        attestCount++;
        attestData[attestCount] = request.data.data;
        return bytes32(attestCount);
    }
}

/// @notice Mock ACP contract with getJob support
contract MockACP {
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

    mapping(uint256 => Job) public jobs;

    function setJob(uint256 jobId, address client, address provider) external {
        jobs[jobId] = Job({
            id: jobId,
            client: client,
            provider: provider,
            evaluator: address(0),
            hook: address(0),
            description: "",
            budget: 0,
            expiredAt: 0,
            status: 0
        });
    }

    function getJob(uint256 jobId) external view returns (Job memory) {
        return jobs[jobId];
    }
}

contract MutualAttestationHookTest is Test {
    MutualAttestationHook public hook;
    MockAttestationService public mockAttestation;
    MockACP public mockACP;

    address client = address(0xC1C1);
    address provider = address(0xD1D1);
    address attacker = address(0xBAD);
    uint256 jobId = 1;
    bytes32 schemaUID = bytes32(uint256(0xDEAD));

    function setUp() public {
        mockAttestation = new MockAttestationService();
        mockACP = new MockACP();
        hook = new MutualAttestationHook(
            address(mockACP),
            address(mockAttestation),
            schemaUID,
            7 days
        );

        // Set up job with real participants
        mockACP.setJob(jobId, client, provider);

        // Simulate job completion via afterAction from ACP
        _simulateJobCompletion(jobId);
    }

    function _simulateJobCompletion(uint256 _jobId) internal {
        // Call afterAction as ACP contract to trigger _postComplete
        bytes4 completeSelector = bytes4(keccak256("complete(uint256,bytes32,bytes)"));
        bytes memory data = abi.encode(bytes32(0), bytes(""));
        vm.prank(address(mockACP));
        hook.afterAction(_jobId, completeSelector, data);
    }

    function _simulateJobRejection(uint256 _jobId) internal {
        bytes4 rejectSelector = bytes4(keccak256("reject(uint256,bytes32,bytes)"));
        bytes memory data = abi.encode(bytes32(0), bytes(""));
        vm.prank(address(mockACP));
        hook.afterAction(_jobId, rejectSelector, data);
    }

    // === CRITICAL FIX: Access Control ===

    function test_revertIfNotClient() public {
        vm.prank(attacker);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__NotJobParticipant.selector);
        hook.submitClientReview(jobId, 5, "Fake review");
    }

    function test_revertIfNotProvider() public {
        vm.prank(attacker);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__NotJobParticipant.selector);
        hook.submitProviderReview(jobId, 4, "Fake review");
    }

    function test_revertIfProviderTriesToReviewAsClient() public {
        vm.prank(provider);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__NotJobParticipant.selector);
        hook.submitClientReview(jobId, 5, "Wrong role");
    }

    function test_revertIfClientTriesToReviewAsProvider() public {
        vm.prank(client);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__NotJobParticipant.selector);
        hook.submitProviderReview(jobId, 4, "Wrong role");
    }

    // === Basic Review Flow ===

    function test_clientCanReviewProvider() public {
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Great work!");

        assertTrue(hook.clientReviewed(jobId));
        assertFalse(hook.providerReviewed(jobId));
        assertEq(mockAttestation.attestCount(), 1);
    }

    function test_providerCanReviewClient() public {
        vm.prank(provider);
        hook.submitProviderReview(jobId, 4, "Clear specs, paid fast");

        assertFalse(hook.clientReviewed(jobId));
        assertTrue(hook.providerReviewed(jobId));
        assertEq(mockAttestation.attestCount(), 1);
    }

    function test_mutualReviewComplete() public {
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Excellent");
        vm.prank(provider);
        hook.submitProviderReview(jobId, 4, "Good client");

        assertTrue(hook.clientReviewed(jobId));
        assertTrue(hook.providerReviewed(jobId));
        assertTrue(hook.isFullyReviewed(jobId));
        assertEq(mockAttestation.attestCount(), 2);
    }

    // === Score Validation ===

    function test_revertOnScoreTooLow() public {
        vm.prank(client);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__InvalidScore.selector);
        hook.submitClientReview(jobId, 0, "Bad");
    }

    function test_revertOnScoreTooHigh() public {
        vm.prank(client);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__InvalidScore.selector);
        hook.submitClientReview(jobId, 6, "Too high");
    }

    function test_validScoreRange() public {
        for (uint8 score = 1; score <= 5; score++) {
            uint256 jid = 100 + score;
            mockACP.setJob(jid, client, provider);
            _simulateJobCompletion(jid);

            vm.prank(client);
            hook.submitClientReview(jid, score, "OK");
        }
        assertEq(mockAttestation.attestCount(), 5);
    }

    // === Double Review Prevention ===

    function test_revertOnDoubleClientReview() public {
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "First");

        vm.prank(client);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__AlreadyReviewed.selector);
        hook.submitClientReview(jobId, 3, "Second");
    }

    function test_revertOnDoubleProviderReview() public {
        vm.prank(provider);
        hook.submitProviderReview(jobId, 4, "First");

        vm.prank(provider);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__AlreadyReviewed.selector);
        hook.submitProviderReview(jobId, 2, "Second");
    }

    // === Review Window ===

    function test_revertAfterReviewWindowExpires() public {
        vm.warp(block.timestamp + 8 days);

        vm.prank(client);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__ReviewWindowExpired.selector);
        hook.submitClientReview(jobId, 5, "Too late");
    }

    function test_reviewWithinWindow() public {
        vm.warp(block.timestamp + 6 days);
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Just in time");
        assertEq(mockAttestation.attestCount(), 1);
    }

    // === Job Not Completed ===

    function test_revertIfJobNotCompleted() public {
        uint256 unknownJob = 999;
        mockACP.setJob(unknownJob, client, provider);
        // Don't call _simulateJobCompletion

        vm.prank(client);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__JobNotCompleted.selector);
        hook.submitClientReview(unknownJob, 5, "No job");
    }

    // === Rejected Jobs CAN Be Reviewed (LOW fix) ===

    function test_rejectedJobCanBeReviewed() public {
        uint256 rejectedJob = 50;
        mockACP.setJob(rejectedJob, client, provider);
        _simulateJobRejection(rejectedJob);

        vm.prank(client);
        hook.submitClientReview(rejectedJob, 2, "Provider ghosted");
        assertEq(mockAttestation.attestCount(), 1);

        vm.prank(provider);
        hook.submitProviderReview(rejectedJob, 1, "Vague specs");
        assertEq(mockAttestation.attestCount(), 2);
        assertTrue(hook.isFullyReviewed(rejectedJob));
    }

    // === Review Status ===

    function test_getReviewStatus() public {
        (bool clientDone, bool providerDone, uint256 deadline) = hook.getReviewStatus(jobId);

        assertFalse(clientDone);
        assertFalse(providerDone);
        assertGt(deadline, block.timestamp);
    }

    function test_getReviewStatusAfterBothReviews() public {
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Great");
        vm.prank(provider);
        hook.submitProviderReview(jobId, 4, "Good");

        (bool clientDone, bool providerDone,) = hook.getReviewStatus(jobId);
        assertTrue(clientDone);
        assertTrue(providerDone);
    }

    // === EAS Attestation Data ===

    function test_attestationContainsCorrectData() public {
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Excellent work");

        bytes memory attestData = mockAttestation.attestData(1);
        (
            uint256 decodedJobId,
            address reviewer,
            address reviewee,
            uint8 score,
            string memory comment,
            bool isClientReview
        ) = abi.decode(attestData, (uint256, address, address, uint8, string, bool));

        assertEq(decodedJobId, jobId);
        assertEq(reviewer, client);
        assertEq(reviewee, provider);
        assertEq(score, 5);
        assertEq(comment, "Excellent work");
        assertTrue(isClientReview);
    }

    function test_providerAttestationData() public {
        vm.prank(provider);
        hook.submitProviderReview(jobId, 3, "Vague specs");

        bytes memory attestData = mockAttestation.attestData(1);
        (,,, uint8 score, string memory comment, bool isClientReview) =
            abi.decode(attestData, (uint256, address, address, uint8, string, bool));

        assertEq(score, 3);
        assertEq(comment, "Vague specs");
        assertFalse(isClientReview);
    }

    // === Events ===

    function test_emitsReviewSubmitted() public {
        vm.prank(client);
        vm.expectEmit(true, true, true, false);
        emit MutualAttestationHook.ReviewSubmitted(
            jobId, client, provider, 5, bytes32(uint256(1)), true
        );
        hook.submitClientReview(jobId, 5, "Nice");
    }

    function test_emitsMutualReviewComplete() public {
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Good");

        vm.prank(provider);
        vm.expectEmit(true, false, false, false);
        emit MutualAttestationHook.MutualReviewComplete(jobId);
        hook.submitProviderReview(jobId, 4, "Good");
    }

    // === Attestation UIDs ===

    function test_storesAttestationUIDs() public {
        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Great");
        vm.prank(provider);
        hook.submitProviderReview(jobId, 4, "Good");

        assertEq(hook.clientAttestationUID(jobId), bytes32(uint256(1)));
        assertEq(hook.providerAttestationUID(jobId), bytes32(uint256(2)));
    }

    // === Multiple Jobs ===

    function test_multipleJobsIndependent() public {
        uint256 job2 = 2;
        mockACP.setJob(job2, client, provider);
        _simulateJobCompletion(job2);

        vm.prank(client);
        hook.submitClientReview(jobId, 5, "Job 1");
        vm.prank(client);
        hook.submitClientReview(job2, 3, "Job 2");

        assertTrue(hook.clientReviewed(jobId));
        assertTrue(hook.clientReviewed(job2));
        assertFalse(hook.providerReviewed(jobId));
        assertFalse(hook.providerReviewed(job2));
    }

    // === Job Participants Stored Correctly ===

    function test_jobParticipantsStoredOnComplete() public {
        assertEq(hook.jobClient(jobId), client);
        assertEq(hook.jobProvider(jobId), provider);
    }

    // === Fuzz Tests ===

    function testFuzz_validScores(uint8 score) public {
        vm.assume(score >= 1 && score <= 5);
        vm.prank(client);
        hook.submitClientReview(jobId, score, "Fuzz");
        assertEq(mockAttestation.attestCount(), 1);
    }

    function testFuzz_invalidScores(uint8 score) public {
        vm.assume(score == 0 || score > 5);
        vm.prank(client);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__InvalidScore.selector);
        hook.submitClientReview(jobId, score, "Bad");
    }

    function testFuzz_onlyParticipantsCanReview(address caller) public {
        vm.assume(caller != client && caller != address(0));
        vm.prank(caller);
        vm.expectRevert(MutualAttestationHook.MutualAttestationHook__NotJobParticipant.selector);
        hook.submitClientReview(jobId, 5, "Unauthorized");
    }

    // === Immutable reviewWindow ===

    function test_reviewWindowIsImmutable() public view {
        assertEq(hook.reviewWindow(), 7 days);
    }

    function test_defaultReviewWindow() public {
        MutualAttestationHook hook2 = new MutualAttestationHook(
            address(mockACP), address(mockAttestation), schemaUID, 0
        );
        assertEq(hook2.reviewWindow(), 7 days);
    }

    function test_customReviewWindow() public {
        MutualAttestationHook hook3 = new MutualAttestationHook(
            address(mockACP), address(mockAttestation), schemaUID, 3 days
        );
        assertEq(hook3.reviewWindow(), 3 days);
    }
}
