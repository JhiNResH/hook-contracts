// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../contracts/hooks/MutualAttestationHook.sol";

/// @notice Mock EAS that records attestations
contract MockEAS {
    uint256 public attestCount;
    mapping(uint256 => bytes) public attestData;

    function attest(IEAS.AttestationRequest calldata request) external payable returns (bytes32) {
        attestCount++;
        attestData[attestCount] = request.data.data;
        return bytes32(attestCount);
    }
}

/// @notice Mock ACP contract
contract MockACP {}

contract MutualAttestationHookTest is Test {
    MutualAttestationHook public hook;
    MockEAS public mockEAS;
    MockACP public mockACP;

    address client = address(0xC1C1);
    address provider = address(0xD1D1);
    bytes32 jobId = bytes32(uint256(1));
    bytes32 schemaUID = bytes32(uint256(0xDEAD));

    function setUp() public {
        mockEAS = new MockEAS();
        mockACP = new MockACP();
        hook = new MutualAttestationHook(
            address(mockACP),
            address(mockEAS),
            schemaUID,
            7 days
        );

        // Simulate job completion by calling _postComplete via afterAction
        // We need to set jobCompletedAt directly since we can't call through ACP
        // Use vm.store to set the mapping
        _simulateJobCompletion(jobId);
    }

    function _simulateJobCompletion(bytes32 _jobId) internal {
        // jobCompletedAt is at storage slot 1
        vm.store(
            address(hook),
            keccak256(abi.encode(_jobId, uint256(1))),
            bytes32(block.timestamp)
        );
    }

    // ─── Basic Review Flow ───────────────────────────────────────

    function test_clientCanReviewProvider() public {
        hook.submitClientReview(jobId, client, provider, 5, "Great work!");
        
        assertTrue(hook.clientReviewed(jobId));
        assertFalse(hook.providerReviewed(jobId));
        assertEq(mockEAS.attestCount(), 1);
    }

    function test_providerCanReviewClient() public {
        hook.submitProviderReview(jobId, provider, client, 4, "Clear specs, paid fast");
        
        assertFalse(hook.clientReviewed(jobId));
        assertTrue(hook.providerReviewed(jobId));
        assertEq(mockEAS.attestCount(), 1);
    }

    function test_mutualReviewComplete() public {
        hook.submitClientReview(jobId, client, provider, 5, "Excellent");
        hook.submitProviderReview(jobId, provider, client, 4, "Good client");

        assertTrue(hook.clientReviewed(jobId));
        assertTrue(hook.providerReviewed(jobId));
        assertTrue(hook.isFullyReviewed(jobId));
        assertEq(mockEAS.attestCount(), 2);
    }

    // ─── Score Validation ────────────────────────────────────────

    function test_revertOnScoreTooLow() public {
        vm.expectRevert(MutualAttestationHook.InvalidScore.selector);
        hook.submitClientReview(jobId, client, provider, 0, "Bad");
    }

    function test_revertOnScoreTooHigh() public {
        vm.expectRevert(MutualAttestationHook.InvalidScore.selector);
        hook.submitClientReview(jobId, client, provider, 6, "Too high");
    }

    function test_validScoreRange() public {
        for (uint8 score = 1; score <= 5; score++) {
            bytes32 jid = bytes32(uint256(100 + score));
            _simulateJobCompletion(jid);
            hook.submitClientReview(jid, client, provider, score, "OK");
        }
        assertEq(mockEAS.attestCount(), 5);
    }

    // ─── Double Review Prevention ────────────────────────────────

    function test_revertOnDoubleClientReview() public {
        hook.submitClientReview(jobId, client, provider, 5, "First");
        
        vm.expectRevert(MutualAttestationHook.AlreadyReviewed.selector);
        hook.submitClientReview(jobId, client, provider, 3, "Second");
    }

    function test_revertOnDoubleProviderReview() public {
        hook.submitProviderReview(jobId, provider, client, 4, "First");
        
        vm.expectRevert(MutualAttestationHook.AlreadyReviewed.selector);
        hook.submitProviderReview(jobId, provider, client, 2, "Second");
    }

    // ─── Review Window ───────────────────────────────────────────

    function test_revertAfterReviewWindowExpires() public {
        vm.warp(block.timestamp + 8 days);
        
        vm.expectRevert(MutualAttestationHook.ReviewWindowExpired.selector);
        hook.submitClientReview(jobId, client, provider, 5, "Too late");
    }

    function test_reviewWithinWindow() public {
        vm.warp(block.timestamp + 6 days);
        hook.submitClientReview(jobId, client, provider, 5, "Just in time");
        assertEq(mockEAS.attestCount(), 1);
    }

    // ─── Job Not Completed ───────────────────────────────────────

    function test_revertIfJobNotCompleted() public {
        bytes32 unknownJob = bytes32(uint256(999));
        
        vm.expectRevert(MutualAttestationHook.JobNotCompleted.selector);
        hook.submitClientReview(unknownJob, client, provider, 5, "No job");
    }

    // ─── Review Status ───────────────────────────────────────────

    function test_getReviewStatus() public {
        (bool clientDone, bool providerDone, uint256 deadline) = hook.getReviewStatus(jobId);
        
        assertFalse(clientDone);
        assertFalse(providerDone);
        assertGt(deadline, block.timestamp);
    }

    function test_getReviewStatusAfterBothReviews() public {
        hook.submitClientReview(jobId, client, provider, 5, "Great");
        hook.submitProviderReview(jobId, provider, client, 4, "Good");

        (bool clientDone, bool providerDone,) = hook.getReviewStatus(jobId);
        assertTrue(clientDone);
        assertTrue(providerDone);
    }

    // ─── EAS Attestation Data ────────────────────────────────────

    function test_attestationContainsCorrectData() public {
        hook.submitClientReview(jobId, client, provider, 5, "Excellent work");

        bytes memory attestData = mockEAS.attestData(1);
        (
            bytes32 decodedJobId,
            address reviewer,
            address reviewee,
            uint8 score,
            string memory comment,
            bool isClientReview
        ) = abi.decode(attestData, (bytes32, address, address, uint8, string, bool));

        assertEq(decodedJobId, jobId);
        assertEq(reviewer, client);
        assertEq(reviewee, provider);
        assertEq(score, 5);
        assertEq(comment, "Excellent work");
        assertTrue(isClientReview);
    }

    function test_providerAttestationData() public {
        hook.submitProviderReview(jobId, provider, client, 3, "Vague specs");

        bytes memory attestData = mockEAS.attestData(1);
        (,,, uint8 score, string memory comment, bool isClientReview) = 
            abi.decode(attestData, (bytes32, address, address, uint8, string, bool));

        assertEq(score, 3);
        assertEq(comment, "Vague specs");
        assertFalse(isClientReview);
    }

    // ─── Events ──────────────────────────────────────────────────

    function test_emitsReviewSubmitted() public {
        vm.expectEmit(true, true, true, false);
        emit MutualAttestationHook.ReviewSubmitted(
            jobId, client, provider, 5, bytes32(uint256(1)), true
        );
        hook.submitClientReview(jobId, client, provider, 5, "Nice");
    }

    function test_emitsMutualReviewComplete() public {
        hook.submitClientReview(jobId, client, provider, 5, "Good");
        
        vm.expectEmit(true, false, false, false);
        emit MutualAttestationHook.MutualReviewComplete(jobId);
        hook.submitProviderReview(jobId, provider, client, 4, "Good");
    }

    // ─── Attestation UIDs ────────────────────────────────────────

    function test_storesAttestationUIDs() public {
        hook.submitClientReview(jobId, client, provider, 5, "Great");
        hook.submitProviderReview(jobId, provider, client, 4, "Good");

        assertEq(hook.clientAttestationUID(jobId), bytes32(uint256(1)));
        assertEq(hook.providerAttestationUID(jobId), bytes32(uint256(2)));
    }

    // ─── Multiple Jobs ───────────────────────────────────────────

    function test_multipleJobsIndependent() public {
        bytes32 job2 = bytes32(uint256(2));
        _simulateJobCompletion(job2);

        hook.submitClientReview(jobId, client, provider, 5, "Job 1");
        hook.submitClientReview(job2, client, provider, 3, "Job 2");

        assertTrue(hook.clientReviewed(jobId));
        assertTrue(hook.clientReviewed(job2));
        assertFalse(hook.providerReviewed(jobId));
        assertFalse(hook.providerReviewed(job2));
    }

    // ─── Fuzz Tests ──────────────────────────────────────────────

    function testFuzz_validScores(uint8 score) public {
        vm.assume(score >= 1 && score <= 5);
        hook.submitClientReview(jobId, client, provider, score, "Fuzz");
        assertEq(mockEAS.attestCount(), 1);
    }

    function testFuzz_invalidScores(uint8 score) public {
        vm.assume(score == 0 || score > 5);
        vm.expectRevert(MutualAttestationHook.InvalidScore.selector);
        hook.submitClientReview(jobId, client, provider, score, "Bad");
    }
}
