// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseACPHook} from "../BaseACPHook.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @notice Minimal interface to read job participants from AgenticCommerceHooked
interface IAgenticCommerceReader {
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
    function getJob(uint256 jobId) external view returns (Job memory);
}

/// @notice Minimal EAS interface (Base: 0x4200000000000000000000000000000000000021)
interface IEAS {
    struct AttestationRequestData {
        address recipient;
        uint64 expirationTime;
        bool revocable;
        bytes32 refUID;
        bytes data;
        uint256 value;
    }

    struct AttestationRequest {
        bytes32 schema;
        AttestationRequestData data;
    }

    function attest(AttestationRequest calldata request) external payable returns (bytes32);
}

/**
 * @title MutualAttestationHook
 * @notice Airbnb-style bilateral review system — both client and provider
 *         attest each other on EAS after job completion, building two-sided
 *         on-chain reputation.
 *
 * USE CASE
 * --------
 * One-sided reviews create incentive problems: clients can post vague
 * specs without accountability, and providers can deliver poor work while
 * blaming the spec. MutualAttestationHook requires both parties to leave
 * an EAS attestation within a configurable review window after a job
 * completes. Clients rate provider quality; providers rate client
 * behaviour. Both sides accumulate verifiable on-chain reputation scores
 * that downstream trust systems (e.g. ERC-8004) can consume.
 *
 * FLOW (all interactions through core contract → hook callbacks)
 * ----
 *  1. createJob(provider, evaluator, expiredAt, description, hook=this)
 *  2. fund(jobId, optParams) — job moves to Funded.
 *  3. submit(jobId, deliverable, optParams) — job moves to Submitted.
 *  4. complete(jobId, reason, optParams)
 *     → _postComplete (via afterAction): record job participants
 *       (client, provider) and completion timestamp for the review window.
 *  5. Within reviewWindow (default 7 days):
 *       a. Client calls submitClientReview(jobId, score, comment)
 *          → validates score 1-5, window not expired, not already reviewed;
 *            calls EAS.attest() with provider as recipient.
 *       b. Provider calls submitProviderReview(jobId, score, comment)
 *          → same validation; calls EAS.attest() with client as recipient.
 *  6. reject(jobId, reason, optParams) [alternative to step 4]
 *     → _postReject (via afterAction): same participant recording; reviews
 *       may still be submitted to capture accountability on failed jobs.
 *
 * TRUST MODEL
 * -----------
 * Only job participants (client or provider recorded at completion) can
 * submit reviews. Each party can review exactly once per job. Review
 * submissions are only possible within the immutable reviewWindow. EAS
 * attestations are non-revocable — reviews are permanent on-chain facts.
 *
 * @custom:security-contact security@erc-8183.org
 */
contract MutualAttestationHook is BaseACPHook, ReentrancyGuard {
    /// @notice EAS contract for attestations
    IEAS public immutable eas;

    /// @notice Schema UID for mutual attestations
    bytes32 public immutable schemaUID;

    /// @notice Review window after job completion (default 7 days)
    uint256 public immutable reviewWindow;

    /// @notice Job participants recorded at completion
    mapping(uint256 => address) public jobClient;
    mapping(uint256 => address) public jobProvider;

    /// @notice Job completion timestamps
    mapping(uint256 => uint256) public jobCompletedAt;

    /// @notice Tracks whether each party has submitted their review
    mapping(uint256 => bool) public clientReviewed;
    mapping(uint256 => bool) public providerReviewed;

    /// @notice Attestation UIDs for each job
    mapping(uint256 => bytes32) public clientAttestationUID;
    mapping(uint256 => bytes32) public providerAttestationUID;

    /// @notice Emitted when a review is submitted
    event ReviewSubmitted(
        uint256 indexed jobId,
        address indexed reviewer,
        address indexed reviewee,
        uint8 score,
        bytes32 attestationUID,
        bool isClientReview
    );

    /// @notice Emitted when both reviews are in
    event MutualReviewComplete(uint256 indexed jobId);

    error MutualAttestationHook__ReviewWindowExpired();
    error MutualAttestationHook__AlreadyReviewed();
    error MutualAttestationHook__InvalidScore();
    error MutualAttestationHook__JobNotCompleted();
    error MutualAttestationHook__NotJobParticipant();

    constructor(
        address acpContract_,
        address eas_,
        bytes32 schemaUID_,
        uint256 reviewWindow_
    ) BaseACPHook(acpContract_) {
        eas = IEAS(eas_);
        schemaUID = schemaUID_;
        reviewWindow = reviewWindow_ == 0 ? 7 days : reviewWindow_;
    }

    /// @notice Records job completion timestamp + participants when job completes
    function _postComplete(
        uint256 jobId,
        bytes32, /* reason */
        bytes memory /* optParams */
    ) internal virtual override {
        jobCompletedAt[jobId] = block.timestamp;
        // Read actual participants from ACP contract
        (address client_, address provider_) = _getJobParticipants(jobId);
        jobClient[jobId] = client_;
        jobProvider[jobId] = provider_;
    }

    /// @notice Records job rejection timestamp + participants so rejected jobs can also be reviewed
    function _postReject(
        uint256 jobId,
        bytes32, /* reason */
        bytes memory /* optParams */
    ) internal virtual override {
        jobCompletedAt[jobId] = block.timestamp;
        (address client_, address provider_) = _getJobParticipants(jobId);
        jobClient[jobId] = client_;
        jobProvider[jobId] = provider_;
    }

    /// @notice Client reviews provider ("Was the work good?")
    /// @param jobId The job identifier
    /// @param score 1-5 star rating
    /// @param comment Brief review text
    function submitClientReview(
        uint256 jobId,
        uint8 score,
        string calldata comment
    ) external nonReentrant {
        _validateReview(jobId, score);
        if (msg.sender != jobClient[jobId]) revert MutualAttestationHook__NotJobParticipant();
        if (clientReviewed[jobId]) revert MutualAttestationHook__AlreadyReviewed();

        clientReviewed[jobId] = true;

        address provider_ = jobProvider[jobId];

        // Client attests provider quality
        bytes32 uid = _createAttestation(
            jobId, msg.sender, provider_, score, comment, true
        );
        clientAttestationUID[jobId] = uid;

        emit ReviewSubmitted(jobId, msg.sender, provider_, score, uid, true);

        if (providerReviewed[jobId]) {
            emit MutualReviewComplete(jobId);
        }
    }

    /// @notice Provider reviews client ("Was the client fair?")
    /// @param jobId The job identifier
    /// @param score 1-5 star rating
    /// @param comment Brief review text
    function submitProviderReview(
        uint256 jobId,
        uint8 score,
        string calldata comment
    ) external nonReentrant {
        _validateReview(jobId, score);
        if (msg.sender != jobProvider[jobId]) revert MutualAttestationHook__NotJobParticipant();
        if (providerReviewed[jobId]) revert MutualAttestationHook__AlreadyReviewed();

        providerReviewed[jobId] = true;

        address client_ = jobClient[jobId];

        // Provider attests client behavior
        bytes32 uid = _createAttestation(
            jobId, msg.sender, client_, score, comment, false
        );
        providerAttestationUID[jobId] = uid;

        emit ReviewSubmitted(jobId, msg.sender, client_, score, uid, false);

        if (clientReviewed[jobId]) {
            emit MutualReviewComplete(jobId);
        }
    }

    /// @notice Check if both reviews are submitted for a job
    function isFullyReviewed(uint256 jobId) external view returns (bool) {
        return clientReviewed[jobId] && providerReviewed[jobId];
    }

    /// @notice Get review status for a job
    function getReviewStatus(uint256 jobId) external view returns (
        bool clientDone,
        bool providerDone,
        uint256 deadline
    ) {
        return (
            clientReviewed[jobId],
            providerReviewed[jobId],
            jobCompletedAt[jobId] + reviewWindow
        );
    }

    function _validateReview(uint256 jobId, uint8 score) internal view {
        if (jobCompletedAt[jobId] == 0) revert MutualAttestationHook__JobNotCompleted();
        if (block.timestamp > jobCompletedAt[jobId] + reviewWindow) revert MutualAttestationHook__ReviewWindowExpired();
        if (score < 1 || score > 5) revert MutualAttestationHook__InvalidScore();
    }

    /// @dev Reads client and provider from ACP contract's getJob()
    function _getJobParticipants(uint256 jobId) internal view returns (address client_, address provider_) {
        IAgenticCommerceReader.Job memory job = IAgenticCommerceReader(acpContract).getJob(jobId);
        client_ = job.client;
        provider_ = job.provider;
    }

    function _createAttestation(
        uint256 jobId,
        address reviewer,
        address reviewee,
        uint8 score,
        string calldata comment,
        bool isClientReview
    ) internal returns (bytes32) {
        return eas.attest(
            IEAS.AttestationRequest({
                schema: schemaUID,
                data: IEAS.AttestationRequestData({
                    recipient: reviewee,
                    expirationTime: 0,
                    revocable: false,
                    refUID: bytes32(0),
                    data: abi.encode(
                        jobId,
                        reviewer,
                        reviewee,
                        score,
                        comment,
                        isClientReview
                    ),
                    value: 0
                })
            })
        );
    }
}
