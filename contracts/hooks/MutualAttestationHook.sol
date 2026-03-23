// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BaseACPHook} from "../BaseACPHook.sol";

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

/// @title MutualAttestationHook
/// @notice Airbnb-style mutual reviews — both client and provider attest each other after job completion.
/// @dev Creates two EAS attestations per completed job: one from each party.
///      Bad clients who post vague specs get low scores from providers.
///      Bad providers who deliver garbage get low scores from clients.
///      Both sides build reputation. Both sides are accountable.
contract MutualAttestationHook is BaseACPHook {
    /// @notice EAS contract for attestations
    IEAS public immutable eas;

    /// @notice Schema UID for mutual attestations
    bytes32 public immutable schemaUID;

    /// @notice Review window after job completion (default 7 days)
    uint256 public reviewWindow;

    /// @notice Job completion timestamps
    mapping(bytes32 => uint256) public jobCompletedAt;

    /// @notice Tracks whether each party has submitted their review
    mapping(bytes32 => bool) public clientReviewed;
    mapping(bytes32 => bool) public providerReviewed;

    /// @notice Attestation UIDs for each job
    mapping(bytes32 => bytes32) public clientAttestationUID;
    mapping(bytes32 => bytes32) public providerAttestationUID;

    /// @notice Review data structure
    struct Review {
        uint8 score;       // 1-5 stars
        string comment;    // Brief review text
    }

    /// @notice Emitted when a review is submitted
    event ReviewSubmitted(
        bytes32 indexed jobId,
        address indexed reviewer,
        address indexed reviewee,
        uint8 score,
        bytes32 attestationUID,
        bool isClientReview
    );

    /// @notice Emitted when both reviews are in
    event MutualReviewComplete(bytes32 indexed jobId);

    error ReviewWindowExpired();
    error AlreadyReviewed();
    error InvalidScore();
    error JobNotCompleted();
    error NotJobParticipant();

    constructor(
        address _acpContract,
        address _eas,
        bytes32 _schemaUID,
        uint256 _reviewWindow
    ) BaseACPHook(_acpContract) {
        eas = IEAS(_eas);
        schemaUID = _schemaUID;
        reviewWindow = _reviewWindow == 0 ? 7 days : _reviewWindow;
    }

    /// @notice Records job completion timestamp when job completes
    function _postComplete(
        uint256 jobId,
        bytes32, /* reason */
        bytes memory /* optParams */
    ) internal virtual override {
        jobCompletedAt[bytes32(jobId)] = block.timestamp;
    }

    /// @notice Client reviews provider ("Was the work good?")
    /// @param jobId The job identifier
    /// @param client The client address (must be msg.sender via core contract)
    /// @param provider The provider being reviewed
    /// @param score 1-5 star rating
    /// @param comment Brief review text
    function submitClientReview(
        bytes32 jobId,
        address client,
        address provider,
        uint8 score,
        string calldata comment
    ) external {
        _validateReview(jobId, score);
        if (clientReviewed[jobId]) revert AlreadyReviewed();

        clientReviewed[jobId] = true;

        // Client attests provider quality
        bytes32 uid = _createAttestation(
            jobId, client, provider, score, comment, true
        );
        clientAttestationUID[jobId] = uid;

        emit ReviewSubmitted(jobId, client, provider, score, uid, true);

        if (providerReviewed[jobId]) {
            emit MutualReviewComplete(jobId);
        }
    }

    /// @notice Provider reviews client ("Was the client fair?")
    /// @param jobId The job identifier
    /// @param provider The provider address
    /// @param client The client being reviewed
    /// @param score 1-5 star rating
    /// @param comment Brief review text
    function submitProviderReview(
        bytes32 jobId,
        address provider,
        address client,
        uint8 score,
        string calldata comment
    ) external {
        _validateReview(jobId, score);
        if (providerReviewed[jobId]) revert AlreadyReviewed();

        providerReviewed[jobId] = true;

        // Provider attests client behavior
        bytes32 uid = _createAttestation(
            jobId, provider, client, score, comment, false
        );
        providerAttestationUID[jobId] = uid;

        emit ReviewSubmitted(jobId, provider, client, score, uid, false);

        if (clientReviewed[jobId]) {
            emit MutualReviewComplete(jobId);
        }
    }

    /// @notice Check if both reviews are submitted for a job
    function isFullyReviewed(bytes32 jobId) external view returns (bool) {
        return clientReviewed[jobId] && providerReviewed[jobId];
    }

    /// @notice Get review status for a job
    function getReviewStatus(bytes32 jobId) external view returns (
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

    function _validateReview(bytes32 jobId, uint8 score) internal view {
        if (jobCompletedAt[jobId] == 0) revert JobNotCompleted();
        if (block.timestamp > jobCompletedAt[jobId] + reviewWindow) revert ReviewWindowExpired();
        if (score < 1 || score > 5) revert InvalidScore();
    }

    function _createAttestation(
        bytes32 jobId,
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
