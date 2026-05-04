// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseERC8183Hook} from "../BaseERC8183Hook.sol";
import {IERC8183HookMetadata} from "../interfaces/IERC8183HookMetadata.sol";
import {AgenticCommerce} from "@erc8183/AgenticCommerce.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title IAttestationService
/// @notice Chain-agnostic attestation interface.
interface IAttestationService {
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

    function attest(AttestationRequest calldata request) external payable returns (bytes32 uid);
}

/// @title MutualAttestationHook
/// @notice Airbnb-style mutual reviews -- both client and provider attest each other after job completion.
/// @dev Creates two attestations per completed job: one from each party.
///      Compatible with EAS (Base), BAS (BSC), and SimpleAttestation (X Layer) -
///      inject the correct address at construction time.
///      Bad clients who post vague specs get low scores from providers.
///      Bad providers who deliver garbage get low scores from clients.
///      Both sides build reputation. Both sides are accountable.
/// @custom:security-contact security@maiat.xyz
contract MutualAttestationHook is BaseERC8183Hook, ReentrancyGuard, IERC8183HookMetadata {
    bytes4 private constant SEL_COMPLETE =
        bytes4(keccak256("complete(uint256,bytes32,bytes)"));
    bytes4 private constant SEL_REJECT =
        bytes4(keccak256("reject(uint256,bytes32,bytes)"));

    /// @notice Attestation service (EAS / BAS / SimpleAttestation)
    IAttestationService public immutable attestationService;

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
        address erc8183Contract_,
        address attestationService_,
        bytes32 schemaUID_,
        uint256 reviewWindow_
    ) BaseERC8183Hook(erc8183Contract_) {
        attestationService = IAttestationService(attestationService_);
        schemaUID = schemaUID_;
        reviewWindow = reviewWindow_ == 0 ? 7 days : reviewWindow_;
    }

    /// @notice Records job completion timestamp + participants when job completes
    function _postComplete(
        uint256 jobId,
        address, /* caller */
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
        address, /* caller */
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
        AgenticCommerce.Job memory job = AgenticCommerce(erc8183Contract).getJob(jobId);
        client_ = job.client;
        provider_ = job.provider;
    }

    function requiredSelectors() external pure returns (bytes4[] memory selectors) {
        selectors = new bytes4[](2);
        selectors[0] = SEL_COMPLETE;
        selectors[1] = SEL_REJECT;
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(BaseERC8183Hook) returns (bool) {
        return
            interfaceId == type(IERC8183HookMetadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _createAttestation(
        uint256 jobId,
        address reviewer,
        address reviewee,
        uint8 score,
        string calldata comment,
        bool isClientReview
    ) internal returns (bytes32) {
        return attestationService.attest(
            IAttestationService.AttestationRequest({
                schema: schemaUID,
                data: IAttestationService.AttestationRequestData({
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
