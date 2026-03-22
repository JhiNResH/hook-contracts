// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../BaseACPHook.sol";

/**
 * @title AttestationHook
 * @notice ERC-8183 hook that writes EAS attestations on job completion and rejection.
 *         Creates an immutable, on-chain receipt for every ACP transaction — enabling
 *         trust scores, reputation systems (e.g. ERC-8004), and agent credit histories.
 *
 * @dev Extends BaseACPHook. Only afterAction hooks are used (non-blocking).
 *      Attestations are written to the Ethereum Attestation Service (EAS) on Base.
 *
 * Flow:
 *   1. Job completes or is rejected via AgenticCommerceHooked
 *   2. afterAction callback fires (complete or reject)
 *   3. Hook reads job data from ACP contract
 *   4. Hook writes EAS attestation with structured receipt data
 *   5. Attestation is permanently on-chain, queryable by anyone
 *
 * Schema (registered on Base EAS):
 *   "uint256 jobId, address client, address provider, address evaluator,
 *    uint256 budget, bytes32 deliverable, bytes32 reason, bool completed"
 *
 * Design decisions:
 *   - Attestation is written to provider as recipient (they accumulate reputation)
 *   - Non-revocable (job outcomes are facts, not opinions)
 *   - afterAction only — never blocks job lifecycle (no beforeAction logic)
 *   - Uses try/catch so EAS failures never revert the job transaction
 *   - Owner can update schema UID if re-registered
 */

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

/// @notice Minimal AgenticCommerce interface to read job data
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

contract AttestationHook is BaseACPHook {
    /*//////////////////////////////////////////////////////////////
                            STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice EAS contract on Base (predeploy at 0x4200...0021)
    IEAS public eas;

    /// @notice Schema UID for the ACP job receipt schema
    bytes32 public schemaUID;

    /// @notice AgenticCommerce contract to read job details
    IAgenticCommerceReader public agenticCommerce;

    /// @notice Owner for admin functions
    address public owner;

    /// @notice Track attestation UIDs per job (for reference)
    mapping(uint256 => bytes32) public jobAttestations;

    /// @notice Counter for total attestations written
    uint256 public totalAttestations;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event AttestationCreated(
        uint256 indexed jobId,
        bytes32 indexed attestationUID,
        address indexed provider,
        bool completed
    );

    event AttestationFailed(uint256 indexed jobId, bytes reason);
    event SchemaUpdated(bytes32 indexed newSchemaUID);
    event EASUpdated(address indexed newEAS);

    /*//////////////////////////////////////////////////////////////
                            ERRORS
    //////////////////////////////////////////////////////////////*/

    error OnlyOwner();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param acpContract_      AgenticCommerceHooked contract address
     * @param eas_              EAS contract address (Base: 0x4200000000000000000000000000000000000021)
     * @param schemaUID_        Pre-registered EAS schema UID for ACP receipts
     */
    constructor(
        address acpContract_,
        address eas_,
        bytes32 schemaUID_
    ) BaseACPHook(acpContract_) {
        eas = IEAS(eas_);
        schemaUID = schemaUID_;
        agenticCommerce = IAgenticCommerceReader(acpContract_);
        owner = msg.sender;
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK: POST-COMPLETE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called after a job is completed. Writes a positive attestation.
     * @param jobId The completed job ID
     * @param reason The evaluator's reason hash
     */
    function _postComplete(
        uint256 jobId,
        bytes32 reason,
        bytes memory /* optParams */
    ) internal override {
        _writeAttestation(jobId, reason, true);
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK: POST-REJECT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Called after a job is rejected. Writes a negative attestation.
     * @param jobId The rejected job ID
     * @param reason The evaluator's/client's reason hash
     */
    function _postReject(
        uint256 jobId,
        bytes32 reason,
        bytes memory /* optParams */
    ) internal override {
        _writeAttestation(jobId, reason, false);
    }

    /*//////////////////////////////////////////////////////////////
                    CORE: WRITE ATTESTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Reads job data from ACP contract and writes an EAS attestation.
     *      Uses try/catch — EAS failures NEVER revert the parent transaction.
     *
     * Schema encoding:
     *   abi.encode(jobId, client, provider, evaluator, budget, deliverable, reason, completed)
     *
     * Recipient = provider (they accumulate reputation from completed/rejected jobs)
     */
    function _writeAttestation(
        uint256 jobId,
        bytes32 reason,
        bool completed
    ) internal {
        // Read job data from ACP contract
        IAgenticCommerceReader.Job memory job;
        try agenticCommerce.getJob(jobId) returns (IAgenticCommerceReader.Job memory j) {
            job = j;
        } catch (bytes memory err) {
            emit AttestationFailed(jobId, err);
            return;
        }

        // Encode attestation data matching our schema
        // Note: deliverable is not stored in the Job struct, so we use reason as
        // the primary content hash. The deliverable was emitted in JobSubmitted event
        // and can be referenced off-chain via the jobId.
        bytes memory attestationData = abi.encode(
            jobId,
            job.client,
            job.provider,
            job.evaluator,
            job.budget,
            reason,       // evaluator's reason / quality hash
            completed
        );

        // Write to EAS
        try eas.attest(
            IEAS.AttestationRequest({
                schema: schemaUID,
                data: IEAS.AttestationRequestData({
                    recipient: job.provider,   // Provider accumulates reputation
                    expirationTime: 0,         // Never expires (permanent record)
                    revocable: false,          // Job outcomes are facts, not opinions
                    refUID: bytes32(0),        // No reference (standalone receipt)
                    data: attestationData,
                    value: 0                   // No ETH value
                })
            })
        ) returns (bytes32 uid) {
            jobAttestations[jobId] = uid;
            totalAttestations++;
            emit AttestationCreated(jobId, uid, job.provider, completed);
        } catch (bytes memory err) {
            emit AttestationFailed(jobId, err);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN
    //////////////////////////////////////////////////////////////*/

    modifier onlyOwner_() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    /**
     * @notice Update the EAS schema UID (e.g. if schema is re-registered)
     * @param schemaUID_ New schema UID
     */
    function setSchemaUID(bytes32 schemaUID_) external onlyOwner_ {
        schemaUID = schemaUID_;
        emit SchemaUpdated(schemaUID_);
    }

    /**
     * @notice Update the EAS contract address
     * @param eas_ New EAS address
     */
    function setEAS(address eas_) external onlyOwner_ {
        eas = IEAS(eas_);
        emit EASUpdated(eas_);
    }

    /**
     * @notice Transfer ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner_ {
        owner = newOwner;
    }

    /*//////////////////////////////////////////////////////////////
                    VIEW
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the EAS attestation UID for a given job
     * @param jobId The job ID
     * @return uid The attestation UID (bytes32(0) if not attested)
     */
    function getAttestation(uint256 jobId) external view returns (bytes32) {
        return jobAttestations[jobId];
    }

    /**
     * @notice ERC-165 support
     */
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IACPHook).interfaceId
            || interfaceId == 0x01ffc9a7; // IERC165
    }
}
