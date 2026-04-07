// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IAttestationService
/// @notice Chain-agnostic attestation interface.
/// @dev Compatible with EAS (Base), BAS (BSC), and SimpleAttestation (X Layer).
///      All three implement the same attest() signature — deploy the adapter
///      that matches the target chain, inject it at construction time.
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

    /// @notice Create a single attestation.
    /// @return uid The attestation UID.
    function attest(AttestationRequest calldata request) external payable returns (bytes32 uid);
}
