// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrustOracle} from "../interfaces/ITrustOracle.sol";

/// @notice Raw interface for the Maiat on-chain oracle (Base mainnet).
/// @dev This mirrors the deployed MaiatOracle contract at 0xc6cf...c6da.
interface IMaiatOracle {
    struct UserReputation {
        uint256 reputationScore;
        uint256 totalReviews;
        uint256 scarabPoints;
        uint256 feeBps;
        bool initialized;
        uint256 lastUpdated;
    }

    function getUserData(address user) external view returns (UserReputation memory);
}

/// @title MaiatTrustOracle
/// @notice Reference ITrustOracle provider — wraps the Maiat on-chain oracle.
/// @dev Deploy this adapter and pass its address to any ITrustOracle-consuming
///      hook or evaluator. Other providers can implement ITrustOracle directly.
contract MaiatTrustOracle is ITrustOracle {
    IMaiatOracle public immutable maiatOracle;

    error MaiatTrustOracle__ZeroAddress();

    constructor(address maiatOracle_) {
        if (maiatOracle_ == address(0)) revert MaiatTrustOracle__ZeroAddress();
        maiatOracle = IMaiatOracle(maiatOracle_);
    }

    /// @inheritdoc ITrustOracle
    function getTrustScore(address user) external view override returns (uint256 score) {
        IMaiatOracle.UserReputation memory rep = maiatOracle.getUserData(user);
        if (!rep.initialized) return 0;
        // Clamp to 100
        score = rep.reputationScore > 100 ? 100 : rep.reputationScore;
    }
}
