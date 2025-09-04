// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/**
 * @title VerificationContext
 * @notice Struct for passing protocol-specific verification context data
 * @dev This allows protocols to define their own verification requirements
 * while using the same key management infrastructure
 * @custom:security-contact security@uniswap.org
 */
struct VerificationContext {
    /// @notice Protocol identifier to distinguish between different protocols
    bytes32 protocol;
    /// @notice Additional context data specific to the protocol
    bytes data;
    /// @notice Optional expiration timestamp for time-sensitive verifications
    uint256 expiration;
    /// @notice Optional nonce for replay protection
    uint256 nonce;
}
