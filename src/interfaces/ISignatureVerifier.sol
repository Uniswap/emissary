// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/**
 * @title ISignatureVerifier
 * @notice Generic interface for signature verification across different protocols
 * @dev This interface allows protocols to define their own verification logic
 * while using the same underlying key management infrastructure
 * @custom:security-contact security@uniswap.org
 */
interface ISignatureVerifier {
    /**
     * @notice Verifies a signature for a specific protocol context
     * @param account The account whose keys should be checked
     * @param digest The digest that was signed
     * @param signature The signature to verify
     * @param context Protocol-specific context data
     * @return selector The function selector if verification succeeds
     */
    function verifySignature(address account, bytes32 digest, bytes calldata signature, bytes calldata context)
        external
        view
        returns (bytes4 selector);

    /**
     * @notice Checks if a signature can be verified for a given account and context
     * @param account The account whose keys should be checked
     * @param digest The digest that was signed
     * @param signature The signature to verify
     * @param context Protocol-specific context data
     * @return canVerify True if the signature can be verified
     */
    function canVerifySignature(address account, bytes32 digest, bytes calldata signature, bytes calldata context)
        external
        view
        returns (bool canVerify);
}
