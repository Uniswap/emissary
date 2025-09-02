// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DynamicArrayLib} from 'lib/solady/src/utils/DynamicArrayLib.sol';
import {IEmissary} from 'lib/the-compact/src/interfaces/IEmissary.sol';
import {IdLib} from 'lib/the-compact/src/lib/IdLib.sol';
import {ResetPeriod} from 'lib/the-compact/src/types/ResetPeriod.sol';

import {BaseKeyVerifier} from './BaseKeyVerifier.sol';

import {Key, KeyLib, KeyType} from './KeyLib.sol';
import {VerificationContext} from './types/VerificationContext.sol';

/**
 * @title KeyManagerEmissary
 * @notice A Compact-specific adapter that implements IEmissary using the generic key management foundation
 */
contract KeyManagerEmissary is BaseKeyVerifier, IEmissary {
    using IdLib for bytes12;
    using IdLib for ResetPeriod;
    using KeyLib for Key;
    using DynamicArrayLib for DynamicArrayLib.DynamicArray;

    /// @notice Constructor that initializes the protocol identifier
    constructor() BaseKeyVerifier(keccak256('the-compact.emissary.v1')) {}

    /**
     * @notice Verifies a claim signature using the registered keys for the sponsor
     * @param sponsor The sponsor whose keys should be checked
     * @param digest The EIP-712 digest that was signed
     * @param claimHash The claim hash that was signed
     * @param signature The signature bytes
     * @param lockTag The lock tag to check reset period compatibility
     * @return selector IEmissary.verifyClaim.selector if verification succeeds
     */
    function verifyClaim(address sponsor, bytes32 digest, bytes32 claimHash, bytes calldata signature, bytes12 lockTag)
        external
        view
        override
        returns (bytes4 selector)
    {
        require(canVerifyClaim(sponsor, digest, claimHash, signature, lockTag), SignatureVerificationFailed());
        return IEmissary.verifyClaim.selector;
    }

    /**
     * @notice Checks if a signature can be verified for a given sponsor and lock tag using any of their registered keys
     * @param sponsor The sponsor address
     * @param digest The EIP-712 digest that was signed
     * @param claimHash The claim hash that was signed
     * @param signature The signature bytes
     * @param lockTag The lock tag to check reset period compatibility
     * @return canVerify True if the signature can be verified
     */
    function canVerifyClaim(
        address sponsor,
        bytes32 digest,
        bytes32 claimHash,
        bytes calldata signature,
        bytes12 lockTag
    ) public view returns (bool canVerify) {
        // Encode the lockTag into the verification context and delegate to the
        // context-aware signature verification flow.
        bytes memory context = createContext(PROTOCOL_ID, abi.encode(lockTag, claimHash), 0, 0);
        return canVerifySignature(sponsor, digest, signature, context);
    }

    /**
     * @inheritdoc BaseKeyVerifier
     * @dev Parses the verification context to extract the lock tag, and enforces
     *      reset period compatibility when verifying signatures for The Compact.
     */
    function canVerifySignature(address account, bytes32 digest, bytes calldata signature, bytes memory context)
        public
        view
        virtual
        override
        returns (bool canVerify)
    {
        // Validate and parse context
        VerificationContext memory ctx = _parseContext(context);
        if (!_validateContext(ctx)) {
            return false;
        }

        if (!_isProtocolSupported(ctx.protocol)) {
            return false;
        }

        if (ctx.expiration != 0 && block.timestamp >= ctx.expiration) {
            return false;
        }

        // Extract lockTag from context data
        (bytes12 lockTag,) = abi.decode(ctx.data, (bytes12, bytes32));
        ResetPeriod required = lockTag.toResetPeriod();

        // Verify using any key that meets the reset period requirement
        bytes32[] storage allKeys = keyHashes[account];
        for (uint256 i = 0; i < allKeys.length; i++) {
            Key storage key = keys[account][allKeys[i]];
            if (uint8(key.resetPeriod) >= uint8(required) && key.verify(digest, signature)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @notice Get keys compatible with a specific reset period
     * @param sponsor The sponsor address
     * @param resetPeriod The reset period to check compatibility against
     * @return compatibleKeys Array of key hashes compatible with the reset period
     */
    function getKeysForResetPeriod(address sponsor, ResetPeriod resetPeriod) external view returns (bytes32[] memory) {
        bytes32[] storage allKeys = keyHashes[sponsor];
        DynamicArrayLib.DynamicArray memory results;

        for (uint256 i = 0; i < allKeys.length; i++) {
            Key storage key = keys[sponsor][allKeys[i]];
            if (uint8(resetPeriod) <= uint8(key.resetPeriod)) {
                results.p(key.hash());
            }
        }

        return results.asBytes32Array();
    }

    /**
     * @inheritdoc BaseKeyVerifier
     * @dev Implements the key compatibility check for The Compact (any valid key)
     */
    function _isKeyCompatible(address account, bytes32 keyHash, bytes32 protocol)
        internal
        view
        virtual
        override
        returns (bool isCompatible)
    {
        // For The Compact, all valid keys in storage are considered compatible
        return _keyExists(account, keyHash) && _isProtocolSupported(protocol);
    }

    /**
     * @inheritdoc BaseKeyVerifier
     * @dev Extends the base validation to include The Compact protocol
     */
    function _validateContext(VerificationContext memory ctx) internal view virtual override returns (bool isValid) {
        return super._validateContext(ctx) && ctx.protocol == PROTOCOL_ID;
    }
}
