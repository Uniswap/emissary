// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {GenericKeyManager} from './GenericKeyManager.sol';
import {Key, KeyLib, KeyType} from './KeyLib.sol';
import {ISignatureVerifier} from './interfaces/ISignatureVerifier.sol';
import {VerificationContext} from './types/VerificationContext.sol';

import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';
import {ResetPeriod} from 'the-compact/types/ResetPeriod.sol';

/**
 * @title BaseKeyVerifier
 * @notice A base contract that implements ISignatureVerifier with common verification patterns
 * @dev This contract provides a foundation for protocols to build upon by combining
 * key management with signature verification functionality
 * @custom:security-contact security@uniswap.org
 */
contract BaseKeyVerifier is GenericKeyManager, ISignatureVerifier {
    using KeyLib for Key;
    using DynamicArrayLib for DynamicArrayLib.DynamicArray;

    /// @notice Protocol identifier for this base verifier
    bytes32 public immutable PROTOCOL_ID;

    /// @notice Emitted when signature verification fails
    error SignatureVerificationFailed();

    /// @notice Emitted when context validation fails
    error InvalidContext();

    constructor(bytes32 protocolId) {
        PROTOCOL_ID = protocolId;
    }

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
        override
        returns (bytes4 selector)
    {
        require(canVerifySignature(account, digest, signature, context), SignatureVerificationFailed());
        return ISignatureVerifier.verifySignature.selector;
    }

    /**
     * @notice Checks if a signature can be verified for a given account and context
     * @param account The account whose keys should be checked
     * @param digest The digest that was signed
     * @param signature The signature to verify
     * @param context Protocol-specific context data
     * @return canVerify True if the signature can be verified
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

        // Validate the context
        if (!_validateContext(ctx)) {
            return false;
        }

        // Check if protocol is supported
        if (!_isProtocolSupported(ctx.protocol)) {
            return false;
        }

        // Check expiration if set
        if (ctx.expiration != 0 && block.timestamp >= ctx.expiration) {
            return false;
        }

        // Try to verify signature with registered keys
        (bool success,) = verifySignatureWithAnyKey(account, digest, signature);
        return success;
    }

    /**
     * @notice Registers a new key with additional context validation
     * @param account The account to register the key for
     * @param keyType The type of key to register
     * @param publicKey The public key to register
     * @param resetPeriod The reset period for the key
     * @param context Additional context for validation
     * @return keyHash The hash of the registered key
     */
    function registerKeyWithContext(
        address account,
        KeyType keyType,
        bytes calldata publicKey,
        ResetPeriod resetPeriod,
        bytes calldata context
    ) external returns (bytes32 keyHash) {
        return _registerKeyWithContext(account, keyType, publicKey, resetPeriod, context);
    }

    /**
     * @notice Registers a new key with additional context validation for the caller
     * @param keyType The type of key to register
     * @param publicKey The public key to register
     * @param resetPeriod The reset period for the key
     * @param context Additional context for validation
     * @return keyHash The hash of the registered key
     */
    function registerKeyWithContext(
        KeyType keyType,
        bytes calldata publicKey,
        ResetPeriod resetPeriod,
        bytes calldata context
    ) external returns (bytes32 keyHash) {
        return _registerKeyWithContext(msg.sender, keyType, publicKey, resetPeriod, context);
    }

    /**
     * @notice Registers a new key with additional context validation
     * @param account The account to register the key for
     * @param keyType The type of key to register
     * @param publicKey The public key to register
     * @param resetPeriod The reset period for the key
     * @param context Additional context for validation
     * @return keyHash The hash of the registered key
     */
    function _registerKeyWithContext(
        address account,
        KeyType keyType,
        bytes calldata publicKey,
        ResetPeriod resetPeriod,
        bytes memory context
    ) internal returns (bytes32 keyHash) {
        // Validate context if provided
        if (context.length > 0) {
            VerificationContext memory ctx = _parseContext(context);
            require(_validateContext(ctx), InvalidContext());
        }

        // Use the standard key registration
        return _registerKey(account, keyType, publicKey, resetPeriod);
    }

    /**
     * @notice Filters keys based on protocol compatibility
     * @param account The account whose keys to filter
     * @param protocol The protocol identifier
     * @return compatibleKeys Array of key hashes compatible with the protocol
     */
    function getCompatibleKeys(address account, bytes32 protocol)
        external
        view
        returns (bytes32[] memory compatibleKeys)
    {
        bytes32[] storage allKeys = keyHashes[account];
        DynamicArrayLib.DynamicArray memory results;

        for (uint256 i = 0; i < allKeys.length; i++) {
            Key storage key = keys[account][allKeys[i]];
            if (_isKeyCompatible(account, allKeys[i], protocol)) {
                results.p(key.hash());
            }
        }

        return results.asBytes32Array();
    }

    /**
     * @notice Parses the context bytes into a VerificationContext struct
     * @param context The context bytes to parse
     * @return ctx The parsed VerificationContext
     */
    function _parseContext(bytes memory context) internal pure returns (VerificationContext memory ctx) {
        if (context.length == 0) {
            // Return empty context with base protocol
            ctx.protocol = keccak256('BaseKeyVerifier');
            return ctx;
        }

        // Decode the context
        (ctx.protocol, ctx.data, ctx.expiration, ctx.nonce) = abi.decode(context, (bytes32, bytes, uint256, uint256));
    }

    /**
     * @notice Validates the context for correctness
     * @param ctx The context to validate
     * @return isValid True if the context is valid
     */
    function _validateContext(VerificationContext memory ctx) internal view virtual returns (bool isValid) {
        // Basic validation - can be overridden by derived contracts
        return ctx.protocol != bytes32(0);
    }

    /**
     * @notice Checks if a protocol is supported
     * @param protocol The protocol identifier
     * @return isSupported True if the protocol is supported
     */
    function _isProtocolSupported(bytes32 protocol) internal view virtual returns (bool isSupported) {
        // Default implementation supports the base protocol
        return protocol == PROTOCOL_ID;
    }

    /**
     * @notice Checks if a key is compatible with a protocol
     * @param account The account that owns the key
     * @param keyHash The key hash to check
     * @param protocol The protocol identifier
     * @return isCompatible True if the key is compatible
     */
    function _isKeyCompatible(address account, bytes32 keyHash, bytes32 protocol)
        internal
        view
        virtual
        returns (bool isCompatible)
    {
        // Default implementation: all keys are compatible with the base protocol
        return _keyExists(account, keyHash) && _isProtocolSupported(protocol);
    }

    /**
     * @notice Creates a basic verification context with protocol and expiration
     * @param protocol The protocol identifier
     * @param expiration The expiration timestamp (0 for no expiration)
     * @return context The encoded context bytes
     */
    function createBasicContext(bytes32 protocol, uint256 expiration) public virtual returns (bytes memory context) {
        VerificationContext memory ctx =
            VerificationContext({protocol: protocol, data: '', expiration: expiration, nonce: 0});
        return abi.encode(ctx.protocol, ctx.data, ctx.expiration, ctx.nonce);
    }

    /**
     * @notice Creates a context with additional data
     * @param protocol The protocol identifier
     * @param data Additional protocol-specific data
     * @param expiration The expiration timestamp (0 for no expiration)
     * @param nonce The nonce for replay protection
     * @return context The encoded context bytes
     */
    function createContext(bytes32 protocol, bytes memory data, uint256 expiration, uint256 nonce)
        public
        pure
        virtual
        returns (bytes memory context)
    {
        VerificationContext memory ctx =
            VerificationContext({protocol: protocol, data: data, expiration: expiration, nonce: nonce});
        return abi.encode(ctx.protocol, ctx.data, ctx.expiration, ctx.nonce);
    }
}
