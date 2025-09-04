// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Key, KeyLib, KeyType} from './KeyLib.sol';
import {IdLib} from 'the-compact/lib/IdLib.sol';
import {ResetPeriod} from 'the-compact/types/ResetPeriod.sol';
import {DynamicArrayLib} from 'solady/utils/DynamicArrayLib.sol';
import {LibSort} from 'solady/utils/LibSort.sol';

/// @notice Configuration for M-of-N multisig
/// @param signerBitmap Bitmap indicating which keys are signers (bit i = keyHashes[account][i] is a signer)
/// @param threshold The number of signatures required (M)
/// @param signerCount The total number of signers (N)
/// @param resetPeriod The reset period for configuration changes
/// @param removalTimestamp Timestamp when multisig can be removed (0 means not scheduled)
/// @param index The 1-based index of this multisig in the multisigHashes array (0 means not registered)
struct MultisigConfig {
    uint256 signerBitmap;
    uint8 threshold;
    uint8 signerCount;
    ResetPeriod resetPeriod;
    uint64 removalTimestamp;
    uint16 index;
}

/// @notice Signature data for multisig verification
/// @param multisigHash The hash of the multisig configuration to use
/// @param participantIndices Array of key indices that signed (must be sorted)
/// @param signatures Corresponding signatures from the participants
struct MultisigSignature {
    bytes32 multisigHash;
    uint16[] participantIndices;
    bytes[] signatures;
}

/**
 * @title GenericKeyManager
 * @notice A generic key management contract that provides core functionality
 * @dev This contract handles key registration, removal, and timelock mechanisms
 * while being protocol-agnostic. Other contracts can inherit from this to add
 * protocol-specific verification logic.
 * @custom:security-contact security@uniswap.org
 */
contract GenericKeyManager {
    using KeyLib for Key;
    using IdLib for ResetPeriod;
    using DynamicArrayLib for DynamicArrayLib.DynamicArray;

    /// @notice Maximum number of keys allowed per account (due to 256-bit signer bitmap)
    uint256 public constant MAX_KEYS_PER_ACCOUNT = 256;

    /// @notice Registry of authorized keys for each account
    /// @dev account => keyHash => Key
    mapping(address account => mapping(bytes32 keyHash => Key key)) public keys;

    /// @notice List of key hashes for each account (for enumeration)
    /// @dev account => keyHash[]
    mapping(address account => bytes32[] keyHashes) public keyHashes;

    /// @notice Registry of multisig configurations for each account
    /// @dev account => multisigHash => MultisigConfig
    mapping(address account => mapping(bytes32 multisigHash => MultisigConfig multisig)) public multisigs;

    /// @notice List of multisig hashes for each account (for enumeration)
    /// @dev account => multisigHash[]
    mapping(address account => bytes32[] multisigHashes) public multisigHashes;

    /// @notice Track which multisigs use a given key for an account
    /// @dev account => keyHash => multisigHash[]
    mapping(address account => mapping(bytes32 keyHash => bytes32[] multisigsUsingKey)) internal _multisigsUsingKey;

    /// @notice Emitted when a key is registered
    /// @param account The account address
    /// @param keyHash The key hash
    /// @param keyType The key type
    /// @param resetPeriod The reset period for the key
    event KeyRegistered(address indexed account, bytes32 indexed keyHash, KeyType keyType, ResetPeriod resetPeriod);

    /// @notice Emitted when a key is removed
    /// @param account The account address
    /// @param keyHash The key hash
    event KeyRemoved(address indexed account, bytes32 indexed keyHash);

    /// @notice Emitted when a key removal is scheduled
    /// @param account The account address
    /// @param keyHash The key hash
    /// @param removableAt The timestamp when the key can be removed
    event KeyRemovalScheduled(address indexed account, bytes32 indexed keyHash, uint256 removableAt);

    /// @notice Emitted when a multisig is registered
    /// @param account The account address
    /// @param multisigHash The multisig hash
    /// @param threshold The signature threshold (M)
    /// @param signerCount The total number of signers (N)
    /// @param resetPeriod The reset period for the multisig
    event MultisigRegistered(
        address indexed account,
        bytes32 indexed multisigHash,
        uint8 threshold,
        uint8 signerCount,
        ResetPeriod resetPeriod
    );

    /// @notice Emitted when a multisig is removed
    /// @param account The account address
    /// @param multisigHash The multisig hash
    event MultisigRemoved(address indexed account, bytes32 indexed multisigHash);

    /// @notice Emitted when a multisig removal is scheduled
    /// @param account The account address
    /// @param multisigHash The multisig hash
    /// @param removableAt The timestamp when the multisig can be removed
    event MultisigRemovalScheduled(address indexed account, bytes32 indexed multisigHash, uint256 removableAt);

    /// @notice Thrown when a key is already registered
    /// @param account The account address
    /// @param keyHash The key hash
    error KeyAlreadyRegistered(address account, bytes32 keyHash);

    /// @notice Thrown when a key is not registered
    /// @param account The account address
    /// @param keyHash The key hash
    error KeyNotRegistered(address account, bytes32 keyHash);

    /// @notice Thrown when a key is invalid
    /// @param keyHash The key hash
    error InvalidKey(bytes32 keyHash);

    /// @notice Thrown when key removal is attempted before timelock expires
    /// @param removableAt The timestamp when removal will be available
    error KeyRemovalUnavailable(uint256 removableAt);

    /// @notice Thrown when caller is not authorized to manage keys for the account
    /// @param caller The caller address
    /// @param account The account address
    error UnauthorizedKeyManagement(address caller, address account);

    /// @notice Thrown when a multisig is already registered
    /// @param account The account address
    /// @param multisigHash The multisig hash
    error MultisigAlreadyRegistered(address account, bytes32 multisigHash);

    /// @notice Thrown when a multisig is not registered
    /// @param account The account address
    /// @param multisigHash The multisig hash
    error MultisigNotRegistered(address account, bytes32 multisigHash);

    /// @notice Thrown when a multisig configuration is invalid
    /// @param reason The reason for invalidity
    error InvalidMultisigConfig(string reason);

    /// @notice Thrown when multisig removal is attempted before timelock expires
    /// @param removableAt The timestamp when removal will be available
    error MultisigRemovalUnavailable(uint256 removableAt);

    /// @notice Thrown when trying to remove a key that's still used in multisigs
    /// @param keyHash The key hash
    /// @param activeMultisigs Number of multisigs still using this key
    error KeyStillInUse(bytes32 keyHash, uint256 activeMultisigs);

    /// @notice Thrown when updating signer bitmaps would cause two signers to collide on the same index
    /// @param multisigHash The multisig hash where the collision would occur
    /// @param newIndex The new index that is already occupied in the bitmap
    error MultisigSignerIndexCollision(bytes32 multisigHash, uint16 newIndex);

    /// @notice Thrown when a signer index is >= 256 and cannot be represented in the bitmap
    /// @param index The invalid signer index
    error MultisigSignerIndexOutOfRange(uint16 index);

    /**
     * @notice Registers a new key for an account
     * @param account The account to register the key for
     * @param keyType The type of key to register
     * @param publicKey The public key to register
     * @param resetPeriod The reset period for the key
     * @return keyHash The hash of the registered key
     */
    function registerKey(address account, KeyType keyType, bytes calldata publicKey, ResetPeriod resetPeriod)
        external
        returns (bytes32 keyHash)
    {
        return _registerKey(account, keyType, publicKey, resetPeriod);
    }

    /**
     * @notice Registers a new key for the caller
     * @param keyType The type of key to register
     * @param publicKey The public key to register
     * @param resetPeriod The reset period for the key
     * @return keyHash The hash of the registered key
     */
    function registerKey(KeyType keyType, bytes calldata publicKey, ResetPeriod resetPeriod)
        external
        virtual
        returns (bytes32 keyHash)
    {
        return _registerKey(msg.sender, keyType, publicKey, resetPeriod);
    }

    function _registerKey(address account, KeyType keyType, bytes calldata publicKey, ResetPeriod resetPeriod)
        internal
        virtual
        returns (bytes32 keyHash)
    {
        _checkKeyManagementAuthorization(account);

        Key memory key;
        key.keyType = keyType;
        key.publicKey = publicKey;
        key.resetPeriod = resetPeriod;
        keyHash = key.hash();

        require(key.isValidKey(), InvalidKey(keyHash));
        require(!_keyExists(account, keyHash), KeyAlreadyRegistered(account, keyHash));

        // Add to key hashes list and get the new index
        keyHashes[account].push(keyHash);
        // We use a 1-based index (0 means unregistered)
        uint16 newIndex = uint16(keyHashes[account].length);

        // Update the key with the correct index and store it
        key.index = newIndex;
        keys[account][keyHash] = key;

        emit KeyRegistered(account, keyHash, key.keyType, key.resetPeriod);
    }

    /**
     * @notice Schedules a key removal for an account
     * @param account The account to schedule key removal for
     * @param keyHash The hash of the key to schedule for removal
     * @return removableAt The timestamp when the key can be removed
     */
    function scheduleKeyRemoval(address account, bytes32 keyHash) public returns (uint256 removableAt) {
        return _scheduleKeyRemoval(account, keyHash);
    }

    /**
     * @notice Schedules a key removal for the caller
     * @param keyHash The hash of the key to schedule for removal
     * @return removableAt The timestamp when the key can be removed
     */
    function scheduleKeyRemoval(bytes32 keyHash) external virtual returns (uint256 removableAt) {
        return _scheduleKeyRemoval(msg.sender, keyHash);
    }

    function _scheduleKeyRemoval(address account, bytes32 keyHash) internal returns (uint256 removableAt) {
        _checkKeyManagementAuthorization(account);
        require(_keyExists(account, keyHash), KeyNotRegistered(account, keyHash));

        // Get the key and its reset period
        Key storage key = keys[account][keyHash];
        ResetPeriod resetPeriod = key.resetPeriod;

        unchecked {
            // Calculate when the key can be removed (current time + reset period)
            removableAt = block.timestamp + resetPeriod.toSeconds();
        }

        // Store the removal schedule directly in the key
        key.removalTimestamp = uint64(removableAt);

        emit KeyRemovalScheduled(account, keyHash, removableAt);
    }

    /**
     * @notice Removes a key for an account
     * @param account The account to remove the key for
     * @param keyHash The hash of the key to remove
     */
    function removeKey(address account, bytes32 keyHash) external {
        _removeKey(account, keyHash);
    }

    /**
     * @notice Removes a key for the caller
     * @param keyHash The hash of the key to remove
     */
    function removeKey(bytes32 keyHash) external virtual {
        _removeKey(msg.sender, keyHash);
    }

    function _removeKey(address account, bytes32 keyHash) internal {
        _checkKeyManagementAuthorization(account);

        // Check if key is still used in any multisigs
        uint256 usageCount = _multisigsUsingKey[account][keyHash].length;
        require(usageCount == 0, KeyStillInUse(keyHash, usageCount));

        // Check if removal has been properly scheduled and timelock has expired
        Key storage key = keys[account][keyHash];
        uint64 removableAt = key.removalTimestamp;
        require(removableAt != 0 && removableAt <= block.timestamp, KeyRemovalUnavailable(removableAt));

        // Get the key's index (1-based) and convert to 0-based
        uint256 index = uint256(key.index) - 1;
        bytes32[] storage accountKeyHashes = keyHashes[account];

        // If not the last element, swap with last element
        if (index < accountKeyHashes.length - 1) {
            bytes32 lastKeyHash = accountKeyHashes[accountKeyHashes.length - 1];

            // Update all multisigs that reference the key being moved from oldIndex to newIndex
            {
                uint16 newIndex = uint16(index);
                uint16 oldIndex = uint16(accountKeyHashes.length - 1);

                // Range check before any bit shifting
                require(newIndex < MAX_KEYS_PER_ACCOUNT && oldIndex < MAX_KEYS_PER_ACCOUNT, MultisigSignerIndexOutOfRange(newIndex));

                bytes32[] storage usingMultisigs = _multisigsUsingKey[account][lastKeyHash];
                for (uint256 m = 0; m < usingMultisigs.length; m++) {
                    bytes32 msHash = usingMultisigs[m];
                    if (!_multisigExists(account, msHash)) continue;
                    MultisigConfig storage cfg = multisigs[account][msHash];

                    // Collision check
                    require((cfg.signerBitmap & (1 << newIndex)) == 0, MultisigSignerIndexCollision(msHash, newIndex));

                    // Move the signer bit from oldIndex to newIndex
                    cfg.signerBitmap = (cfg.signerBitmap & ~(1 << oldIndex)) | (1 << newIndex);
                }
            }

            // Perform the actual swap in the key hash array
            accountKeyHashes[index] = lastKeyHash;

            // Update the moved key's index in its struct
            keys[account][lastKeyHash].index = uint16(index + 1); // Convert back to 1-based
        }

        // Remove the last element
        accountKeyHashes.pop();

        // Remove from keys mapping (delete the entire struct)
        delete keys[account][keyHash];

        emit KeyRemoved(account, keyHash);
    }

    /**
     * @notice Verifies a signature using a specific registered key
     * @param account The account whose key should be checked
     * @param keyHash The specific key hash to verify against
     * @param digest The digest that was signed
     * @param signature The signature bytes
     * @return success True if the signature was verified successfully
     */
    function verifySignatureWithKey(address account, bytes32 keyHash, bytes32 digest, bytes calldata signature)
        public
        view
        returns (bool success)
    {
        // Check if the key exists
        if (!_keyExists(account, keyHash)) {
            return false;
        }

        // Get the key and verify the signature
        Key storage key = keys[account][keyHash];
        return key.verify(digest, signature);
    }

    /**
     * @notice Verifies a signature using any of the registered keys for an account
     * @param account The account whose keys should be checked
     * @param digest The digest that was signed
     * @param signature The signature bytes
     * @return success True if the signature was verified successfully
     * @return keyHash The hash of the key that successfully verified the signature
     */
    function verifySignatureWithAnyKey(address account, bytes32 digest, bytes calldata signature)
        public
        view
        returns (bool success, bytes32 keyHash)
    {
        // Get all key hashes for this account
        bytes32[] storage accountKeyHashes = keyHashes[account];

        // Try to verify the signature against each registered key
        for (uint256 i = 0; i < accountKeyHashes.length; i++) {
            bytes32 currentKeyHash = accountKeyHashes[i];
            Key storage key = keys[account][currentKeyHash];

            // Try to verify signature with this key
            if (key.verify(digest, signature)) {
                return (true, currentKeyHash);
            }
        }

        // No registered key can verify the signature
        return (false, bytes32(0));
    }

    /**
     * @notice Get details about a specific key
     * @param account The account address
     * @param keyHash The key hash
     * @return key The key details
     */
    function getKey(address account, bytes32 keyHash) external view returns (Key memory key) {
        require(_keyExists(account, keyHash), KeyNotRegistered(account, keyHash));
        return keys[account][keyHash];
    }

    /**
     * @notice Get all key hashes for an account
     * @param account The account address
     * @return hashes Array of key hashes
     */
    function getKeyHashes(address account) external view returns (bytes32[] memory hashes) {
        return keyHashes[account];
    }

    /**
     * @notice Check if a key is registered for an account
     * @param account The account address
     * @param keyHash The key hash
     * @return isRegistered True if key is registered
     */
    function isKeyRegistered(address account, bytes32 keyHash) external view returns (bool isRegistered) {
        return _keyExists(account, keyHash);
    }

    /**
     * @notice Get the count of keys for an account
     * @param account The account address
     * @return count Number of registered keys
     */
    function getKeyCount(address account) external view returns (uint256 count) {
        return keyHashes[account].length;
    }

    /**
     * @notice Compute the hash of a key
     * @param key The key to hash
     * @return keyHash The hash of the key
     */
    function computeKeyHash(Key calldata key) external pure returns (bytes32 keyHash) {
        return key.hash();
    }

    /**
     * @notice Validate a key structure
     * @param key The key to validate
     * @return isValid True if the key is valid
     */
    function validateKey(Key calldata key) external pure returns (bool isValid) {
        return key.isValidKey();
    }

    /**
     * @notice Get the reset period for a specific key
     * @param account The account address
     * @param keyHash The key hash
     * @return resetPeriod The reset period for the key
     */
    function getKeyResetPeriod(address account, bytes32 keyHash) external view returns (ResetPeriod resetPeriod) {
        require(_keyExists(account, keyHash), KeyNotRegistered(account, keyHash));
        return keys[account][keyHash].resetPeriod;
    }

    /**
     * @notice Get the removal status for a specific key
     * @param account The account address
     * @param keyHash The key hash
     * @return isScheduled True if removal is scheduled
     * @return removableAt The timestamp when the key can be removed (0 if not scheduled)
     */
    function getKeyRemovalStatus(address account, bytes32 keyHash)
        external
        view
        returns (bool isScheduled, uint256 removableAt)
    {
        require(_keyExists(account, keyHash), KeyNotRegistered(account, keyHash));
        uint64 schedule = keys[account][keyHash].removalTimestamp;
        isScheduled = (schedule != 0);
        removableAt = uint256(schedule);
    }

    /**
     * @notice Check if a key can be removed immediately
     * @param account The account address
     * @param keyHash The key hash
     * @return canRemove True if the key can be removed now
     */
    function canRemoveKey(address account, bytes32 keyHash) external view returns (bool canRemove) {
        uint64 removableAt = keys[account][keyHash].removalTimestamp;
        return (removableAt != 0 && block.timestamp >= removableAt);
    }

    /**
     * @notice Checks if a key exists for an account
     * @param account The account address
     * @param keyHash The key hash
     * @return exists True if key exists
     */
    function _keyExists(address account, bytes32 keyHash) internal view returns (bool exists) {
        return keys[account][keyHash].index != 0;
    }

    /**
     * @notice Checks if the caller is authorized to manage keys for an account
     * @param account The account to check authorization for
     * @dev Override this function in derived contracts to implement custom authorization logic
     */
    function _checkKeyManagementAuthorization(address account) internal view virtual {
        // Default implementation: only the account itself can manage its keys
        require(msg.sender == account, UnauthorizedKeyManagement(msg.sender, account));
    }

    // ========== MULTISIG FUNCTIONS ==========

    /**
     * @notice Registers a new multisig for an account
     * @param account The account to register the multisig for
     * @param threshold The number of signatures required (M)
     * @param signerIndices Array of key indices that can sign (references keyHashes[account])
     * @param resetPeriod The reset period for the multisig
     * @return multisigHash The hash of the registered multisig
     */
    function registerMultisig(
        address account,
        uint8 threshold,
        uint16[] calldata signerIndices,
        ResetPeriod resetPeriod
    ) external returns (bytes32 multisigHash) {
        _checkKeyManagementAuthorization(account);
        return _registerMultisig(account, threshold, signerIndices, resetPeriod);
    }

    /**
     * @notice Registers a new multisig for the caller
     * @param threshold The number of signatures required (M)
     * @param signerIndices Array of key indices that can sign
     * @param resetPeriod The reset period for the multisig
     * @return multisigHash The hash of the registered multisig
     */
    function registerMultisig(uint8 threshold, uint16[] calldata signerIndices, ResetPeriod resetPeriod)
        external
        returns (bytes32 multisigHash)
    {
        return _registerMultisig(msg.sender, threshold, signerIndices, resetPeriod);
    }

    /**
     * @notice Internal function to register a multisig
     * @param account The account to register the multisig for
     * @param threshold The number of signatures required (M)
     * @param signerIndices Array of key indices that can sign (references keyHashes[account])
     * @param resetPeriod The reset period for the multisig
     * @return multisigHash The hash of the registered multisig
     */
    function _registerMultisig(
        address account,
        uint8 threshold,
        uint16[] calldata signerIndices,
        ResetPeriod resetPeriod
    ) internal returns (bytes32 multisigHash) {
        // Validate inputs
        uint8 signerCount = uint8(signerIndices.length);
        require(threshold > 0 && threshold <= signerCount, InvalidMultisigConfig('Invalid threshold'));
        require(signerCount > 0 && signerCount < MAX_KEYS_PER_ACCOUNT, InvalidMultisigConfig('Invalid signer count'));
        require(signerIndices.length <= keyHashes[account].length, InvalidMultisigConfig('Signer index out of bounds'));

        // Create bitmap from signer indices
        uint256 signerBitmap = 0;
        // Build the stable list of authorized key hashes (by identity, not index)
        bytes32[] memory authorizedKeyHashes = new bytes32[](signerIndices.length);
        for (uint256 i = 0; i < signerIndices.length; i++) {
            uint16 index = signerIndices[i];
            require(index < keyHashes[account].length, InvalidMultisigConfig('Signer index out of bounds'));
            require((signerBitmap & (1 << index)) == 0, InvalidMultisigConfig('Duplicate signer index'));
            require(index < MAX_KEYS_PER_ACCOUNT, MultisigSignerIndexOutOfRange(index));

            // Verify the key exists
            bytes32 keyHash = keyHashes[account][index];
            require(_keyExists(account, keyHash), InvalidMultisigConfig('Referenced key does not exist'));

            signerBitmap |= (1 << index);
            authorizedKeyHashes[i] = keyHash;
        }

        // Create multisig config
        MultisigConfig memory config = MultisigConfig({
            signerBitmap: signerBitmap,
            threshold: threshold,
            signerCount: signerCount,
            resetPeriod: resetPeriod,
            removalTimestamp: 0,
            index: 0
        });

        // Compute a stable identity hash based on the set of key identities (order-independent),
        // threshold, signerCount, and resetPeriod. This will not change if key indices shift.
        multisigHash = _computeMultisigIdentityHash(authorizedKeyHashes, threshold, signerCount, resetPeriod);
        require(!_multisigExists(account, multisigHash), MultisigAlreadyRegistered(account, multisigHash));

        // Add to multisig hashes list and get the new index
        multisigHashes[account].push(multisigHash);
        // We use a 1-based index (0 means unregistered)
        uint16 newIndex = uint16(multisigHashes[account].length);

        // Update the config with the correct index and store it
        config.index = newIndex;
        multisigs[account][multisigHash] = config;

        // Track back-references for each key used in this multisig
        for (uint256 i = 0; i < signerIndices.length; i++) {
            uint16 sIdx = signerIndices[i];
            bytes32 sKeyHash = keyHashes[account][sIdx];
            _multisigsUsingKey[account][sKeyHash].push(multisigHash);
        }

        emit MultisigRegistered(account, multisigHash, threshold, signerCount, resetPeriod);
    }

    /**
     * @notice Verifies a multisig signature
     * @param account The account whose multisig should be checked
     * @param multisigHash The hash of the multisig configuration to use
     * @param digest The digest that was signed
     * @param signature The multisig signature data
     * @return success True if the signature was verified successfully
     */
    function verifyMultisigSignature(
        address account,
        bytes32 multisigHash,
        bytes32 digest,
        MultisigSignature calldata signature
    ) public view returns (bool success) {
        // Verify multisig exists
        if (!_multisigExists(account, multisigHash)) {
            return false;
        }

        // Verify the signature references the correct multisig
        if (signature.multisigHash != multisigHash) {
            return false;
        }

        MultisigConfig storage config = multisigs[account][multisigHash];

        // Ensure arrays are consistent
        if (signature.participantIndices.length != signature.signatures.length) {
            return false;
        }

        // Check we have enough signatures
        if (signature.participantIndices.length < config.threshold) {
            return false;
        }

        // Verify each signature
        uint256 validSignatures = 0;
        uint16 prevIndex = 0;
        bool hasPrev = false;
        for (uint256 i = 0; i < signature.participantIndices.length; i++) {
            uint16 keyIndex = signature.participantIndices[i];

            // Enforce strictly increasing, sorted indices to prevent duplicates / double-counting
            if (hasPrev) {
                if (keyIndex <= prevIndex) {
                    return false;
                }
            } else {
                hasPrev = true;
            }
            prevIndex = keyIndex;

            // Check this key is a valid signer
            if ((config.signerBitmap & (1 << keyIndex)) == 0) {
                continue; // Skip invalid signers
            }

            // Check key index is within bounds
            if (keyIndex >= keyHashes[account].length) {
                continue; // Skip out of bounds indices
            }

            bytes32 keyHash = keyHashes[account][keyIndex];

            // Verify this individual signature
            if (verifySignatureWithKey(account, keyHash, digest, signature.signatures[i])) {
                validSignatures++;

                // Early exit if we have enough valid signatures
                if (validSignatures >= config.threshold) {
                    return true;
                }
            }
        }

        return validSignatures >= config.threshold;
    }

    /**
     * @notice Schedules a multisig removal for an account
     * @param account The account to schedule multisig removal for
     * @param multisigHash The hash of the multisig to schedule for removal
     * @return removableAt The timestamp when the multisig can be removed
     */
    function scheduleMultisigRemoval(address account, bytes32 multisigHash) external returns (uint256 removableAt) {
        _checkKeyManagementAuthorization(account);
        return _scheduleMultisigRemoval(account, multisigHash);
    }

    /**
     * @notice Schedules a multisig removal for the caller
     * @param multisigHash The hash of the multisig to schedule for removal
     * @return removableAt The timestamp when the multisig can be removed
     */
    function scheduleMultisigRemoval(bytes32 multisigHash) external returns (uint256 removableAt) {
        _checkKeyManagementAuthorization(msg.sender);
        return _scheduleMultisigRemoval(msg.sender, multisigHash);
    }

    /**
     * @notice Internal function to schedule multisig removal
     * @param account The account to schedule multisig removal for
     * @param multisigHash The hash of the multisig to schedule for removal
     * @return removableAt The timestamp when the multisig can be removed
     */
    function _scheduleMultisigRemoval(address account, bytes32 multisigHash) internal returns (uint256 removableAt) {
        require(_multisigExists(account, multisigHash), MultisigNotRegistered(account, multisigHash));

        // Get the multisig and its reset period
        MultisigConfig storage config = multisigs[account][multisigHash];
        ResetPeriod resetPeriod = config.resetPeriod;

        unchecked {
            // Calculate when the multisig can be removed (current time + reset period)
            removableAt = block.timestamp + resetPeriod.toSeconds();
        }

        // Store the removal schedule directly in the config
        config.removalTimestamp = uint64(removableAt);

        emit MultisigRemovalScheduled(account, multisigHash, removableAt);
    }

    /**
     * @notice Removes a multisig for an account
     * @param account The account to remove the multisig for
     * @param multisigHash The hash of the multisig to remove
     */
    function removeMultisig(address account, bytes32 multisigHash) external {
        _checkKeyManagementAuthorization(account);
        _removeMultisig(account, multisigHash);
    }

    /**
     * @notice Removes a multisig for the caller
     * @param multisigHash The hash of the multisig to remove
     */
    function removeMultisig(bytes32 multisigHash) external {
        _checkKeyManagementAuthorization(msg.sender);
        _removeMultisig(msg.sender, multisigHash);
    }

    /**
     * @notice Internal function to remove a multisig
     * @param account The account to remove the multisig for
     * @param multisigHash The hash of the multisig to remove
     */
    function _removeMultisig(address account, bytes32 multisigHash) internal {
        // Check if removal has been properly scheduled and timelock has expired
        MultisigConfig storage config = multisigs[account][multisigHash];
        uint64 removableAt = config.removalTimestamp;
        require(removableAt != 0 && removableAt <= block.timestamp, MultisigRemovalUnavailable(removableAt));

        // Remove back-references for each key that was in this multisig
        uint256 signerBitmap = config.signerBitmap;
        for (uint256 i = 0; i < keyHashes[account].length; i++) {
            if ((signerBitmap & (1 << i)) != 0) {
                bytes32 keyHash = keyHashes[account][i];

                // Remove back-reference to this multisig from the key
                bytes32[] storage list = _multisigsUsingKey[account][keyHash];
                for (uint256 j = 0; j < list.length; j++) {
                    if (list[j] == multisigHash) {
                        if (j < list.length - 1) {
                            list[j] = list[list.length - 1];
                        }
                        list.pop();
                        break;
                    }
                }
            }
        }

        // Get the multisig's index (1-based) and convert to 0-based
        uint256 index = uint256(config.index) - 1;
        bytes32[] storage accountMultisigHashes = multisigHashes[account];

        // If not the last element, swap with last element
        if (index < accountMultisigHashes.length - 1) {
            bytes32 lastMultisigHash = accountMultisigHashes[accountMultisigHashes.length - 1];
            accountMultisigHashes[index] = lastMultisigHash;

            // Update the moved multisig's index in its struct
            multisigs[account][lastMultisigHash].index = uint16(index + 1); // Convert back to 1-based
        }

        // Remove the last element
        accountMultisigHashes.pop();

        // Remove from multisigs mapping (delete the entire struct)
        delete multisigs[account][multisigHash];

        emit MultisigRemoved(account, multisigHash);
    }

    /**
     * @notice Get all multisig hashes for an account
     * @param account The account address
     * @return hashes Array of multisig hashes
     */
    function getMultisigHashes(address account) external view returns (bytes32[] memory hashes) {
        return multisigHashes[account];
    }

    /**
     * @notice Get details about a specific multisig
     * @param account The account address
     * @param multisigHash The multisig hash
     * @return config The multisig configuration
     */
    function getMultisig(address account, bytes32 multisigHash) external view returns (MultisigConfig memory config) {
        require(_multisigExists(account, multisigHash), MultisigNotRegistered(account, multisigHash));
        return multisigs[account][multisigHash];
    }

    /**
     * @notice Get the current authorized key hashes for a multisig
     * @param account The account address
     * @param multisigHash The multisig hash
     * @return authorizedKeyHashes Array of key hashes that are currently authorized signers for this multisig
     */
    function getAuthorizedKeyHashesForMultisig(address account, bytes32 multisigHash)
        external
        view
        returns (bytes32[] memory authorizedKeyHashes)
    {
        require(_multisigExists(account, multisigHash), MultisigNotRegistered(account, multisigHash));

        MultisigConfig storage config = multisigs[account][multisigHash];
        bytes32[] storage accountKeyHashes = keyHashes[account];

        // Single pass with dynamic array builder
        DynamicArrayLib.DynamicArray memory results;
        uint256 maxLen = accountKeyHashes.length;
        if (maxLen > MAX_KEYS_PER_ACCOUNT) maxLen = MAX_KEYS_PER_ACCOUNT; // signerBitmap capacity is 256 bits
        for (uint256 i = 0; i < maxLen; i++) {
            if ((config.signerBitmap & (1 << i)) != 0) {
                results.p(accountKeyHashes[i]);
            }
        }
        authorizedKeyHashes = results.asBytes32Array();
    }

    /**
     * @notice Check if a multisig is registered for an account
     * @param account The account address
     * @param multisigHash The multisig hash
     * @return isRegistered True if multisig is registered
     */
    function isMultisigRegistered(address account, bytes32 multisigHash) external view returns (bool isRegistered) {
        return _multisigExists(account, multisigHash);
    }

    /**
     * @notice Get the count of multisigs for an account
     * @param account The account address
     * @return count Number of registered multisigs
     */
    function getMultisigCount(address account) external view returns (uint256 count) {
        return multisigHashes[account].length;
    }

    /**
     * @notice Get the removal status for a specific multisig
     * @param account The account address
     * @param multisigHash The multisig hash
     * @return isScheduled True if removal is scheduled
     * @return removableAt The timestamp when the multisig can be removed (0 if not scheduled)
     */
    function getMultisigRemovalStatus(address account, bytes32 multisigHash)
        external
        view
        returns (bool isScheduled, uint256 removableAt)
    {
        require(_multisigExists(account, multisigHash), MultisigNotRegistered(account, multisigHash));
        uint64 schedule = multisigs[account][multisigHash].removalTimestamp;
        isScheduled = (schedule != 0);
        removableAt = uint256(schedule);
    }

    /**
     * @notice Check if a multisig can be removed immediately
     * @param account The account address
     * @param multisigHash The multisig hash
     * @return canRemove True if the multisig can be removed now
     */
    function canRemoveMultisig(address account, bytes32 multisigHash) external view returns (bool canRemove) {
        uint64 removableAt = multisigs[account][multisigHash].removalTimestamp;
        return (removableAt != 0 && block.timestamp >= removableAt);
    }

    /**
     * @notice Computes a stable identity hash for a multisig configuration
     * @dev Uses the set of authorized key hashes (order-independent), threshold, signerCount, and resetPeriod.
     *      This remains stable even if key indices shift.
     * @param authorizedKeyHashes The array of authorized key hashes
     * @param threshold The number of signatures required
     * @param signerCount Total number of signers
     * @param resetPeriod The reset period of the multisig
     * @return multisigHash The identity hash of the configuration
     */
    function _computeMultisigIdentityHash(
        bytes32[] memory authorizedKeyHashes,
        uint8 threshold,
        uint8 signerCount,
        ResetPeriod resetPeriod
    ) internal pure returns (bytes32 multisigHash) {
        // Sort the hashes to make the identity hash order-independent (using solady's LibSort)
        LibSort.sort(authorizedKeyHashes);
        return keccak256(abi.encode(authorizedKeyHashes, threshold, signerCount, resetPeriod));
    }

    /**
     * @notice Checks if a multisig exists for an account
     * @param account The account address
     * @param multisigHash The multisig hash
     * @return exists True if multisig exists
     */
    function _multisigExists(address account, bytes32 multisigHash) internal view returns (bool exists) {
        return multisigs[account][multisigHash].index != 0;
    }

    /**
     * @notice Get number of active multisigs using a specific key
     * @param account The account address
     * @param keyHash The key hash
     * @return count Number of multisigs using this key
     */
    function getKeyUsageCount(address account, bytes32 keyHash) external view returns (uint256 count) {
        return _multisigsUsingKey[account][keyHash].length;
    }

    /**
     * @notice Check if a key can be safely removed
     * @param account The account address
     * @param keyHash The key hash
     * @return canRemove True if the key is not used in any active multisigs
     */
    function canSafelyRemoveKey(address account, bytes32 keyHash) external view returns (bool canRemove) {
        return _multisigsUsingKey[account][keyHash].length == 0;
    }
}
