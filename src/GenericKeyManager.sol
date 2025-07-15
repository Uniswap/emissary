// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Key, KeyLib, KeyType} from './KeyLib.sol';
import {IdLib} from 'lib/the-compact/src/lib/IdLib.sol';
import {ResetPeriod} from 'lib/the-compact/src/types/ResetPeriod.sol';

/**
 * @title GenericKeyManager
 * @notice A generic key management contract that provides core functionality
 * @dev This contract handles key registration, removal, and timelock mechanisms
 * while being protocol-agnostic. Other contracts can inherit from this to add
 * protocol-specific verification logic.
 */
contract GenericKeyManager {
    using KeyLib for Key;
    using IdLib for ResetPeriod;

    /// @notice Registry of authorized keys for each account
    /// @dev account => keyHash => Key
    mapping(address account => mapping(bytes32 keyHash => Key key)) public keys;

    /// @notice List of key hashes for each account (for enumeration)
    /// @dev account => keyHash[]
    mapping(address account => bytes32[] keyHashes) public keyHashes;

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
            removableAt = block.timestamp + _resetPeriodToSeconds(resetPeriod);
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

    /**
     * @notice Converts a ResetPeriod enum to seconds
     * @param resetPeriod The reset period to convert
     * @return seconds The reset period in seconds
     */
    function _resetPeriodToSeconds(ResetPeriod resetPeriod) internal pure returns (uint256) {
        return resetPeriod.toSeconds();
    }
}
