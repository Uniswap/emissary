# GenericKeyManager
[Git Source](https://github.com/Uniswap/emissary/blob/73d4c334089f173fa867450ba717f1216afcec61/src/GenericKeyManager.sol)

A generic key management contract that provides core functionality

*This contract handles key registration, removal, and timelock mechanisms
while being protocol-agnostic. Other contracts can inherit from this to add
protocol-specific verification logic.*

**Note:**
security-contact: security@uniswap.org


## State Variables
### MAX_KEYS_PER_ACCOUNT
Maximum number of keys allowed per account (due to 256-bit signer bitmap)


```solidity
uint256 public constant MAX_KEYS_PER_ACCOUNT = 256;
```


### keys
Registry of authorized keys for each account

*account => keyHash => Key*


```solidity
mapping(address account => mapping(bytes32 keyHash => Key key)) public keys;
```


### keyHashes
List of key hashes for each account (for enumeration)

*account => keyHash[]*


```solidity
mapping(address account => bytes32[] keyHashes) public keyHashes;
```


### multisigs
Registry of multisig configurations for each account

*account => multisigHash => MultisigConfig*


```solidity
mapping(address account => mapping(bytes32 multisigHash => MultisigConfig multisig)) public multisigs;
```


### multisigHashes
List of multisig hashes for each account (for enumeration)

*account => multisigHash[]*


```solidity
mapping(address account => bytes32[] multisigHashes) public multisigHashes;
```


### _multisigsUsingKey
Track which multisigs use a given key for an account

*account => keyHash => multisigHash[]*


```solidity
mapping(address account => mapping(bytes32 keyHash => bytes32[] multisigsUsingKey)) internal _multisigsUsingKey;
```


## Functions
### registerKey

Registers a new key for an account


```solidity
function registerKey(address account, KeyType keyType, bytes calldata publicKey, ResetPeriod resetPeriod)
    external
    returns (bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to register the key for|
|`keyType`|`KeyType`|The type of key to register|
|`publicKey`|`bytes`|The public key to register|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the registered key|


### registerKey

Registers a new key for the caller


```solidity
function registerKey(KeyType keyType, bytes calldata publicKey, ResetPeriod resetPeriod)
    external
    virtual
    returns (bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyType`|`KeyType`|The type of key to register|
|`publicKey`|`bytes`|The public key to register|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the registered key|


### _registerKey


```solidity
function _registerKey(address account, KeyType keyType, bytes calldata publicKey, ResetPeriod resetPeriod)
    internal
    virtual
    returns (bytes32 keyHash);
```

### scheduleKeyRemoval

Schedules a key removal for an account


```solidity
function scheduleKeyRemoval(address account, bytes32 keyHash) public returns (uint256 removableAt);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to schedule key removal for|
|`keyHash`|`bytes32`|The hash of the key to schedule for removal|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`removableAt`|`uint256`|The timestamp when the key can be removed|


### scheduleKeyRemoval

Schedules a key removal for the caller


```solidity
function scheduleKeyRemoval(bytes32 keyHash) external virtual returns (uint256 removableAt);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the key to schedule for removal|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`removableAt`|`uint256`|The timestamp when the key can be removed|


### _scheduleKeyRemoval


```solidity
function _scheduleKeyRemoval(address account, bytes32 keyHash) internal returns (uint256 removableAt);
```

### removeKey

Removes a key for an account


```solidity
function removeKey(address account, bytes32 keyHash) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to remove the key for|
|`keyHash`|`bytes32`|The hash of the key to remove|


### removeKey

Removes a key for the caller


```solidity
function removeKey(bytes32 keyHash) external virtual;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the key to remove|


### _removeKey


```solidity
function _removeKey(address account, bytes32 keyHash) internal;
```

### verifySignatureWithKey

Verifies a signature using a specific registered key


```solidity
function verifySignatureWithKey(address account, bytes32 keyHash, bytes32 digest, bytes calldata signature)
    public
    view
    returns (bool success);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose key should be checked|
|`keyHash`|`bytes32`|The specific key hash to verify against|
|`digest`|`bytes32`|The digest that was signed|
|`signature`|`bytes`|The signature bytes|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`success`|`bool`|True if the signature was verified successfully|


### verifySignatureWithAnyKey

Verifies a signature using any of the registered keys for an account


```solidity
function verifySignatureWithAnyKey(address account, bytes32 digest, bytes calldata signature)
    public
    view
    returns (bool success, bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose keys should be checked|
|`digest`|`bytes32`|The digest that was signed|
|`signature`|`bytes`|The signature bytes|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`success`|`bool`|True if the signature was verified successfully|
|`keyHash`|`bytes32`|The hash of the key that successfully verified the signature|


### getKey

Get details about a specific key


```solidity
function getKey(address account, bytes32 keyHash) external view returns (Key memory key);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The key details|


### getKeyHashes

Get all key hashes for an account


```solidity
function getKeyHashes(address account) external view returns (bytes32[] memory hashes);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`hashes`|`bytes32[]`|Array of key hashes|


### isKeyRegistered

Check if a key is registered for an account


```solidity
function isKeyRegistered(address account, bytes32 keyHash) external view returns (bool isRegistered);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isRegistered`|`bool`|True if key is registered|


### getKeyCount

Get the count of keys for an account


```solidity
function getKeyCount(address account) external view returns (uint256 count);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`count`|`uint256`|Number of registered keys|


### computeKeyHash

Compute the hash of a key


```solidity
function computeKeyHash(Key calldata key) external pure returns (bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The key to hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the key|


### validateKey

Validate a key structure


```solidity
function validateKey(Key calldata key) external pure returns (bool isValid);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The key to validate|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isValid`|`bool`|True if the key is valid|


### getKeyResetPeriod

Get the reset period for a specific key


```solidity
function getKeyResetPeriod(address account, bytes32 keyHash) external view returns (ResetPeriod resetPeriod);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|


### getKeyRemovalStatus

Get the removal status for a specific key


```solidity
function getKeyRemovalStatus(address account, bytes32 keyHash)
    external
    view
    returns (bool isScheduled, uint256 removableAt);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isScheduled`|`bool`|True if removal is scheduled|
|`removableAt`|`uint256`|The timestamp when the key can be removed (0 if not scheduled)|


### canRemoveKey

Check if a key can be removed immediately


```solidity
function canRemoveKey(address account, bytes32 keyHash) external view returns (bool canRemove);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`canRemove`|`bool`|True if the key can be removed now|


### _keyExists

Checks if a key exists for an account


```solidity
function _keyExists(address account, bytes32 keyHash) internal view returns (bool exists);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`exists`|`bool`|True if key exists|


### _checkKeyManagementAuthorization

Checks if the caller is authorized to manage keys for an account

*Override this function in derived contracts to implement custom authorization logic*


```solidity
function _checkKeyManagementAuthorization(address account) internal view virtual;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to check authorization for|


### registerMultisig

Registers a new multisig for an account


```solidity
function registerMultisig(address account, uint8 threshold, uint16[] calldata signerIndices, ResetPeriod resetPeriod)
    external
    returns (bytes32 multisigHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to register the multisig for|
|`threshold`|`uint8`|The number of signatures required (M)|
|`signerIndices`|`uint16[]`|Array of key indices that can sign (references keyHashes[account])|
|`resetPeriod`|`ResetPeriod`|The reset period for the multisig|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The hash of the registered multisig|


### registerMultisig

Registers a new multisig for the caller


```solidity
function registerMultisig(uint8 threshold, uint16[] calldata signerIndices, ResetPeriod resetPeriod)
    external
    returns (bytes32 multisigHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`threshold`|`uint8`|The number of signatures required (M)|
|`signerIndices`|`uint16[]`|Array of key indices that can sign|
|`resetPeriod`|`ResetPeriod`|The reset period for the multisig|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The hash of the registered multisig|


### _registerMultisig

Internal function to register a multisig


```solidity
function _registerMultisig(address account, uint8 threshold, uint16[] calldata signerIndices, ResetPeriod resetPeriod)
    internal
    returns (bytes32 multisigHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to register the multisig for|
|`threshold`|`uint8`|The number of signatures required (M)|
|`signerIndices`|`uint16[]`|Array of key indices that can sign (references keyHashes[account])|
|`resetPeriod`|`ResetPeriod`|The reset period for the multisig|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The hash of the registered multisig|


### verifyMultisigSignature

Verifies a multisig signature


```solidity
function verifyMultisigSignature(
    address account,
    bytes32 multisigHash,
    bytes32 digest,
    MultisigSignature calldata signature
) public view returns (bool success);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose multisig should be checked|
|`multisigHash`|`bytes32`|The hash of the multisig configuration to use|
|`digest`|`bytes32`|The digest that was signed|
|`signature`|`MultisigSignature`|The multisig signature data|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`success`|`bool`|True if the signature was verified successfully|


### scheduleMultisigRemoval

Schedules a multisig removal for an account


```solidity
function scheduleMultisigRemoval(address account, bytes32 multisigHash) external returns (uint256 removableAt);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to schedule multisig removal for|
|`multisigHash`|`bytes32`|The hash of the multisig to schedule for removal|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`removableAt`|`uint256`|The timestamp when the multisig can be removed|


### scheduleMultisigRemoval

Schedules a multisig removal for the caller


```solidity
function scheduleMultisigRemoval(bytes32 multisigHash) external returns (uint256 removableAt);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The hash of the multisig to schedule for removal|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`removableAt`|`uint256`|The timestamp when the multisig can be removed|


### _scheduleMultisigRemoval

Internal function to schedule multisig removal


```solidity
function _scheduleMultisigRemoval(address account, bytes32 multisigHash) internal returns (uint256 removableAt);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to schedule multisig removal for|
|`multisigHash`|`bytes32`|The hash of the multisig to schedule for removal|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`removableAt`|`uint256`|The timestamp when the multisig can be removed|


### removeMultisig

Removes a multisig for an account


```solidity
function removeMultisig(address account, bytes32 multisigHash) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to remove the multisig for|
|`multisigHash`|`bytes32`|The hash of the multisig to remove|


### removeMultisig

Removes a multisig for the caller


```solidity
function removeMultisig(bytes32 multisigHash) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The hash of the multisig to remove|


### _removeMultisig

Internal function to remove a multisig


```solidity
function _removeMultisig(address account, bytes32 multisigHash) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to remove the multisig for|
|`multisigHash`|`bytes32`|The hash of the multisig to remove|


### getMultisigHashes

Get all multisig hashes for an account


```solidity
function getMultisigHashes(address account) external view returns (bytes32[] memory hashes);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`hashes`|`bytes32[]`|Array of multisig hashes|


### getMultisig

Get details about a specific multisig


```solidity
function getMultisig(address account, bytes32 multisigHash) external view returns (MultisigConfig memory config);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`config`|`MultisigConfig`|The multisig configuration|


### getAuthorizedKeyHashesForMultisig

Get the current authorized key hashes for a multisig


```solidity
function getAuthorizedKeyHashesForMultisig(address account, bytes32 multisigHash)
    external
    view
    returns (bytes32[] memory authorizedKeyHashes);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`authorizedKeyHashes`|`bytes32[]`|Array of key hashes that are currently authorized signers for this multisig|


### isMultisigRegistered

Check if a multisig is registered for an account


```solidity
function isMultisigRegistered(address account, bytes32 multisigHash) external view returns (bool isRegistered);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isRegistered`|`bool`|True if multisig is registered|


### getMultisigCount

Get the count of multisigs for an account


```solidity
function getMultisigCount(address account) external view returns (uint256 count);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`count`|`uint256`|Number of registered multisigs|


### getMultisigRemovalStatus

Get the removal status for a specific multisig


```solidity
function getMultisigRemovalStatus(address account, bytes32 multisigHash)
    external
    view
    returns (bool isScheduled, uint256 removableAt);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isScheduled`|`bool`|True if removal is scheduled|
|`removableAt`|`uint256`|The timestamp when the multisig can be removed (0 if not scheduled)|


### canRemoveMultisig

Check if a multisig can be removed immediately


```solidity
function canRemoveMultisig(address account, bytes32 multisigHash) external view returns (bool canRemove);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`canRemove`|`bool`|True if the multisig can be removed now|


### _computeMultisigIdentityHash

Computes a stable identity hash for a multisig configuration

*Uses the set of authorized key hashes (order-independent), threshold, signerCount, and resetPeriod.
This remains stable even if key indices shift.*


```solidity
function _computeMultisigIdentityHash(
    bytes32[] memory authorizedKeyHashes,
    uint8 threshold,
    uint8 signerCount,
    ResetPeriod resetPeriod
) internal pure returns (bytes32 multisigHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`authorizedKeyHashes`|`bytes32[]`|The array of authorized key hashes|
|`threshold`|`uint8`|The number of signatures required|
|`signerCount`|`uint8`|Total number of signers|
|`resetPeriod`|`ResetPeriod`|The reset period of the multisig|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The identity hash of the configuration|


### _multisigExists

Checks if a multisig exists for an account


```solidity
function _multisigExists(address account, bytes32 multisigHash) internal view returns (bool exists);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`exists`|`bool`|True if multisig exists|


### getKeyUsageCount

Get number of active multisigs using a specific key


```solidity
function getKeyUsageCount(address account, bytes32 keyHash) external view returns (uint256 count);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`count`|`uint256`|Number of multisigs using this key|


## Events
### KeyRegistered
Emitted when a key is registered


```solidity
event KeyRegistered(address indexed account, bytes32 indexed keyHash, KeyType keyType, ResetPeriod resetPeriod);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|
|`keyType`|`KeyType`|The key type|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|

### KeyRemoved
Emitted when a key is removed


```solidity
event KeyRemoved(address indexed account, bytes32 indexed keyHash);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

### KeyRemovalScheduled
Emitted when a key removal is scheduled


```solidity
event KeyRemovalScheduled(address indexed account, bytes32 indexed keyHash, uint256 removableAt);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|
|`removableAt`|`uint256`|The timestamp when the key can be removed|

### MultisigRegistered
Emitted when a multisig is registered


```solidity
event MultisigRegistered(
    address indexed account, bytes32 indexed multisigHash, uint8 threshold, uint8 signerCount, ResetPeriod resetPeriod
);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|
|`threshold`|`uint8`|The signature threshold (M)|
|`signerCount`|`uint8`|The total number of signers (N)|
|`resetPeriod`|`ResetPeriod`|The reset period for the multisig|

### MultisigRemoved
Emitted when a multisig is removed


```solidity
event MultisigRemoved(address indexed account, bytes32 indexed multisigHash);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

### MultisigRemovalScheduled
Emitted when a multisig removal is scheduled


```solidity
event MultisigRemovalScheduled(address indexed account, bytes32 indexed multisigHash, uint256 removableAt);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|
|`removableAt`|`uint256`|The timestamp when the multisig can be removed|

## Errors
### KeyAlreadyRegistered
Thrown when a key is already registered


```solidity
error KeyAlreadyRegistered(address account, bytes32 keyHash);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

### KeyNotRegistered
Thrown when a key is not registered


```solidity
error KeyNotRegistered(address account, bytes32 keyHash);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`keyHash`|`bytes32`|The key hash|

### InvalidKey
Thrown when a key is invalid


```solidity
error InvalidKey(bytes32 keyHash);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The key hash|

### KeyRemovalUnavailable
Thrown when key removal is attempted before timelock expires


```solidity
error KeyRemovalUnavailable(uint256 removableAt);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`removableAt`|`uint256`|The timestamp when removal will be available|

### UnauthorizedKeyManagement
Thrown when caller is not authorized to manage keys for the account


```solidity
error UnauthorizedKeyManagement(address caller, address account);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`caller`|`address`|The caller address|
|`account`|`address`|The account address|

### MultisigAlreadyRegistered
Thrown when a multisig is already registered


```solidity
error MultisigAlreadyRegistered(address account, bytes32 multisigHash);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

### MultisigNotRegistered
Thrown when a multisig is not registered


```solidity
error MultisigNotRegistered(address account, bytes32 multisigHash);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account address|
|`multisigHash`|`bytes32`|The multisig hash|

### InvalidMultisigConfig
Thrown when a multisig configuration is invalid


```solidity
error InvalidMultisigConfig(string reason);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`reason`|`string`|The reason for invalidity|

### MultisigRemovalUnavailable
Thrown when multisig removal is attempted before timelock expires


```solidity
error MultisigRemovalUnavailable(uint256 removableAt);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`removableAt`|`uint256`|The timestamp when removal will be available|

### KeyStillInUse
Thrown when trying to remove a key that's still used in multisigs


```solidity
error KeyStillInUse(bytes32 keyHash, uint256 activeMultisigs);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The key hash|
|`activeMultisigs`|`uint256`|Number of multisigs still using this key|

### MultisigSignerIndexCollision
Thrown when updating signer bitmaps would cause two signers to collide on the same index


```solidity
error MultisigSignerIndexCollision(bytes32 multisigHash, uint16 newIndex);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The multisig hash where the collision would occur|
|`newIndex`|`uint16`|The new index that is already occupied in the bitmap|

### MultisigSignerIndexOutOfRange
Thrown when a signer index is >= 256 and cannot be represented in the bitmap


```solidity
error MultisigSignerIndexOutOfRange(uint16 index);
```

**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`index`|`uint16`|The invalid signer index|

