# BaseKeyVerifier
[Git Source](https://github.com/Uniswap/emissary/blob/026379c337c2c643aa148c4bc9f4bfba296a3b4a/src/BaseKeyVerifier.sol)

**Inherits:**
[GenericKeyManager](/src/GenericKeyManager.sol/contract.GenericKeyManager.md), [ISignatureVerifier](/src/interfaces/ISignatureVerifier.sol/interface.ISignatureVerifier.md)

A base contract that implements ISignatureVerifier with common verification patterns

*This contract provides a foundation for protocols to build upon by combining
key management with signature verification functionality*


## State Variables
### PROTOCOL_ID
Protocol identifier for this base verifier


```solidity
bytes32 public immutable PROTOCOL_ID;
```


## Functions
### constructor


```solidity
constructor(bytes32 protocolId);
```

### verifySignature

Verifies a signature for a specific protocol context


```solidity
function verifySignature(address account, bytes32 digest, bytes calldata signature, bytes calldata context)
    external
    view
    override
    returns (bytes4 selector);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose keys should be checked|
|`digest`|`bytes32`|The digest that was signed|
|`signature`|`bytes`|The signature to verify|
|`context`|`bytes`|Protocol-specific context data|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`selector`|`bytes4`|The function selector if verification succeeds|


### canVerifySignature

Checks if a signature can be verified for a given account and context


```solidity
function canVerifySignature(address account, bytes32 digest, bytes calldata signature, bytes memory context)
    public
    view
    virtual
    override
    returns (bool canVerify);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose keys should be checked|
|`digest`|`bytes32`|The digest that was signed|
|`signature`|`bytes`|The signature to verify|
|`context`|`bytes`|Protocol-specific context data|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`canVerify`|`bool`|True if the signature can be verified|


### registerKeyWithContext

Registers a new key with additional context validation


```solidity
function registerKeyWithContext(
    address account,
    KeyType keyType,
    bytes calldata publicKey,
    ResetPeriod resetPeriod,
    bytes calldata context
) external returns (bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to register the key for|
|`keyType`|`KeyType`|The type of key to register|
|`publicKey`|`bytes`|The public key to register|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|
|`context`|`bytes`|Additional context for validation|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the registered key|


### registerKeyWithContext

Registers a new key with additional context validation for the caller


```solidity
function registerKeyWithContext(
    KeyType keyType,
    bytes calldata publicKey,
    ResetPeriod resetPeriod,
    bytes calldata context
) external returns (bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`keyType`|`KeyType`|The type of key to register|
|`publicKey`|`bytes`|The public key to register|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|
|`context`|`bytes`|Additional context for validation|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the registered key|


### _registerKeyWithContext

Registers a new key with additional context validation


```solidity
function _registerKeyWithContext(
    address account,
    KeyType keyType,
    bytes calldata publicKey,
    ResetPeriod resetPeriod,
    bytes memory context
) internal returns (bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account to register the key for|
|`keyType`|`KeyType`|The type of key to register|
|`publicKey`|`bytes`|The public key to register|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|
|`context`|`bytes`|Additional context for validation|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The hash of the registered key|


### getCompatibleKeys

Filters keys based on protocol compatibility


```solidity
function getCompatibleKeys(address account, bytes32 protocol) external view returns (bytes32[] memory compatibleKeys);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account whose keys to filter|
|`protocol`|`bytes32`|The protocol identifier|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`compatibleKeys`|`bytes32[]`|Array of key hashes compatible with the protocol|


### _parseContext

Parses the context bytes into a VerificationContext struct


```solidity
function _parseContext(bytes memory context) internal pure returns (VerificationContext memory ctx);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`context`|`bytes`|The context bytes to parse|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ctx`|`VerificationContext`|The parsed VerificationContext|


### _validateContext

Validates the context for correctness


```solidity
function _validateContext(VerificationContext memory ctx) internal view virtual returns (bool isValid);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`ctx`|`VerificationContext`|The context to validate|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isValid`|`bool`|True if the context is valid|


### _isProtocolSupported

Checks if a protocol is supported


```solidity
function _isProtocolSupported(bytes32 protocol) internal view virtual returns (bool isSupported);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`protocol`|`bytes32`|The protocol identifier|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isSupported`|`bool`|True if the protocol is supported|


### _isKeyCompatible

Checks if a key is compatible with a protocol


```solidity
function _isKeyCompatible(address account, bytes32 keyHash, bytes32 protocol)
    internal
    view
    virtual
    returns (bool isCompatible);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|The account that owns the key|
|`keyHash`|`bytes32`|The key hash to check|
|`protocol`|`bytes32`|The protocol identifier|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isCompatible`|`bool`|True if the key is compatible|


### createBasicContext

Creates a basic verification context with protocol and expiration


```solidity
function createBasicContext(bytes32 protocol, uint256 expiration) public virtual returns (bytes memory context);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`protocol`|`bytes32`|The protocol identifier|
|`expiration`|`uint256`|The expiration timestamp (0 for no expiration)|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`context`|`bytes`|The encoded context bytes|


### createContext

Creates a context with additional data


```solidity
function createContext(bytes32 protocol, bytes memory data, uint256 expiration, uint256 nonce)
    public
    pure
    virtual
    returns (bytes memory context);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`protocol`|`bytes32`|The protocol identifier|
|`data`|`bytes`|Additional protocol-specific data|
|`expiration`|`uint256`|The expiration timestamp (0 for no expiration)|
|`nonce`|`uint256`|The nonce for replay protection|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`context`|`bytes`|The encoded context bytes|


## Errors
### SignatureVerificationFailed
Emitted when signature verification fails


```solidity
error SignatureVerificationFailed();
```

### InvalidContext
Emitted when context validation fails


```solidity
error InvalidContext();
```

