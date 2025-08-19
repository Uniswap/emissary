# KeyLib
[Git Source](https://github.com/Uniswap/emissary/blob/338b5651e3672b8603d73d0f0092a62f1841b4f8/src/KeyLib.sol)

Library for key management and signature verification

*Adapted from Uniswap Calibur 7702 wallet implementation*


## Functions
### hash

Hashes a key to create a unique identifier


```solidity
function hash(Key memory key) internal pure returns (bytes32 keyHash);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The key to hash|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`keyHash`|`bytes32`|The keccak256 hash of the key|


### verify

Verifies a signature from `key` over a `digest`

*Signatures from P256 are expected to be over the `sha256` hash of `digest`*


```solidity
function verify(Key storage key, bytes32 digest, bytes calldata signature) internal view returns (bool isValid);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The key to verify against|
|`digest`|`bytes32`|The digest that was signed|
|`signature`|`bytes`|The signature to verify|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isValid`|`bool`|True if the signature is valid|


### isValidKey

Validates that a key is properly formatted


```solidity
function isValidKey(Key memory key) internal pure returns (bool isValid);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The key to validate|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isValid`|`bool`|True if the key is valid|


### fromAddress

Turns a calling address into a key object for Secp256k1


```solidity
function fromAddress(address caller, ResetPeriod resetPeriod) internal pure returns (Key memory key);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`caller`|`address`|The address to convert to a key|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The key object representing the caller|


### fromP256

Creates a P256 key from x,y coordinates


```solidity
function fromP256(bytes32 x, bytes32 y, ResetPeriod resetPeriod) internal pure returns (Key memory key);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`x`|`bytes32`|The x coordinate of the P256 public key|
|`y`|`bytes32`|The y coordinate of the P256 public key|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The P256 key object|


### fromWebAuthnP256

Creates a WebAuthn P256 key from x,y coordinates


```solidity
function fromWebAuthnP256(uint256 x, uint256 y, ResetPeriod resetPeriod) internal pure returns (Key memory key);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`x`|`uint256`|The x coordinate of the WebAuthn P256 public key|
|`y`|`uint256`|The y coordinate of the WebAuthn P256 public key|
|`resetPeriod`|`ResetPeriod`|The reset period for the key|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`key`|`Key`|The WebAuthn P256 key object|


