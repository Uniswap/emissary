# KeyLib
[Git Source](https://github.com/Uniswap/emissary/blob/73d4c334089f173fa867450ba717f1216afcec61/src/KeyLib.sol)

Library for key management and signature verification

*Adapted from Uniswap Calibur 7702 wallet implementation*

**Note:**
security-contact: security@uniswap.org


## State Variables
### P256_P

```solidity
uint256 internal constant P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
```


### P256_B

```solidity
uint256 internal constant P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
```


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


### _p256IsOnCurve

Checks if a P256 point is on the curve

*a = -3 mod p is handled via subtraction; we use x^3 - 3x + b form*


```solidity
function _p256IsOnCurve(bytes32 xBytes, bytes32 yBytes) internal pure returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`xBytes`|`bytes32`|The x coordinate of the P256 point|
|`yBytes`|`bytes32`|The y coordinate of the P256 point|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|True if the point is on the curve|


