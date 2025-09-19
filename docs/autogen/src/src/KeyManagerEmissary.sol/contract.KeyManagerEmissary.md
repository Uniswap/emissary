# KeyManagerEmissary
[Git Source](https://github.com/Uniswap/emissary/blob/73d4c334089f173fa867450ba717f1216afcec61/src/KeyManagerEmissary.sol)

**Inherits:**
[BaseKeyVerifier](/src/BaseKeyVerifier.sol/contract.BaseKeyVerifier.md), IEmissary

A Compact-specific adapter that implements IEmissary using the generic key management foundation

**Note:**
security-contact: security@uniswap.org


## Functions
### constructor

Constructor that initializes the protocol identifier


```solidity
constructor() BaseKeyVerifier(keccak256('the-compact.emissary.v1'));
```

### verifyClaim

Verifies a claim signature using the registered keys for the sponsor


```solidity
function verifyClaim(address sponsor, bytes32 digest, bytes32 claimHash, bytes calldata signature, bytes12 lockTag)
    external
    view
    override
    returns (bytes4 selector);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`sponsor`|`address`|The sponsor whose keys should be checked|
|`digest`|`bytes32`|The EIP-712 digest that was signed|
|`claimHash`|`bytes32`|The claim hash that was signed|
|`signature`|`bytes`|The signature bytes|
|`lockTag`|`bytes12`|The lock tag to check reset period compatibility|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`selector`|`bytes4`|IEmissary.verifyClaim.selector if verification succeeds|


### canVerifyClaim

Checks if a signature can be verified for a given sponsor and lock tag using any of their registered keys


```solidity
function canVerifyClaim(address sponsor, bytes32 digest, bytes32 claimHash, bytes calldata signature, bytes12 lockTag)
    public
    view
    returns (bool canVerify);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`sponsor`|`address`|The sponsor address|
|`digest`|`bytes32`|The EIP-712 digest that was signed|
|`claimHash`|`bytes32`|The claim hash that was signed|
|`signature`|`bytes`|The signature bytes|
|`lockTag`|`bytes12`|The lock tag to check reset period compatibility|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`canVerify`|`bool`|True if the signature can be verified|


### canVerifySignature

Checks if a signature can be verified for a given account and context

*Parses the verification context to extract the lock tag, and enforces
reset period compatibility when verifying signatures for The Compact.*


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


### getKeysForResetPeriod

Get keys compatible with a specific reset period


```solidity
function getKeysForResetPeriod(address sponsor, ResetPeriod resetPeriod) external view returns (bytes32[] memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`sponsor`|`address`|The sponsor address|
|`resetPeriod`|`ResetPeriod`|The reset period to check compatibility against|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32[]`|compatibleKeys Array of key hashes compatible with the reset period|


### _isKeyCompatible

Checks if a key is compatible with a protocol

*Implements the key compatibility check for The Compact (any valid key)*


```solidity
function _isKeyCompatible(address account, bytes32 keyHash, bytes32 protocol)
    internal
    view
    virtual
    override
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


### _validateContext

Validates the context for correctness

*Extends the base validation to include The Compact protocol*


```solidity
function _validateContext(VerificationContext memory ctx) internal view virtual override returns (bool isValid);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`ctx`|`VerificationContext`|The context to validate|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`isValid`|`bool`|True if the context is valid|


