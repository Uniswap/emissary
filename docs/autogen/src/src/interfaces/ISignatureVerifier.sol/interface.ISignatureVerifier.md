# ISignatureVerifier
[Git Source](https://github.com/Uniswap/emissary/blob/73d4c334089f173fa867450ba717f1216afcec61/src/interfaces/ISignatureVerifier.sol)

Generic interface for signature verification across different protocols

*This interface allows protocols to define their own verification logic
while using the same underlying key management infrastructure*

**Note:**
security-contact: security@uniswap.org


## Functions
### verifySignature

Verifies a signature for a specific protocol context


```solidity
function verifySignature(address account, bytes32 digest, bytes calldata signature, bytes calldata context)
    external
    view
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
function canVerifySignature(address account, bytes32 digest, bytes calldata signature, bytes calldata context)
    external
    view
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


