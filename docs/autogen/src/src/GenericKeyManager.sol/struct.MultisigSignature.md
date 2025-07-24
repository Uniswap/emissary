# MultisigSignature
[Git Source](https://github.com/Uniswap/emissary/blob/338b5651e3672b8603d73d0f0092a62f1841b4f8/src/GenericKeyManager.sol)

Signature data for multisig verification


```solidity
struct MultisigSignature {
    bytes32 multisigHash;
    uint16[] participantIndices;
    bytes[] signatures;
}
```

**Properties**

|Name|Type|Description|
|----|----|-----------|
|`multisigHash`|`bytes32`|The hash of the multisig configuration to use|
|`participantIndices`|`uint16[]`|Array of key indices that signed (must be sorted)|
|`signatures`|`bytes[]`|Corresponding signatures from the participants|

