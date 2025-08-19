# MultisigConfig
[Git Source](https://github.com/Uniswap/emissary/blob/338b5651e3672b8603d73d0f0092a62f1841b4f8/src/GenericKeyManager.sol)

Configuration for M-of-N multisig


```solidity
struct MultisigConfig {
    uint256 signerBitmap;
    uint8 threshold;
    uint8 signerCount;
    ResetPeriod resetPeriod;
    uint64 removalTimestamp;
    uint16 index;
}
```

**Properties**

|Name|Type|Description|
|----|----|-----------|
|`signerBitmap`|`uint256`|Bitmap indicating which keys are signers (bit i = keyHashes[account][i] is a signer)|
|`threshold`|`uint8`|The number of signatures required (M)|
|`signerCount`|`uint8`|The total number of signers (N)|
|`resetPeriod`|`ResetPeriod`|The reset period for configuration changes|
|`removalTimestamp`|`uint64`|Timestamp when multisig can be removed (0 means not scheduled)|
|`index`|`uint16`|The 1-based index of this multisig in the multisigHashes array (0 means not registered)|

