# Key
[Git Source](https://github.com/Uniswap/emissary/blob/338b5651e3672b8603d73d0f0092a62f1841b4f8/src/KeyLib.sol)

Represents a cryptographic key with its type, reset period, removal timestamp, and encoded public key


```solidity
struct Key {
    KeyType keyType;
    ResetPeriod resetPeriod;
    uint64 removalTimestamp;
    uint16 index;
    bytes publicKey;
}
```

**Properties**

|Name|Type|Description|
|----|----|-----------|
|`keyType`|`KeyType`|The type of key. See the {KeyType} enum.|
|`resetPeriod`|`ResetPeriod`|The reset period for timelock verification.|
|`removalTimestamp`|`uint64`|The timestamp when key can be removed (0 means not scheduled for removal).|
|`index`|`uint16`|The 1-based index of this key in the keyHashes array (0 means not registered).|
|`publicKey`|`bytes`|The public key in encoded form.|

