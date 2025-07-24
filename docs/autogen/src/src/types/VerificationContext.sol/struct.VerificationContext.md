# VerificationContext
[Git Source](https://github.com/Uniswap/emissary/blob/338b5651e3672b8603d73d0f0092a62f1841b4f8/src/types/VerificationContext.sol)

Struct for passing protocol-specific verification context data

*This allows protocols to define their own verification requirements
while using the same key management infrastructure*


```solidity
struct VerificationContext {
    bytes32 protocol;
    bytes data;
    uint256 expiration;
    uint256 nonce;
}
```

