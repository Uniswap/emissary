# VerificationContext
[Git Source](https://github.com/Uniswap/emissary/blob/73d4c334089f173fa867450ba717f1216afcec61/src/types/VerificationContext.sol)

Struct for passing protocol-specific verification context data

*This allows protocols to define their own verification requirements
while using the same key management infrastructure*

**Note:**
security-contact: security@uniswap.org


```solidity
struct VerificationContext {
    bytes32 protocol;
    bytes data;
    uint256 expiration;
    uint256 nonce;
}
```

