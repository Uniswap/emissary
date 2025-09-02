# @uniswap/emissary

[![CI Status](https://github.com/uniswap/emissary/actions/workflows/test.yaml/badge.svg)](https://github.com/uniswap/emissary/actions)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](./README.md)

**Emissary** is a minimal, audited, protocol-agnostic key management and signature verification layer for EVM accounts that aims to provide a generalized framework for managing delegated signature authority. It supports Secp256k1, P-256, and WebAuthn keys; first-class M-of-N multisig with timelocked key lifecycle; and context-aware verification for arbitrary protocols.

**[KeyManagerEmissary](./src/KeyManagerEmissary.sol)** is a protocol-specific adapter for [The Compact v1](https://github.com/uniswap/the-compact). It is deployed at `0x00000000000059A79403C99B216981C8B7E40Cd7` on several major networks and [can be deployed permissionlessly](#deployments) to the same address on any EVM.

> 🔐 The Emissary codebase has undergone independent security review by [OpenZeppelin](https://openzeppelin.com), and will soon become part of the [Uniswap Labs Bug Bounty Program on Cantina](https://cantina.xyz/code/f9df94db-c7b1-434b-bb06-d1360abdd1be/overview).
>
> All finalized audit reports are available in [the `audits/` folder](./audits).

## Table of Contents

- [Overview](#overview)
- [Deployments](#deployments)
- [Architecture](#architecture)
- [Components](#components)
- [Multisig Support](#multisig-support)
- [Usage](#usage)
- [Examples](#examples)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Overview

The system consists of several composable components that can be used independently or together:

1. **GenericKeyManager**: Core key management functionality (registration, removal, timelocks, M-of-N multisig)
2. **BaseKeyVerifier**: Generic signature verification with protocol support
3. **KeyManagerEmissary**: Compact-specific adapter implementing IEmissary
4. **ISignatureVerifier**: Generic interface for signature verification

### Key Features

#### Security

- **Timelock Protection**: Configurable delays for key removal
- **Access Control**: Customizable authorization patterns
- **Signature Verification**: Multi-algorithm support (Secp256k1, P256, WebAuthn)
- **Replay Protection**: Nonce and expiration support (protocol-specific implementation required)

#### Composability

- **Protocol Agnostic**: Generic foundation for any protocol
- **Modular Design**: Use components independently or together
- **Extensible**: Easy to add new protocols and key types
- **Interoperable**: Standard interfaces for cross-protocol use

#### Gas Efficiency

- **Optimized Storage**: Efficient key storage and enumeration
- **Assembly Usage**: Critical paths optimized with inline assembly
- **Batch Operations**: Support for multiple key operations
- **Minimal Proxy**: Deployable as minimal proxy for gas savings
- **Targeted Verification**: Use `verifySignatureWithKey` for O(1) verification when key hash is known
- **Multisig Optimization**: Bitmap-based signer references backed by existing key management

## Deployments

The deployment script leverages the Immutable Create2 Factory pattern to enable permissionless deterministic deployments of `KeyManagerEmissary` on any EVM network.

### Current known deployments

> ☝️ Feel free to submit a PR if you see a missing deployment.

- [Ethereum Mainnet (chainId 1) @ `0x00000000000059A79403C99B216981C8B7E40Cd7`](https://etherscan.io/address/0x00000000000059A79403C99B216981C8B7E40Cd7)
- [Optimism (chainId 10) @ `0x00000000000059A79403C99B216981C8B7E40Cd7`](https://optimistic.etherscan.io/address/0x00000000000059A79403C99B216981C8B7E40Cd7)
- [Base (chainId 8453) @ `0x00000000000059A79403C99B216981C8B7E40Cd7`](https://basescan.org/address/0x00000000000059A79403C99B216981C8B7E40Cd7)
- [Unichain (chainId 130) @ `0x00000000000059A79403C99B216981C8B7E40Cd7`](https://uniscan.xyz/address/0x00000000000059A79403C99B216981C8B7E40Cd7)
- [Arbitrum One (chainId 42161) @ `0x00000000000059A79403C99B216981C8B7E40Cd7`](https://arbiscan.io/address/0x00000000000059A79403C99B216981C8B7E40Cd7)

### Permissionless deterministic deployment to any EVM chain

Deployments are permissionless and deterministic using the Immutable Create2 Factory at `0x0000000000FFe8B47B3e2130213B802212439497`.

- **Factory**: `0x0000000000FFe8B47B3e2130213B802212439497` (must exist on the target chain)
- **Salt** (derived with [0age's create2crunch](https://github.com/0age/create2crunch)): `0x00000000000000000000000000000000000000006c8e1b192c643f327b4d5c28`
- **Target Address** (with current bytecode): `0x00000000000059A79403C99B216981C8B7E40Cd7`

The [Deploy.s.sol script](./script/Deploy.s.sol) makes deployment a one-step process:

```bash
forge script script/Deploy.s.sol \
  --rpc-url <network> \
  --broadcast \
  -vvvv
```

- The script ensures deployment lands at the expected deterministic address.
- If the contract bytecode changes (compiler/settings/code), the resulting address changes; re-derive before deploying.

Deterministic address derivation follows `keccak256(0xff ++ factory ++ salt ++ keccak256(init_code))` and takes the last 20 bytes; with the factory and salt above and current init code, this equals `0x00000000000059A79403C99B216981C8B7E40Cd7` on every EVM chain.

Notes:

- 0age's ImmutableCreate2Factory is widely deployed; if it's not yet present on a chain you need, you can [deploy it yourself](https://gist.github.com/ccashwell/a62fee57b90e9ee79150b65d9bf7a34d), then call `safeCreate2` with the same salt and init code (or just run the deploy script).
- `safeCreate2` reverts if the contract is already deployed at the deterministic address (idempotent safety).
- Use the same compiler version and settings (e.g., `solc_version`, `via_ir`) to preserve identical creation bytecode across chains. The deployment script will refuse to proceed if the deployed address doesn't match the expected one.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Protocol-Specific Adapters             │
|                           ┌────────────────────┐    │
│  ┌─────────────────────┐  │ ┌────────────────────┐  │
│  │ KeyManagerEmissary  │  │ │   Custom Protocol  │  │
│  │  (The Compact v1)   │  └─│     Adapters       │  │
│  └─────────────────────┘    └────────────────────┘  │
└─────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────┐
│  ┌─────────────────────┐  ┌─────────────────────┐   │
│  │   BaseKeyVerifier   │──│ ISignatureVerifier  │   │
│  │                     │  │    (Interface)      │   │
│  └─────────────────────┘  └─────────────────────┘   │
│              │          \                           │
│  ┌─────────────────────┐ \┌─────────────────────┐   │
│  │  GenericKeyManager  │  │ VerificationContext │   │
│  │                     │  │     (Types)         │   │
│  └─────────────────────┘  └─────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Components

### GenericKeyManager

The foundation contract that handles core key management:

- **Key Registration**: Register Secp256k1, P256, and WebAuthn keys
- **Timelock Removal**: Schedule key removal with configurable reset periods
- **Access Control**: Customizable authorization for key management operations
- **Signature Verification**: Verify signatures against registered keys with two approaches:
  - `verifySignatureWithAnyKey`: Loops through all registered keys to find a match
  - `verifySignatureWithKey`: Verifies against a specific key hash (more efficient)
- **M-of-N Multisig**: Register and verify multisig configurations requiring M signatures from N authorized signers
  - Bitmap-based storage for gas-efficient signer references
  - Flexible threshold requirements (e.g., 2-of-3, 3-of-5)
  - Timelock protection for multisig removal

### BaseKeyVerifier

Extends GenericKeyManager with protocol-aware signature verification:

- **Protocol Support**: Multi-protocol signature verification
- **Context Validation**: Expiration, nonce, and custom protocol data
- **Compatibility Filtering**: Get keys compatible with specific protocols
- **Generic Interface**: Implements ISignatureVerifier for interoperability

### KeyManagerEmissary

An adapter that implements The Compact's IEmissary interface and implements protocol-specific checks:

- **Compact Integration**: Implements [IEmissary](https://github.com/uniswap/the-compact/tree/main/src/interfaces/IEmissary.sol) for The Compact v1
- **Reset Period Compatibility**: Validates keys against lock tag requirements

### ISignatureVerifier

Generic interface for signature verification across protocols:

```solidity
interface ISignatureVerifier {
    function verifySignature(
        address account,
        bytes32 digest,
        bytes calldata signature,
        bytes calldata context
    ) external view returns (bytes4 selector);

    function canVerifySignature(
        address account,
        bytes32 digest,
        bytes calldata signature,
        bytes calldata context
    ) external view returns (bool canVerify);
}
```

## Multisig Support

The GenericKeyManager includes comprehensive M-of-N multisig functionality, allowing accounts to require multiple signatures for authentication. This provides enhanced security through distributed key management.

### Key Features

- **Flexible Thresholds**: Configure any M-of-N requirement (e.g., 2-of-3, 3-of-5, 5-of-10)
- **Bitmap Storage**: Gas-efficient storage using `uint256` bitmaps to reference existing keys
- **Timelock Protection**: Multisig configurations have the same timelock protections as individual keys
- **Composable Design**: Multisigs reference existing registered keys, avoiding duplication

### Multisig Structure

```solidity
struct MultisigConfig {
    uint256 signerBitmap;      // Bitmap of authorized signer key indices
    uint8 threshold;           // Minimum required signatures
    uint8 signerCount;         // Total number of authorized signers
    ResetPeriod resetPeriod;   // Timelock period for removal
    uint64 removalTimestamp;   // When removal becomes available
    uint16 index;              // Position in account's multisig array
}

struct MultisigSignature {
    bytes32 multisigHash;         // Hash of the multisig configuration
    uint16[] participantIndices;  // Indices of signing keys
    bytes[] signatures;           // Corresponding signatures
}
```

### Storage Optimization

The system uses several optimizations for gas efficiency:

- **Bitmap References**: Instead of storing key hashes directly, multisigs use a bitmap where each bit represents a key index
- **Struct Packing**: `MultisigConfig` is optimized to use only 2 storage slots (64 bytes) instead of 3
- **Index-Based Lookup**: Keys are referenced by their registration index for O(1) lookup

### Security Model

- **Key Dependency**: Multisigs reference existing keys, so removing a key invalidates multisigs that depend on it
- **Threshold Enforcement**: Verification strictly requires at least `threshold` valid signatures
- **Unique Participation**: Each key can only contribute one signature per multisig verification
- **Hash Validation**: Multisig signatures must include the correct `multisigHash` for integrity

## Usage

### Basic Key Management

```solidity
// Deploy the key manager
GenericKeyManager keyManager = new GenericKeyManager();

// Register a key
bytes32 keyHash = keyManager.registerKey(
    KeyType.Secp256k1,
    abi.encode(userAddress),
    ResetPeriod.OneDay
);

// Verify a signature against any registered key
(bool success, bytes32 usedKeyHash) = keyManager.verifySignatureWithAnyKey(
    userAddress,
    digest,
    signature
);

// Verify a signature against a specific key (more efficient)
bool success = keyManager.verifySignatureWithKey(
    userAddress,
    keyHash,
    digest,
    signature
);
```

### Multisig Management

```solidity
// Deploy the key manager
GenericKeyManager keyManager = new GenericKeyManager();

// First, register individual keys that will be part of the multisig
bytes32 aliceKey = keyManager.registerKey(
    KeyType.Secp256k1,
    abi.encode(aliceAddress),
    ResetPeriod.OneDay
);

bytes32 bobKey = keyManager.registerKey(
    KeyType.Secp256k1,
    abi.encode(bobAddress),
    ResetPeriod.OneDay
);

bytes32 charlieKey = keyManager.registerKey(
    KeyType.Secp256k1,
    abi.encode(charlieAddress),
    ResetPeriod.OneDay
);

// Register a 2-of-3 multisig using key indices
uint16[] memory signerIndices = new uint16[](3);
signerIndices[0] = 0;  // Alice's key index
signerIndices[1] = 1;  // Bob's key index
signerIndices[2] = 2;  // Charlie's key index

bytes32 multisigHash = keyManager.registerMultisig(
    2,  // threshold: require 2 signatures
    signerIndices,
    ResetPeriod.SevenDaysAndOneHour
);

// Create a multisig signature (Alice + Bob)
uint16[] memory participantIndices = new uint16[](2);
participantIndices[0] = 0;  // Alice participates
participantIndices[1] = 1;  // Bob participates

bytes[] memory signatures = new bytes[](2);
signatures[0] = aliceSignature;  // Alice's signature
signatures[1] = bobSignature;    // Bob's signature

MultisigSignature memory multisigSig = MultisigSignature({
    multisigHash: multisigHash,
    participantIndices: participantIndices,
    signatures: signatures
});

// Verify the multisig signature
bool success = keyManager.verifyMultisigSignature(
    userAddress,
    multisigHash,
    digest,
    multisigSig
);
```

### Protocol-Specific Verification

```solidity
// Deploy the base verifier
BaseKeyVerifier verifier = new BaseKeyVerifier();

// Register a key with context
bytes memory context = verifier.createBasicContext(
    keccak256("MyProtocol"),
    block.timestamp + 1 hours
);

bytes32 keyHash = verifier.registerKeyWithContext(
    KeyType.Secp256k1,
    abi.encode(userAddress),
    ResetPeriod.OneDay,
    context
);

// Verify with protocol context
bool canVerify = verifier.canVerifySignature(
    userAddress,
    digest,
    signature,
    context
);
```

### The Compact Integration

```solidity
// Canonical KeyManagerEmissary
KeyManagerEmissary emissary = KeyManagerEmissary(0x00000000000059A79403C99B216981C8B7E40Cd7);

// Register a key for a sponsor
bytes32 keyHash = emissary.registerKey(
    KeyType.Secp256k1,
    abi.encode(sponsorAddress),
    ResetPeriod.OneDay
);
```

The sponsor can then use the canonical `KeyManagerEmissary` as your emissary in any type of compact. When The Compact attempts to validate the signature provided for the sponsor, it will first attempt to do so directly against the sponsor's own address. If that fails, it will proceed to call `verifyClaim` on the designated emissary:

```
// The Compact makes this call as needed during
// the sponsor signature validation flow
bytes4 selector = emissary.verifyClaim(
    sponsor,
    digest,
    claimHash,
    signature,
    lockTag
);
```

The emissary will then validate the signature against registered keys whose reset period is at least as long as the lock tag associated with the claim being validated. If an eligible key can verify the signature, a magic value (the selector for `IEmissary.verifyClaim`) is returned, confirming to The Compact that the signature represents the sponsor's authorization of the claim in question.

## Examples

### Creating a Custom Protocol Adapter

```solidity
contract MyProtocolAdapter is BaseKeyVerifier, IMyProtocol {
    bytes32 public constant MY_PROTOCOL_ID = keccak256("MyProtocol");

    function verifyMyProtocolSignature(
        address user,
        bytes32 digest,
        bytes calldata signature,
        MyProtocolContext memory ctx
    ) external view returns (bool) {
        bytes memory context = abi.encode(
            MY_PROTOCOL_ID,
            abi.encode(ctx),
            ctx.expiration,
            ctx.nonce
        );

        return canVerifySignature(user, digest, signature, context);
    }

    function _isProtocolSupported(bytes32 protocol)
        internal
        view
        virtual
        override
        returns (bool)
    {
        return protocol == MY_PROTOCOL_ID || super._isProtocolSupported(protocol);
    }
}
```

### Advanced Key Management

```solidity
// Custom authorization logic
contract ManagedKeyManager is GenericKeyManager {
    mapping(address => address) public managers;

    function setManager(address manager) external {
        managers[msg.sender] = manager;
    }

    function _checkKeyManagementAuthorization(address account)
        internal
        view
        virtual
        override
    {
        require(
            msg.sender == account || msg.sender == managers[account],
            "Unauthorized"
        );
    }
}
```

### Corporate Multisig Wallet

```solidity
contract CorporateWallet is GenericKeyManager {
    struct Department {
        string name;
        bytes32[] multisigHashes;
        uint256 spendingLimit;
    }

    mapping(bytes32 => Department) public departments;
    mapping(bytes32 => uint256) public multisigSpendingLimits;

    event TransactionExecuted(
        bytes32 indexed multisigHash,
        address indexed to,
        uint256 amount,
        bytes32 txHash
    );

    function createDepartment(
        bytes32 deptId,
        string memory name,
        uint16[] memory signerIndices,
        uint8 threshold,
        uint256 spendingLimit
    ) external {
        // Register department multisig
        bytes32 multisigHash = this.registerMultisig(
            threshold,
            signerIndices,
            ResetPeriod.SevenDaysAndOneHour
        );

        departments[deptId].name = name;
        departments[deptId].multisigHashes.push(multisigHash);
        departments[deptId].spendingLimit = spendingLimit;
        multisigSpendingLimits[multisigHash] = spendingLimit;
    }

    function executeTransaction(
        bytes32 multisigHash,
        address to,
        uint256 amount,
        bytes32 digest,
        MultisigSignature memory signature
    ) external {
        // Verify multisig signature
        require(
            verifyMultisigSignature(msg.sender, multisigHash, digest, signature),
            "Invalid multisig signature"
        );

        // Check spending limit
        require(
            amount <= multisigSpendingLimits[multisigHash],
            "Amount exceeds limit"
        );

        // Execute transaction
        (bool success,) = to.call{value: amount}("");
        require(success, "Transaction failed");

        emit TransactionExecuted(multisigHash, to, amount, digest);
    }
}
```

### Performance Optimization

The key manager provides two signature verification approaches:

```solidity
// When you know the specific key hash (O(1) - most efficient)
bool success = keyManager.verifySignatureWithKey(
    userAddress,
    expectedKeyHash,
    digest,
    signature
);

// When you don't know which key was used (O(n) - loops through all keys)
(bool success, bytes32 usedKeyHash) = keyManager.verifySignatureWithAnyKey(
    userAddress,
    digest,
    signature
);

// Example: Using targeted verification in a protocol
contract MyProtocol {
    mapping(address => bytes32) public preferredKeys;

    function processSignedMessage(
        address user,
        bytes32 digest,
        bytes calldata signature
    ) external {
        bytes32 expectedKey = preferredKeys[user];

        if (expectedKey != bytes32(0)) {
            // Try the preferred key first (O(1))
            if (keyManager.verifySignatureWithKey(user, expectedKey, digest, signature)) {
                // Process with preferred key
                return;
            }
        }

        // Fall back to checking all keys (O(n))
        (bool success, bytes32 usedKey) = keyManager.verifySignatureWithAnyKey(
            user,
            digest,
            signature
        );

        if (success) {
            // Update preferred key for next time
            preferredKeys[user] = usedKey;
            // Process message
        }
    }
}
```

## Testing

The system includes comprehensive tests demonstrating all functionality:

```bash
# Run all tests
forge test

# Run specific test file
forge test --match-path test/GenericKeyManager.t.sol

# Run with gas reporting
forge test --gas-report

# Run fuzz tests
forge test --fuzz-runs 10000
```

Key test categories:

- **Unit Tests**: Core functionality of each component
- **Integration Tests**: Cross-component interactions
- **Multisig Tests**: Comprehensive M-of-N signature verification, registration, and removal
- **Fuzz Tests**: Property-based testing with random inputs
- **Protocol Tests**: Specific protocol adapter testing

## Contributing

Emissary is intended to be a reusable primitive and contributions are welcome. See the latest guidelines in [CONTRIBUTING.md](CONTRIBUTING.md), or open an issue!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
