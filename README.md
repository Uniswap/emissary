## Generalized Key Management System

[![CI Status](../../actions/workflows/test.yaml/badge.svg)](../../actions)

This repository provides a composable foundation for key management across different protocols. It was originally designed to implement the Emissary actor for The Compact v1, but has been generalized to support multiple protocols.

#### Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
- [Usage](#usage)
- [Examples](#examples)
- [Testing](#testing)
- [Contributing](#contributing)

## Overview

The system consists of several composable components that can be used independently or together:

1. **GenericKeyManager**: Core key management functionality (registration, removal, timelocks)
2. **BaseKeyVerifier**: Generic signature verification with protocol support
3. **KeyManagerEmissary**: Compact-specific adapter implementing IEmissary
4. **ISignatureVerifier**: Generic interface for signature verification

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

### BaseKeyVerifier

Extends GenericKeyManager with protocol-aware signature verification:

- **Protocol Support**: Multi-protocol signature verification
- **Context Validation**: Expiration, nonce, and custom protocol data
- **Compatibility Filtering**: Get keys compatible with specific protocols
- **Generic Interface**: Implements ISignatureVerifier for interoperability

### KeyManagerEmissary

A Compact-specific adapter that implements The Compact's IEmissary interface:

- **Compact Integration**: Implements IEmissary for The Compact v1
- **Reset Period Compatibility**: Validates keys against lock tag requirements
- **Legacy Support**: Maintains compatibility with original interface

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
// Deploy for The Compact
KeyManagerEmissary emissary = new KeyManagerEmissary();

// Register a key for a sponsor
bytes32 keyHash = emissary.registerKey(
    KeyType.Secp256k1,
    abi.encode(sponsorAddress),
    ResetPeriod.OneDay
);

// Verify claim (implements IEmissary)
bytes4 selector = emissary.verifyClaim(
    sponsor,
    digest,
    claimHash,
    signature,
    lockTag
);
```

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
- **Fuzz Tests**: Property-based testing with random inputs
- **Protocol Tests**: Specific protocol adapter testing

## Key Features

### Security

- **Timelock Protection**: Configurable delays for key removal
- **Access Control**: Customizable authorization patterns
- **Signature Verification**: Multi-algorithm support (Secp256k1, P256, WebAuthn)
- **Replay Protection**: Nonce and expiration support

### Composability

- **Protocol Agnostic**: Generic foundation for any protocol
- **Modular Design**: Use components independently or together
- **Extensible**: Easy to add new protocols and key types
- **Interoperable**: Standard interfaces for cross-protocol use

### Gas Efficiency

- **Optimized Storage**: Efficient key storage and enumeration
- **Assembly Usage**: Critical paths optimized with inline assembly
- **Batch Operations**: Support for multiple key operations
- **Minimal Proxy**: Deployable as minimal proxy for gas savings
- **Targeted Verification**: Use `verifySignatureWithKey` for O(1) verification when key hash is known

## Contributing

If you want to contribute to this project, please check [CONTRIBUTING.md](CONTRIBUTING.md) first.

### Adding New Protocols

1. Inherit from `BaseKeyVerifier`
2. Override `_isProtocolSupported` to add your protocol
3. Override `_validateContext` for protocol-specific validation
4. Implement your protocol's interface
5. Add comprehensive tests

### Adding New Key Types

1. Add your key type to the `KeyType` enum in `KeyLib.sol`
2. Implement verification logic in `KeyLib.verify`
3. Add validation logic in `KeyLib.isValidKey`
4. Update tests to cover the new key type

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
