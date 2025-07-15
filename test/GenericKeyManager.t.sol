// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from 'forge-std/Test.sol';

import {ResetPeriod} from 'lib/the-compact/src/types/ResetPeriod.sol';
import {BaseKeyVerifier} from 'src/BaseKeyVerifier.sol';
import {GenericKeyManager} from 'src/GenericKeyManager.sol';

import {Key, KeyLib, KeyType} from 'src/KeyLib.sol';
import {ISignatureVerifier} from 'src/interfaces/ISignatureVerifier.sol';
import {VerificationContext} from 'src/types/VerificationContext.sol';

contract GenericKeyManagerTest is Test {
    using KeyLib for Key;

    GenericKeyManager keyManager;
    BaseKeyVerifier keyVerifier;

    address alice;
    address bob;
    uint256 alicePrivateKey;
    uint256 bobPrivateKey;

    // Test keys for different types
    Key secp256k1Key;
    Key p256Key;
    Key webauthnKey;

    bytes32 testDigest;
    bytes testSignature;

    function setUp() public {
        keyManager = new GenericKeyManager();
        keyVerifier = new BaseKeyVerifier();

        // Create test addresses
        alicePrivateKey = 0xa11ce;
        bobPrivateKey = 0xb0b;
        alice = vm.addr(alicePrivateKey);
        bob = vm.addr(bobPrivateKey);

        // Create test digest
        testDigest = keccak256('test message');

        // Setup test keys
        setupTestKeys();
    }

    function setupTestKeys() internal {
        // Secp256k1 key (Alice's address)
        secp256k1Key = Key({
            keyType: KeyType.Secp256k1,
            resetPeriod: ResetPeriod.OneDay,
            removalTimestamp: 0,
            index: 0,
            publicKey: abi.encode(alice)
        });

        // P256 key (dummy coordinates)
        p256Key = Key({
            keyType: KeyType.P256,
            resetPeriod: ResetPeriod.OneHourAndFiveMinutes,
            removalTimestamp: 0,
            index: 0,
            publicKey: abi.encode(
                bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef),
                bytes32(0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321)
            )
        });

        // WebAuthn key (dummy coordinates)
        webauthnKey = Key({
            keyType: KeyType.WebAuthnP256,
            resetPeriod: ResetPeriod.TenMinutes,
            removalTimestamp: 0,
            index: 0,
            publicKey: abi.encode(
                bytes32(0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890),
                bytes32(0x0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba)
            )
        });

        // Generate test signature for secp256k1
        testSignature = generateSecp256k1Signature(testDigest, alicePrivateKey);
    }

    function generateSecp256k1Signature(bytes32 digest, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_KeyManager_RegisterKey() public {
        vm.prank(alice);
        bytes32 keyHash = keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Verify key was registered
        assertTrue(keyManager.isKeyRegistered(alice, keyHash));

        // Verify key details
        Key memory retrievedKey = keyManager.getKey(alice, keyHash);
        assertEq(uint8(retrievedKey.keyType), uint8(secp256k1Key.keyType));
        assertEq(retrievedKey.publicKey, secp256k1Key.publicKey);
        assertEq(uint8(retrievedKey.resetPeriod), uint8(secp256k1Key.resetPeriod));
        assertEq(retrievedKey.index, 1); // First key gets index 1

        // Verify key count
        assertEq(keyManager.getKeyCount(alice), 1);
    }

    function test_KeyManager_RegisterMultipleKeys() public {
        vm.startPrank(alice);

        // Register multiple keys
        bytes32 keyHash1 =
            keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        bytes32 keyHash2 = keyManager.registerKey(p256Key.keyType, p256Key.publicKey, p256Key.resetPeriod);

        bytes32 keyHash3 = keyManager.registerKey(webauthnKey.keyType, webauthnKey.publicKey, webauthnKey.resetPeriod);

        vm.stopPrank();

        // Verify all keys are registered
        assertTrue(keyManager.isKeyRegistered(alice, keyHash1));
        assertTrue(keyManager.isKeyRegistered(alice, keyHash2));
        assertTrue(keyManager.isKeyRegistered(alice, keyHash3));

        // Verify key count
        assertEq(keyManager.getKeyCount(alice), 3);

        // Verify key hashes array
        bytes32[] memory keyHashes = keyManager.getKeyHashes(alice);
        assertEq(keyHashes.length, 3);
        assertEq(keyHashes[0], keyHash1);
        assertEq(keyHashes[1], keyHash2);
        assertEq(keyHashes[2], keyHash3);
    }

    function test_KeyManager_CannotRegisterDuplicateKey() public {
        vm.prank(alice);
        keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Try to register the same key again
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(GenericKeyManager.KeyAlreadyRegistered.selector, alice, secp256k1Key.hash())
        );
        keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);
    }

    function test_KeyManager_ScheduleKeyRemoval() public {
        vm.prank(alice);
        bytes32 keyHash = keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Schedule removal
        vm.warp(1000);
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleKeyRemoval(keyHash);

        // Should be removable after reset period
        assertEq(removableAt, 1000 + 1 days);

        // Check removal status
        (bool isScheduled, uint256 scheduledAt) = keyManager.getKeyRemovalStatus(alice, keyHash);
        assertTrue(isScheduled);
        assertEq(scheduledAt, removableAt);

        // Should not be removable yet
        assertFalse(keyManager.canRemoveKey(alice, keyHash));
    }

    function test_KeyManager_RemoveKey() public {
        vm.prank(alice);
        bytes32 keyHash = keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Schedule removal
        vm.warp(1000);
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleKeyRemoval(keyHash);

        // Try to remove before timelock expires
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.KeyRemovalUnavailable.selector, removableAt));
        keyManager.removeKey(keyHash);

        // Warp to after timelock
        vm.warp(removableAt + 1);

        // Should be removable now
        assertTrue(keyManager.canRemoveKey(alice, keyHash));

        // Remove the key
        vm.prank(alice);
        keyManager.removeKey(keyHash);

        // Verify key is removed
        assertFalse(keyManager.isKeyRegistered(alice, keyHash));
        assertEq(keyManager.getKeyCount(alice), 0);
    }

    function test_KeyManager_SignatureVerification() public {
        vm.prank(alice);
        bytes32 keyHash = keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Test signature verification
        (bool success, bytes32 usedKeyHash) = keyManager.verifySignatureWithAnyKey(alice, testDigest, testSignature);
        assertTrue(success);
        assertEq(usedKeyHash, keyHash);

        // Test with invalid signature
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        (bool failSuccess,) = keyManager.verifySignatureWithAnyKey(alice, testDigest, invalidSignature);
        assertFalse(failSuccess);
    }

    function test_KeyManager_VerifySignatureWithSpecificKey() public {
        // Register a key for Alice
        vm.prank(alice);
        bytes32 keyHash = keyManager.registerKey(alice, KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);

        // Generate a test signature
        bytes32 testDigest = keccak256(abi.encodePacked('test message'));
        bytes memory testSignature = generateSecp256k1Signature(testDigest, alicePrivateKey);

        // Test verification with the correct key hash
        bool success = keyManager.verifySignatureWithKey(alice, keyHash, testDigest, testSignature);
        assertTrue(success);

        // Test verification with non-existent key hash
        bytes32 nonExistentKeyHash = keccak256(abi.encode('non-existent'));
        bool failSuccess = keyManager.verifySignatureWithKey(alice, nonExistentKeyHash, testDigest, testSignature);
        assertFalse(failSuccess);

        // Test verification with invalid signature
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        bool invalidSuccess = keyManager.verifySignatureWithKey(alice, keyHash, testDigest, invalidSignature);
        assertFalse(invalidSuccess);

        // Register a second key for Alice
        vm.prank(alice);
        bytes32 keyHash2 = keyManager.registerKey(alice, KeyType.Secp256k1, abi.encode(bob), ResetPeriod.OneDay);

        // Test that signature made with first key doesn't work with second key
        bool wrongKeySuccess = keyManager.verifySignatureWithKey(alice, keyHash2, testDigest, testSignature);
        assertFalse(wrongKeySuccess);

        // Test that signature made with second key works with second key
        bytes memory testSignature2 = generateSecp256k1Signature(testDigest, bobPrivateKey);
        bool correctKeySuccess = keyManager.verifySignatureWithKey(alice, keyHash2, testDigest, testSignature2);
        assertTrue(correctKeySuccess);
    }

    function test_KeyManager_UnauthorizedKeyManagement() public {
        // Bob tries to register a key for Alice
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.UnauthorizedKeyManagement.selector, bob, alice));
        keyManager.registerKey(alice, secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);
    }

    function test_BaseKeyVerifier_SignatureVerification() public {
        // Register a key for Alice
        vm.prank(alice);
        keyVerifier.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Create basic context
        bytes memory context = keyVerifier.createBasicContext(keyVerifier.PROTOCOL_ID(), 0);

        // Test signature verification
        assertTrue(keyVerifier.canVerifySignature(alice, testDigest, testSignature, context));

        // Test with ISignatureVerifier interface
        bytes4 selector = keyVerifier.verifySignature(alice, testDigest, testSignature, context);
        assertEq(selector, ISignatureVerifier.verifySignature.selector);
    }

    function test_BaseKeyVerifier_ContextValidation() public {
        vm.prank(alice);
        keyVerifier.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Test with expired context
        vm.warp(2000);
        bytes memory expiredContext = keyVerifier.createBasicContext(keyVerifier.PROTOCOL_ID(), 1000);
        assertFalse(keyVerifier.canVerifySignature(alice, testDigest, testSignature, expiredContext));

        // Test with valid context
        bytes memory validContext = keyVerifier.createBasicContext(keyVerifier.PROTOCOL_ID(), 3000);
        assertTrue(keyVerifier.canVerifySignature(alice, testDigest, testSignature, validContext));
    }

    function test_BaseKeyVerifier_ProtocolSupport() public {
        vm.prank(alice);
        keyVerifier.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        // Test with unsupported protocol
        bytes32 unsupportedProtocol = keccak256('UnsupportedProtocol');
        bytes memory unsupportedContext = keyVerifier.createBasicContext(unsupportedProtocol, 0);
        assertFalse(keyVerifier.canVerifySignature(alice, testDigest, testSignature, unsupportedContext));
    }

    function test_BaseKeyVerifier_RegisterWithContext() public {
        bytes memory context = keyVerifier.createBasicContext(keyVerifier.PROTOCOL_ID(), 0);

        vm.prank(alice);
        bytes32 keyHash = keyVerifier.registerKeyWithContext(
            secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod, context
        );

        assertTrue(keyVerifier.isKeyRegistered(alice, keyHash));
    }

    function test_BaseKeyVerifier_GetCompatibleKeys() public {
        vm.startPrank(alice);

        // Register keys
        bytes32 keyHash1 =
            keyVerifier.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        bytes32 keyHash2 = keyVerifier.registerKey(p256Key.keyType, p256Key.publicKey, p256Key.resetPeriod);

        vm.stopPrank();

        // Get compatible keys
        bytes32[] memory compatibleKeys = keyVerifier.getCompatibleKeys(alice, keyVerifier.PROTOCOL_ID());
        assertEq(compatibleKeys.length, 2);

        // Order should match registration order
        assertEq(compatibleKeys[0], keyHash1);
        assertEq(compatibleKeys[1], keyHash2);
    }

    function test_KeyManager_ComputeKeyHash() public {
        bytes32 computedHash = keyManager.computeKeyHash(secp256k1Key);
        bytes32 expectedHash = secp256k1Key.hash();
        assertEq(computedHash, expectedHash);
    }

    function test_KeyManager_ValidateKey() public {
        assertTrue(keyManager.validateKey(secp256k1Key));

        // Test invalid key
        Key memory invalidKey = Key({
            keyType: KeyType.Secp256k1,
            resetPeriod: ResetPeriod.OneDay,
            removalTimestamp: 0,
            index: 0,
            publicKey: '' // Invalid empty public key
        });

        assertFalse(keyManager.validateKey(invalidKey));
    }

    function test_KeyManager_GetKeyResetPeriod() public {
        vm.prank(alice);
        bytes32 keyHash = keyManager.registerKey(secp256k1Key.keyType, secp256k1Key.publicKey, secp256k1Key.resetPeriod);

        ResetPeriod retrievedPeriod = keyManager.getKeyResetPeriod(alice, keyHash);
        assertEq(uint8(retrievedPeriod), uint8(secp256k1Key.resetPeriod));
    }

    function testFuzz_RegisterAndVerifyKeys(uint8 keyTypeRaw, uint8 resetPeriodRaw, uint256 privateKey) public {
        // Bound inputs
        vm.assume(privateKey != 0 && privateKey < type(uint240).max);
        KeyType keyType = KeyType(bound(keyTypeRaw, 0, 2));
        ResetPeriod resetPeriod = ResetPeriod(bound(resetPeriodRaw, 0, 7));

        // Only test Secp256k1 for now (other types need more complex setup)
        if (keyType != KeyType.Secp256k1) return;

        address user = vm.addr(privateKey);

        // Create key
        Key memory key = Key({
            keyType: keyType,
            resetPeriod: resetPeriod,
            removalTimestamp: 0,
            index: 0,
            publicKey: abi.encode(user)
        });

        // Register key
        vm.prank(user);
        bytes32 keyHash = keyManager.registerKey(key.keyType, key.publicKey, key.resetPeriod);

        // Verify registration
        assertTrue(keyManager.isKeyRegistered(user, keyHash));

        // Test signature verification
        bytes32 digest = keccak256(abi.encodePacked('test', block.timestamp));
        bytes memory signature = generateSecp256k1Signature(digest, privateKey);

        (bool success, bytes32 usedKeyHash) = keyManager.verifySignatureWithAnyKey(user, digest, signature);
        assertTrue(success);
        assertEq(usedKeyHash, keyHash);
    }
}
