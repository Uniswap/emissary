// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from 'forge-std/Test.sol';

import {ResetPeriod} from 'the-compact/types/ResetPeriod.sol';

import {BaseKeyVerifier} from 'src/BaseKeyVerifier.sol';
import {GenericKeyManager, MultisigConfig, MultisigSignature} from 'src/GenericKeyManager.sol';
import {Key, KeyLib, KeyType} from 'src/KeyLib.sol';
import {ISignatureVerifier} from 'src/interfaces/ISignatureVerifier.sol';
import {VerificationContext} from 'src/types/VerificationContext.sol';

contract GenericKeyManagerTest is Test {
    using KeyLib for Key;

    GenericKeyManager keyManager;
    BaseKeyVerifier keyVerifier;

    address alice;
    address bob;
    address charlie;
    uint256 alicePrivateKey;
    uint256 bobPrivateKey;
    uint256 charliePrivateKey;

    // Test keys for different types
    Key secp256k1Key;
    Key p256Key;
    Key webauthnKey;

    bytes32 testDigest;
    bytes testSignature;

    function setUp() public {
        keyManager = new GenericKeyManager();
        keyVerifier = new BaseKeyVerifier(keccak256('BaseKeyVerifier'));

        // Create test addresses
        alicePrivateKey = 0xa11ce;
        bobPrivateKey = 0xb0b;
        charliePrivateKey = 0xcc;
        alice = vm.addr(alicePrivateKey);
        bob = vm.addr(bobPrivateKey);
        charlie = vm.addr(charliePrivateKey);

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
        testDigest = keccak256(abi.encodePacked('test message'));
        testSignature = generateSecp256k1Signature(testDigest, alicePrivateKey);

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

    function test_RegisterKey_WithAccountParam_Authorized() public {
        vm.prank(alice);
        bytes32 keyHash = keyManager.registerKey(alice, KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);
        assertTrue(keyManager.isKeyRegistered(alice, keyHash));
    }

    function test_RegisterKey_WithAccountParam_Unauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.UnauthorizedKeyManagement.selector, bob, alice));
        vm.prank(bob);
        keyManager.registerKey(alice, KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);
    }

    function test_ScheduleKeyRemoval_WithAccountParam_Authorized() public {
        vm.prank(alice);
        bytes32 h = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);
        vm.warp(100);
        vm.prank(alice);
        uint256 t = keyManager.scheduleKeyRemoval(alice, h);
        assertGt(t, 100);
    }

    function test_ScheduleKeyRemoval_WithAccountParam_Unauthorized() public {
        vm.prank(alice);
        bytes32 h = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.UnauthorizedKeyManagement.selector, bob, alice));
        vm.prank(bob);
        keyManager.scheduleKeyRemoval(alice, h);
    }

    function test_RemoveKey_WithAccountParam_Authorized() public {
        vm.prank(alice);
        bytes32 h = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleKeyRemoval(alice, h);
        vm.warp(removableAt + 1);
        vm.prank(alice);
        keyManager.removeKey(alice, h);
        assertFalse(keyManager.isKeyRegistered(alice, h));
    }

    function test_revert_RemoveKey_KeyNotRegistered() public {
        bytes32 keyHash = keccak256('notRegistered');
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.KeyNotRegistered.selector, alice, keyHash));
        vm.prank(alice);
        keyManager.removeKey(alice, keyHash);
    }

    function test_canRemoveKey_NotScheduled_ReturnsFalse() public {
        vm.prank(alice);
        bytes32 h = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneSecond);

        bool canRemove = keyManager.canRemoveKey(alice, h);
        assertFalse(canRemove);
    }

    function test_canRemoveKey_ScheduledBeforeTimelock_ReturnsFalse() public {
        vm.prank(alice);
        bytes32 h = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.TenMinutes);

        vm.warp(100);
        vm.prank(alice);
        keyManager.scheduleKeyRemoval(alice, h);

        bool canRemove = keyManager.canRemoveKey(alice, h);
        assertFalse(canRemove);
    }

    function test_canRemoveKey_ScheduledAfterTimelock_NoMultisig_ReturnsTrue() public {
        vm.prank(alice);
        bytes32 h = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneSecond);

        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleKeyRemoval(alice, h);

        vm.warp(removableAt + 1);
        bool canRemove = keyManager.canRemoveKey(alice, h);
        assertTrue(canRemove);
    }

    function test_canRemoveKey_ScheduledAfterTimelock_UsedInMultisig_ReturnsFalse() public {
        // Register two keys so we can build a multisig including the first key
        vm.startPrank(alice);
        bytes32 h1 = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneSecond);
        keyManager.registerKey(KeyType.Secp256k1, abi.encode(bob), ResetPeriod.OneSecond);
        vm.stopPrank();

        // Create a 1-of-2 multisig that includes index 0 (h1)
        uint16[] memory signerIndices = new uint16[](1);
        signerIndices[0] = 0; // key at index 0 is h1
        vm.prank(alice);
        keyManager.registerMultisig(1, signerIndices, ResetPeriod.OneSecond);

        // Schedule removal of h1 and advance time beyond timelock
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleKeyRemoval(alice, h1);
        vm.warp(removableAt + 1);

        // Because h1 is used in a multisig, canRemoveKey should be false
        bool canRemove = keyManager.canRemoveKey(alice, h1);
        assertFalse(canRemove);
    }

    function test_RemoveKey_WithAccountParam_Unauthorized() public {
        vm.prank(alice);
        bytes32 h = keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleKeyRemoval(alice, h);
        vm.warp(removableAt + 1);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.UnauthorizedKeyManagement.selector, bob, alice));
        vm.prank(bob);
        keyManager.removeKey(alice, h);
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

    function test_KeyManager_ComputeKeyHash() public view {
        bytes32 computedHash = keyManager.computeKeyHash(secp256k1Key);
        bytes32 expectedHash = secp256k1Key.hash();
        assertEq(computedHash, expectedHash);
    }

    function test_KeyManager_ValidateKey() public view {
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

    // ================= MULTISIG TESTS =================

    function _setupMultisigKeys() internal {
        // Register keys for Alice to use in multisig tests
        vm.startPrank(alice);
        keyManager.registerKey(KeyType.Secp256k1, abi.encode(alice), ResetPeriod.OneDay);
        keyManager.registerKey(KeyType.Secp256k1, abi.encode(bob), ResetPeriod.OneDay);
        keyManager.registerKey(KeyType.Secp256k1, abi.encode(charlie), ResetPeriod.OneDay);
        vm.stopPrank();
    }

    function test_RegisterMultisig_2of3() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](3);
        signerIndices[0] = 0; // Alice's key
        signerIndices[1] = 1; // Bob's key
        signerIndices[2] = 2; // Charlie's key

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(
            2, // threshold
            signerIndices,
            ResetPeriod.SevenDaysAndOneHour
        );

        // Verify multisig was registered
        assertTrue(keyManager.isMultisigRegistered(alice, multisigHash));

        // Verify multisig details
        MultisigConfig memory config = keyManager.getMultisig(alice, multisigHash);
        assertEq(config.threshold, 2);
        assertEq(config.signerCount, 3);
        assertEq(uint8(config.resetPeriod), uint8(ResetPeriod.SevenDaysAndOneHour));

        // Verify bitmap is correct (bits 0, 1, 2 should be set)
        assertEq(config.signerBitmap & (1 << 0), 1 << 0); // Alice
        assertEq(config.signerBitmap & (1 << 1), 1 << 1); // Bob
        assertEq(config.signerBitmap & (1 << 2), 1 << 2); // Charlie

        // Verify count
        assertEq(keyManager.getMultisigCount(alice), 1);
    }

    function test_RegisterMultisig_3of5() public {
        _setupMultisigKeys();

        // Add two more keys for testing
        vm.prank(alice);
        keyManager.registerKey(KeyType.Secp256k1, abi.encode(makeAddr('user4')), ResetPeriod.OneDay);

        vm.prank(alice);
        keyManager.registerKey(KeyType.Secp256k1, abi.encode(makeAddr('user5')), ResetPeriod.OneDay);

        uint16[] memory signerIndices = new uint16[](5);
        signerIndices[0] = 0;
        signerIndices[1] = 1;
        signerIndices[2] = 2;
        signerIndices[3] = 3;
        signerIndices[4] = 4;

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(
            3, // threshold
            signerIndices,
            ResetPeriod.ThirtyDays
        );

        MultisigConfig memory config = keyManager.getMultisig(alice, multisigHash);
        assertEq(config.threshold, 3);
        assertEq(config.signerCount, 5);

        // Verify all bits are set correctly
        for (uint256 i = 0; i < 5; i++) {
            assertEq(config.signerBitmap & (1 << i), 1 << i);
        }
    }

    function test_RegisterMultisig_InvalidThreshold() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](3);
        signerIndices[0] = 0;
        signerIndices[1] = 1;
        signerIndices[2] = 2;

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.InvalidMultisigConfig.selector, 'Invalid threshold'));
        keyManager.registerMultisig(0, signerIndices, ResetPeriod.SevenDaysAndOneHour); // threshold 0

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.InvalidMultisigConfig.selector, 'Invalid threshold'));
        keyManager.registerMultisig(4, signerIndices, ResetPeriod.SevenDaysAndOneHour); // threshold > signer count
    }

    function test_RegisterMultisig_DuplicateSignerIndex() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](3);
        signerIndices[0] = 0;
        signerIndices[1] = 1;
        signerIndices[2] = 1; // Duplicate

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(GenericKeyManager.InvalidMultisigConfig.selector, 'Duplicate signer index')
        );
        keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);
    }

    function test_RegisterMultisig_OutOfBoundsIndex() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](2);
        signerIndices[0] = 0;
        signerIndices[1] = 10; // Out of bounds (only have 3 keys)

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(GenericKeyManager.InvalidMultisigConfig.selector, 'Signer index out of bounds')
        );
        keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);
    }

    function test_VerifyMultisigSignature_2of3_Success() public {
        _setupMultisigKeys();
        bytes32 multisigTestDigest = keccak256('test multisig message');

        // Register a 2-of-3 multisig
        uint16[] memory signerIndices = new uint16[](3);
        signerIndices[0] = 0; // Alice
        signerIndices[1] = 1; // Bob
        signerIndices[2] = 2; // Charlie

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);

        // Create signatures from Alice and Bob (meets threshold)
        bytes memory aliceSignature = generateSecp256k1Signature(multisigTestDigest, alicePrivateKey);
        bytes memory bobSignature = generateSecp256k1Signature(multisigTestDigest, bobPrivateKey);

        uint16[] memory participantIndices = new uint16[](2);
        participantIndices[0] = 0; // Alice's key index
        participantIndices[1] = 1; // Bob's key index

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = aliceSignature;
        signatures[1] = bobSignature;

        MultisigSignature memory multisigSig = MultisigSignature({
            multisigHash: multisigHash,
            participantIndices: participantIndices,
            signatures: signatures
        });

        // Verify the multisig signature
        bool success = keyManager.verifyMultisigSignature(alice, multisigHash, multisigTestDigest, multisigSig);
        assertTrue(success);
    }

    function test_VerifyMultisigSignature_2of3_InsufficientSignatures() public {
        _setupMultisigKeys();
        bytes32 multisigTestDigest = keccak256('test multisig message');

        // Register a 2-of-3 multisig
        uint16[] memory signerIndices = new uint16[](3);
        signerIndices[0] = 0;
        signerIndices[1] = 1;
        signerIndices[2] = 2;

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);

        // Create signature from only Alice (doesn't meet threshold)
        bytes memory aliceSignature = generateSecp256k1Signature(multisigTestDigest, alicePrivateKey);

        uint16[] memory participantIndices = new uint16[](1);
        participantIndices[0] = 0;

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = aliceSignature;

        MultisigSignature memory multisigSig = MultisigSignature({
            multisigHash: multisigHash,
            participantIndices: participantIndices,
            signatures: signatures
        });

        // Verify should fail due to insufficient signatures
        bool success = keyManager.verifyMultisigSignature(alice, multisigHash, multisigTestDigest, multisigSig);
        assertFalse(success);
    }

    function test_VerifyMultisigSignature_InvalidSigner() public {
        _setupMultisigKeys();
        bytes32 multisigTestDigest = keccak256('test multisig message');

        // Register a 2-of-3 multisig with only indices 0, 1, 2
        uint16[] memory signerIndices = new uint16[](3);
        signerIndices[0] = 0;
        signerIndices[1] = 1;
        signerIndices[2] = 2;

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);

        // Add a 4th key that's not part of the multisig
        vm.prank(alice);
        keyManager.registerKey(KeyType.Secp256k1, abi.encode(makeAddr('user4')), ResetPeriod.OneDay);

        // Try to use the 4th key (index 3) which is not in the multisig
        bytes memory aliceSignature = generateSecp256k1Signature(multisigTestDigest, alicePrivateKey);
        bytes memory invalidSignature = generateSecp256k1Signature(multisigTestDigest, uint256(keccak256('user4')));

        uint16[] memory participantIndices = new uint16[](2);
        participantIndices[0] = 0; // Valid signer
        participantIndices[1] = 3; // Invalid signer (not in bitmap)

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = aliceSignature;
        signatures[1] = invalidSignature;

        MultisigSignature memory multisigSig = MultisigSignature({
            multisigHash: multisigHash,
            participantIndices: participantIndices,
            signatures: signatures
        });

        // Should still succeed with just Alice's valid signature if we add another valid one
        participantIndices[1] = 1; // Change to Bob (valid signer)
        signatures[1] = generateSecp256k1Signature(multisigTestDigest, bobPrivateKey);

        bool success = keyManager.verifyMultisigSignature(alice, multisigHash, multisigTestDigest, multisigSig);
        assertTrue(success);
    }

    function test_VerifyMultisigSignature_WrongMultisigHash() public {
        _setupMultisigKeys();
        bytes32 multisigTestDigest = keccak256('test multisig message');

        uint16[] memory signerIndices = new uint16[](2);
        signerIndices[0] = 0;
        signerIndices[1] = 1;

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);

        bytes memory aliceSignature = generateSecp256k1Signature(multisigTestDigest, alicePrivateKey);
        bytes memory bobSignature = generateSecp256k1Signature(multisigTestDigest, bobPrivateKey);

        uint16[] memory participantIndices = new uint16[](2);
        participantIndices[0] = 0;
        participantIndices[1] = 1;

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = aliceSignature;
        signatures[1] = bobSignature;

        // Use wrong multisig hash in signature
        MultisigSignature memory multisigSig = MultisigSignature({
            multisigHash: keccak256('wrong hash'),
            participantIndices: participantIndices,
            signatures: signatures
        });

        bool success = keyManager.verifyMultisigSignature(alice, multisigHash, multisigTestDigest, multisigSig);
        assertFalse(success);
    }

    function test_ScheduleMultisigRemoval() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](2);
        signerIndices[0] = 0;
        signerIndices[1] = 1;

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);

        // Schedule removal
        vm.warp(1000);
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleMultisigRemoval(multisigHash);

        // Should be removable after reset period (7 days + 1 hour)
        assertEq(removableAt, 1000 + 7 days + 1 hours);

        // Check removal status
        (bool isScheduled, uint256 scheduledAt) = keyManager.getMultisigRemovalStatus(alice, multisigHash);
        assertTrue(isScheduled);
        assertEq(scheduledAt, removableAt);

        // Should not be removable yet
        assertFalse(keyManager.canRemoveMultisig(alice, multisigHash));
    }

    function test_RemoveMultisig() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](2);
        signerIndices[0] = 0;
        signerIndices[1] = 1;

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);

        // Schedule removal
        vm.warp(1000);
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleMultisigRemoval(multisigHash);

        // Try to remove before timelock expires
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.MultisigRemovalUnavailable.selector, removableAt));
        keyManager.removeMultisig(multisigHash);

        // Warp to after timelock
        vm.warp(removableAt + 1);

        // Should be removable now
        assertTrue(keyManager.canRemoveMultisig(alice, multisigHash));

        // Remove the multisig
        vm.prank(alice);
        keyManager.removeMultisig(multisigHash);

        // Verify multisig is removed
        assertFalse(keyManager.isMultisigRegistered(alice, multisigHash));
        assertEq(keyManager.getMultisigCount(alice), 0);
    }

    function test_RemoveMultisig_FromMiddleOfArray() public {
        _setupMultisigKeys();

        // Register multiple multisigs
        uint16[] memory signerIndices1 = new uint16[](2);
        signerIndices1[0] = 0;
        signerIndices1[1] = 1;

        uint16[] memory signerIndices2 = new uint16[](2);
        signerIndices2[0] = 1;
        signerIndices2[1] = 2;

        uint16[] memory signerIndices3 = new uint16[](2);
        signerIndices3[0] = 0;
        signerIndices3[1] = 2;

        vm.startPrank(alice);
        bytes32 multisigHash1 = keyManager.registerMultisig(2, signerIndices1, ResetPeriod.SevenDaysAndOneHour);
        bytes32 multisigHash2 = keyManager.registerMultisig(2, signerIndices2, ResetPeriod.SevenDaysAndOneHour);
        bytes32 multisigHash3 = keyManager.registerMultisig(2, signerIndices3, ResetPeriod.SevenDaysAndOneHour);
        vm.stopPrank();

        assertEq(keyManager.getMultisigCount(alice), 3);

        // Schedule and remove the middle multisig
        vm.warp(1000);
        vm.prank(alice);
        uint256 removableAt = keyManager.scheduleMultisigRemoval(multisigHash2);

        vm.warp(removableAt + 1);
        vm.prank(alice);
        keyManager.removeMultisig(multisigHash2);

        // Verify array was compacted correctly
        assertEq(keyManager.getMultisigCount(alice), 2);
        assertTrue(keyManager.isMultisigRegistered(alice, multisigHash1));
        assertFalse(keyManager.isMultisigRegistered(alice, multisigHash2));
        assertTrue(keyManager.isMultisigRegistered(alice, multisigHash3));
    }

    function test_MultisigQueryFunctions() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](3);
        signerIndices[0] = 0;
        signerIndices[1] = 1;
        signerIndices[2] = 2;

        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(2, signerIndices, ResetPeriod.SevenDaysAndOneHour);
        vm.snapshotGasLastCall('registerMultisig');

        // Test getMultisigHashes
        bytes32[] memory hashes = keyManager.getMultisigHashes(alice);
        assertEq(hashes.length, 1);
        assertEq(hashes[0], multisigHash);

        // Test getMultisig
        MultisigConfig memory config = keyManager.getMultisig(alice, multisigHash);
        assertEq(config.threshold, 2);
        assertEq(config.signerCount, 3);
        assertEq(config.index, 1); // First multisig gets index 1

        // Test isMultisigRegistered
        assertTrue(keyManager.isMultisigRegistered(alice, multisigHash));
        assertFalse(keyManager.isMultisigRegistered(alice, keccak256('nonexistent')));

        // Test getMultisigCount
        assertEq(keyManager.getMultisigCount(alice), 1);
    }

    function test_UnauthorizedMultisigManagement() public {
        _setupMultisigKeys();

        uint16[] memory signerIndices = new uint16[](2);
        signerIndices[0] = 0;
        signerIndices[1] = 1;

        // Bob tries to register a multisig for Alice
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(GenericKeyManager.UnauthorizedKeyManagement.selector, bob, alice));
        keyManager.registerMultisig(alice, 2, signerIndices, ResetPeriod.SevenDaysAndOneHour);
    }

    function testFuzz_RegisterAndVerifyMultisig(uint8 threshold, uint8 signerCount, uint8 resetPeriodRaw) public {
        // Bound inputs to valid ranges
        threshold = uint8(bound(threshold, 1, 10));
        signerCount = uint8(bound(signerCount, threshold, 10));
        ResetPeriod resetPeriod = ResetPeriod(bound(resetPeriodRaw, 0, 7));

        // Register enough keys
        for (uint256 i = keyManager.getKeyCount(alice); i < signerCount; i++) {
            vm.prank(alice);
            keyManager.registerKey(KeyType.Secp256k1, abi.encode(vm.addr(i + 100)), ResetPeriod.OneDay);
        }

        // Create signer indices
        uint16[] memory signerIndices = new uint16[](signerCount);
        for (uint256 i = 0; i < signerCount; i++) {
            signerIndices[i] = uint16(i);
        }

        // Register multisig
        vm.prank(alice);
        bytes32 multisigHash = keyManager.registerMultisig(threshold, signerIndices, resetPeriod);

        // Verify registration
        assertTrue(keyManager.isMultisigRegistered(alice, multisigHash));

        MultisigConfig memory config = keyManager.getMultisig(alice, multisigHash);
        assertEq(config.threshold, threshold);
        assertEq(config.signerCount, signerCount);
    }
}
