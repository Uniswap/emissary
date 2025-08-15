// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from 'forge-std/Test.sol';

import {ResetPeriod} from 'lib/the-compact/src/types/ResetPeriod.sol';
import {GenericKeyManager, MultisigConfig, MultisigSignature} from 'src/GenericKeyManager.sol';
import {Key, KeyLib, KeyType} from 'src/KeyLib.sol';

contract MultisigBitmapUpdateTest is Test {
    GenericKeyManager keyManager;

    address owner;
    uint256 ownerPk;

    uint256 pkA = 0xA11;
    uint256 pkB = 0xB22;
    uint256 pkC = 0xC33;
    uint256 pkD = 0xD44;

    address addrA;
    address addrB;
    address addrC;
    address addrD;

    bytes32 digest;

    function setUp() public {
        keyManager = new GenericKeyManager();
        ownerPk = 0x777;
        owner = vm.addr(ownerPk);

        addrA = vm.addr(pkA);
        addrB = vm.addr(pkB);
        addrC = vm.addr(pkC);
        addrD = vm.addr(pkD);

        digest = keccak256('bitmap-update');
    }

    function _sig(bytes32 _digest, uint256 _pk) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, _digest);
        return abi.encodePacked(r, s, v);
    }

    function _register(address a, address k) internal returns (bytes32) {
        vm.prank(a);
        return keyManager.registerKey(KeyType.Secp256k1, abi.encode(k), ResetPeriod.OneDay);
    }

    function _registerMultisig(address a, uint16[] memory signerIdx, uint8 threshold) internal returns (bytes32) {
        vm.prank(a);
        return keyManager.registerMultisig(threshold, signerIdx, ResetPeriod.OneDay);
    }

    function _scheduleAndRemoveKey(address a, bytes32 keyHash) internal {
        vm.prank(a);
        keyManager.scheduleKeyRemoval(a, keyHash);
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(a);
        keyManager.removeKey(a, keyHash);
    }

    // Case: removing a non-signer causes the last key (which IS a signer) to move; bitmap should update
    function test_UpdateBitmap_WhenLastSignerMoves_OnRemovalOfNonSigner() public {
        // Order: [A, B, C, D]; make D a signer, remove A -> D moves to index 0
        bytes32 hA = _register(owner, addrA); // idx 0
        bytes32 hB = _register(owner, addrB); // idx 1
        bytes32 hC = _register(owner, addrC); // idx 2
        bytes32 hD = _register(owner, addrD); // idx 3 (last)

        uint16[] memory signers = new uint16[](1);
        signers[0] = 3; // D
        bytes32 ms = _registerMultisig(owner, signers, 1);

        // Sanity: signer bit 3 set
        MultisigConfig memory beforeCfg = keyManager.getMultisig(owner, ms);
        assertTrue((beforeCfg.signerBitmap & (1 << 3)) != 0);
        assertTrue((beforeCfg.signerBitmap & (1 << 0)) == 0);

        // Remove A (non-signer). This moves D from 3 -> 0 and should update bitmap accordingly
        _scheduleAndRemoveKey(owner, hA);

        MultisigConfig memory afterCfg = keyManager.getMultisig(owner, ms);
        assertTrue((afterCfg.signerBitmap & (1 << 0)) != 0, 'bit for moved signer not set');
        assertTrue((afterCfg.signerBitmap & (1 << 3)) == 0, 'old bit still set');

        // Verify signature with D at its NEW index 0 works; old index 3 should not
        uint16[] memory part = new uint16[](1);
        bytes[] memory sigs = new bytes[](1);

        // old index 3 should fail
        part[0] = 3;
        sigs[0] = _sig(digest, pkD);
        MultisigSignature memory sigOld =
            MultisigSignature({multisigHash: ms, participantIndices: part, signatures: sigs});
        assertFalse(keyManager.verifyMultisigSignature(owner, ms, digest, sigOld));

        // new index 0 should pass
        part[0] = 0;
        sigs[0] = _sig(digest, pkD);
        MultisigSignature memory sigNew =
            MultisigSignature({multisigHash: ms, participantIndices: part, signatures: sigs});
        assertTrue(keyManager.verifyMultisigSignature(owner, ms, digest, sigNew));
    }

    // Case: moved key appears in multiple multisigs; all should update
    function test_UpdateBitmap_ForMultipleMultisigs() public {
        // [A, B, C, D]; D is signer in two multisigs; remove A -> D moves 3 -> 0
        bytes32 hA = _register(owner, addrA);
        _register(owner, addrB);
        _register(owner, addrC);
        _register(owner, addrD);

        uint16[] memory s1 = new uint16[](1);
        s1[0] = 3; // D only
        bytes32 ms1 = _registerMultisig(owner, s1, 1);

        // Second multisig is different: includes D and B (bitmap differs), threshold 1
        uint16[] memory s2 = new uint16[](2);
        s2[0] = 3; // D
        s2[1] = 1; // B
        bytes32 ms2 = _registerMultisig(owner, s2, 1);

        _scheduleAndRemoveKey(owner, hA);

        MultisigConfig memory cfg1 = keyManager.getMultisig(owner, ms1);
        MultisigConfig memory cfg2 = keyManager.getMultisig(owner, ms2);
        assertTrue((cfg1.signerBitmap & (1 << 0)) != 0);
        assertTrue((cfg2.signerBitmap & (1 << 0)) != 0);
        assertTrue((cfg1.signerBitmap & (1 << 3)) == 0);
        assertTrue((cfg2.signerBitmap & (1 << 3)) == 0);
    }

    // Case: removing a non-signer moves a non-signer; multisig bitmap should remain unchanged
    function test_NoBitmapChange_WhenMovedKeyNotASigner() public {
        // [A, B, C, D]; B is signer; remove A -> D moves 3 -> 0; bitmap should still only have bit 1
        bytes32 hA = _register(owner, addrA);
        _register(owner, addrB);
        _register(owner, addrC);
        _register(owner, addrD);

        uint16[] memory s = new uint16[](1);
        s[0] = 1; // B signer
        bytes32 ms = _registerMultisig(owner, s, 1);

        MultisigConfig memory beforeCfg = keyManager.getMultisig(owner, ms);
        assertTrue((beforeCfg.signerBitmap & (1 << 1)) != 0);
        assertTrue((beforeCfg.signerBitmap & (1 << 3)) == 0);
        assertTrue((beforeCfg.signerBitmap & (1 << 0)) == 0);

        _scheduleAndRemoveKey(owner, hA);

        MultisigConfig memory afterCfg = keyManager.getMultisig(owner, ms);
        assertTrue((afterCfg.signerBitmap & (1 << 1)) != 0);
        assertTrue((afterCfg.signerBitmap & (1 << 3)) == 0);
        assertTrue((afterCfg.signerBitmap & (1 << 0)) == 0);
    }
}
