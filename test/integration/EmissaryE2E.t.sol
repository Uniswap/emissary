// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Setup} from 'lib/the-compact/test/integration/Setup.sol';
import {P256VerifierEtcher} from 'test/helpers/P256VerifierEtcher.sol';

import {Key, KeyLib, KeyType} from 'src/KeyLib.sol';
import {KeyManagerEmissary} from 'src/KeyManagerEmissary.sol';

import {MockERC1271Wallet} from 'lib/solady/test/utils/mocks/MockERC1271Wallet.sol';
import {ITheCompact} from 'lib/the-compact/src/interfaces/ITheCompact.sol';
import {Claim} from 'lib/the-compact/src/types/Claims.sol';
import {Component} from 'lib/the-compact/src/types/Components.sol';
import {ResetPeriod} from 'lib/the-compact/src/types/ResetPeriod.sol';
import {Scope} from 'lib/the-compact/src/types/Scope.sol';
import {CreateClaimHashWithWitnessArgs} from 'lib/the-compact/test/integration/TestHelperStructs.sol';
import {P256} from 'solady/utils/P256.sol';
import {BaseKeyVerifier} from 'src/BaseKeyVerifier.sol';

contract EmissaryE2E is Setup, P256VerifierEtcher {
    using KeyLib for Key;

    KeyManagerEmissary private emissary;

    function setUp() public override {
        super.setUp();
        _etchRIPPrecompile(true);
        _etchVerifier(true);
        emissary = new KeyManagerEmissary();
    }

    function test_e2e_EmissaryVerifiesAfterEIP1271Upgrade() public {
        // Register allocator and deposit
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);
        }

        uint256 amount = 1e18;
        uint256 id = _makeDeposit(swapper, amount, lockTag);

        // Build claim hash with witness typestring
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = address(0x2222222222222222222222222222222222222222);
            args.sponsor = swapper;
            args.nonce = 0;
            args.expires = block.timestamp + 1000;
            args.id = id;
            args.amount = amount;
            args.witness = _createCompactWitness(1);
            claimHash = _createClaimHashWithWitness(args);
        }

        // Register key
        (address notSponsor, uint256 notSponsorKey) = makeAddrAndKey('emissary-after-1271');
        Key memory signerKey = KeyLib.fromAddress(notSponsor, ResetPeriod.TenMinutes);
        vm.prank(swapper);
        emissary.registerKey(signerKey.keyType, signerKey.publicKey, signerKey.resetPeriod);

        // Assign emissary to lockTag
        vm.prank(swapper);
        assertTrue(theCompact.assignEmissary(lockTag, address(emissary)));

        // Upgrade sponsor address to a smart account implementation (simulating EIP-7702)
        {
            MockERC1271Wallet temp = new MockERC1271Wallet(address(0)); // address(0) → reject all signatures
            bytes memory code = address(temp).code;
            vm.etch(swapper, code);
        }

        // Sign digest with emissary key (not the sponsor) so it must fall back to emissary
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(notSponsorKey, _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash));

        // Build claim and include allocator authorization
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = amount;
        claim.id = id;
        claim.witnessTypestring = 'uint256 witnessArgument';
        claim.witness = _createCompactWitness(1);
        claim.sponsorSignature = abi.encodePacked(r, s, v);
        {
            uint256 claimant = abi.decode(abi.encodePacked(bytes12(0), swapper), (uint256));
            Component[] memory claimComponents = new Component[](1);
            claimComponents[0] = Component({claimant: claimant, amount: amount});
            claim.claimants = claimComponents;
        }
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
            (bytes32 ar, bytes32 avs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(ar, avs);
        }

        // Should succeed via emissary fallback despite sponsor now being ERC1271.
        // This is because the claim was originally signed by the sponsor EOA which
        // is now an ERC1271-compatible smart account that rejects all signatures.
        // The claim is then verified by the emissary, which still considers the pk
        // to be a valid signer for the sponsor even though the 1271 implementation
        // explicitly rejects all signatures by specifying address(0) as the signer.
        vm.prank(address(0x2222222222222222222222222222222222222222));
        bytes32 returnedClaimHash = theCompact.claim(claim);
        assertEq(returnedClaimHash, claimHash);
    }

    function test_e2e_ClaimViaEmissaryFallback_CompatibleResetPeriod() public {
        // 1) Register allocator and derive lockTag with shorter reset period than the key.
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);
            // Scope.Multichain is used in Setup's _registerAllocator; keep defaults.
        }

        // 2) Deposit assets to create a lock id and allocated amount.
        uint256 amount = 1e18;
        uint256 id = _makeDeposit(swapper, amount, lockTag);

        // 3) Build a claim hash using helpers (with witness typestring), so the digest matches Compact's computation.
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = address(0x2222222222222222222222222222222222222222);
            args.sponsor = swapper;
            args.nonce = 0;
            args.expires = block.timestamp + 1000;
            args.id = id;
            args.amount = amount;
            args.witness = _createCompactWitness(1);
            claimHash = _createClaimHashWithWitness(args);
        }

        // 4) Create a digest for signing and a non-sponsor key pair for emissary verification.
        (address nonSponsor, uint256 privateKey) = makeAddrAndKey('emissary-signer');

        // 5) Register the non-sponsor key in the emissary for the sponsor with a sufficient reset period.
        Key memory signerKey = KeyLib.fromAddress(nonSponsor, ResetPeriod.TenMinutes);
        vm.prank(swapper);
        emissary.registerKey(signerKey.keyType, signerKey.publicKey, signerKey.resetPeriod);

        // 6) Assign our KeyManagerEmissary to The Compact for this lockTag.
        vm.prank(swapper);
        assertTrue(theCompact.assignEmissary(lockTag, address(emissary)));

        // 7) Create signature by the registered key over the digest (not by the sponsor!), forcing fallback to emissary.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash));

        // 8) Construct a minimal Claim calldata and invoke theCompact.claim, expecting success via emissary.
        {
            Claim memory claim;
            claim.sponsor = swapper;
            claim.nonce = 0;
            claim.expires = block.timestamp + 1000;
            claim.allocatedAmount = amount;
            claim.id = id;
            claim.witnessTypestring = 'uint256 witnessArgument';
            claim.witness = _createCompactWitness(1);
            claim.sponsorSignature = abi.encodePacked(r, s, v); // not from sponsor; verified by emissary
            uint256 claimant = abi.decode(abi.encodePacked(bytes12(bytes32(id)), swapper), (uint256));
            Component[] memory recipients = new Component[](1);
            recipients[0] = Component({claimant: claimant, amount: amount});
            claim.claimants = recipients;

            // Add allocator authorization
            {
                bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
                (bytes32 ar, bytes32 avs) = vm.signCompact(allocatorPrivateKey, digest);
                claim.allocatorData = abi.encodePacked(ar, avs);
            }

            vm.prank(address(0x2222222222222222222222222222222222222222));
            bytes32 returnedClaimHash = theCompact.claim(claim);
            assertEq(returnedClaimHash, claimHash);
        }
    }

    function test_revert_e2e_ClaimViaEmissaryFallback_IncompatibleResetPeriod() public {
        // 1) Register allocator and derive lockTag with a long reset period.
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);
        }

        // 2) Deposit assets for claim.
        uint256 amount = 1e18;
        uint256 id = _makeDeposit(swapper, amount, lockTag);

        // 3) Build claim hash with witness typestring to match Compact's computation.
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = address(0x2222222222222222222222222222222222222222);
            args.sponsor = swapper;
            args.nonce = 0;
            args.expires = block.timestamp + 1000;
            args.id = id;
            args.amount = amount;
            args.witness = _createCompactWitness(1);
            claimHash = _createClaimHashWithWitness(args);
        }

        // 4) Register a key with a shorter reset period than the lockTag and assign emissary.
        (address nonSponsor, uint256 privateKey) = makeAddrAndKey('emissary-signer-short');
        Key memory shortKey = KeyLib.fromAddress(nonSponsor, ResetPeriod.OneSecond);
        vm.prank(swapper);
        emissary.registerKey(shortKey.keyType, shortKey.publicKey, shortKey.resetPeriod);
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, address(emissary));

        // 5) Create signature by the registered key over the digest.
        (uint8 v2, bytes32 r2, bytes32 s2) =
            vm.sign(privateKey, _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash));

        // 6) Attempt claim; expect revert due to emissary reset period incompatibility.
        Claim memory claim;
        claim.sponsor = swapper;
        claim.nonce = 0;
        claim.expires = block.timestamp + 1000;
        claim.allocatedAmount = amount;
        claim.id = id;
        claim.witnessTypestring = 'uint256 witnessArgument';
        claim.witness = _createCompactWitness(1);
        claim.sponsorSignature = abi.encodePacked(r2, s2, v2);
        uint256 claimant = abi.decode(abi.encodePacked(bytes12(bytes32(id)), swapper), (uint256));
        Component[] memory recipients = new Component[](1);
        recipients[0] = Component({claimant: claimant, amount: amount});
        claim.claimants = recipients;

        // Add allocator authorization
        {
            bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
            (bytes32 ar, bytes32 avs) = vm.signCompact(allocatorPrivateKey, digest);
            claim.allocatorData = abi.encodePacked(ar, avs);
        }

        vm.prank(address(0x2222222222222222222222222222222222222222));
        vm.expectRevert(BaseKeyVerifier.SignatureVerificationFailed.selector);
        theCompact.claim(claim);
    }

    function test_e2e_ClaimViaEmissaryFallback_P256() public {
        // Register allocator and deposit
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);
        }

        uint256 amount = 1e18;
        uint256 id = _makeDeposit(swapper, amount, lockTag);

        // Build claim hash with witness typestring
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = address(0x2222222222222222222222222222222222222222);
            args.sponsor = swapper;
            args.nonce = 0;
            args.expires = block.timestamp + 1000;
            args.id = id;
            args.amount = amount;
            args.witness = _createCompactWitness(1);
            claimHash = _createClaimHashWithWitness(args);
        }

        // Create P256 key pair and register with emissary (reset period >= lockTag)
        uint256 p256Sk = _bound(uint256(keccak256('p256_e2e_success')), 1, P256.N - 1);
        {
            (uint256 xU, uint256 yU) = vm.publicKeyP256(p256Sk);
            Key memory p256Key = KeyLib.fromP256(bytes32(xU), bytes32(yU), ResetPeriod.TenMinutes);
            vm.prank(swapper);
            emissary.registerKey(p256Key.keyType, p256Key.publicKey, p256Key.resetPeriod);
        }

        // Assign emissary
        vm.prank(swapper);
        assertTrue(theCompact.assignEmissary(lockTag, address(emissary)));

        // Sign digest with P256
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 s) = vm.signP256(p256Sk, digest);
        s = P256.normalized(s);
        bytes memory sponsorSignature = abi.encodePacked(r, s); // 64-bytes r||s

        // Build claim
        Claim memory claim;
        {
            claim.sponsor = swapper;
            claim.nonce = 0;
            claim.expires = block.timestamp + 1000;
            claim.allocatedAmount = amount;
            claim.id = id;
            claim.witnessTypestring = 'uint256 witnessArgument';
            claim.witness = _createCompactWitness(1);
            claim.sponsorSignature = sponsorSignature;
        }
        uint256 claimantPacked = abi.decode(abi.encodePacked(bytes12(bytes32(id)), swapper), (uint256));
        Component[] memory cc = new Component[](1);
        cc[0] = Component({claimant: claimantPacked, amount: amount});
        claim.claimants = cc;
        (bytes32 ar, bytes32 avs) = vm.signCompact(allocatorPrivateKey, digest);
        claim.allocatorData = abi.encodePacked(ar, avs);

        // Expect success via emissary with P256
        vm.prank(address(0x2222222222222222222222222222222222222222));
        bytes32 returnedClaimHash = theCompact.claim(claim);
        assertEq(returnedClaimHash, claimHash);
    }

    function test_revert_e2e_ClaimViaEmissaryFallback_P256_IncompatibleResetPeriod() public {
        // Register allocator and deposit
        bytes12 lockTag;
        {
            uint96 allocatorId;
            (allocatorId, lockTag) = _registerAllocator(allocator);
        }

        uint256 amount = 1e18;
        uint256 id = _makeDeposit(swapper, amount, lockTag);

        // Build claim hash with witness typestring
        bytes32 claimHash;
        {
            CreateClaimHashWithWitnessArgs memory args;
            args.typehash = compactWithWitnessTypehash;
            args.arbiter = address(0x2222222222222222222222222222222222222222);
            args.sponsor = swapper;
            args.nonce = 0;
            args.expires = block.timestamp + 1000;
            args.id = id;
            args.amount = amount;
            args.witness = _createCompactWitness(1);
            claimHash = _createClaimHashWithWitness(args);
        }

        // Create P256 key with too-short reset period and register with emissary
        uint256 p256Sk = _bound(uint256(keccak256('p256_e2e_fail')), 1, P256.N - 1);
        {
            (uint256 xU, uint256 yU) = vm.publicKeyP256(p256Sk);
            Key memory p256Key = KeyLib.fromP256(bytes32(xU), bytes32(yU), ResetPeriod.OneMinute);
            vm.prank(swapper);
            emissary.registerKey(p256Key.keyType, p256Key.publicKey, p256Key.resetPeriod);
        }

        // Assign emissary
        vm.prank(swapper);
        theCompact.assignEmissary(lockTag, address(emissary));

        // Sign digest with P256
        bytes32 digest = _createDigest(theCompact.DOMAIN_SEPARATOR(), claimHash);
        (bytes32 r, bytes32 s) = vm.signP256(p256Sk, digest);
        s = P256.normalized(s);
        bytes memory sponsorSignature = abi.encodePacked(r, s);

        // Build claim
        Claim memory claim;
        {
            claim.sponsor = swapper;
            claim.nonce = 0;
            claim.expires = block.timestamp + 1000;
            claim.allocatedAmount = amount;
            claim.id = id;
            claim.witnessTypestring = 'uint256 witnessArgument';
            claim.witness = _createCompactWitness(1);
            claim.sponsorSignature = sponsorSignature;
        }
        uint256 claimantPacked2 = abi.decode(abi.encodePacked(bytes12(bytes32(id)), swapper), (uint256));
        Component[] memory cc2 = new Component[](1);
        cc2[0] = Component({claimant: claimantPacked2, amount: amount});
        claim.claimants = cc2;
        (bytes32 ar2, bytes32 avs2) = vm.signCompact(allocatorPrivateKey, digest);
        claim.allocatorData = abi.encodePacked(ar2, avs2);

        // Expect revert due to emissary reset period incompatibility
        vm.prank(address(0x2222222222222222222222222222222222222222));
        vm.expectRevert(BaseKeyVerifier.SignatureVerificationFailed.selector);
        theCompact.claim(claim);
    }
}
