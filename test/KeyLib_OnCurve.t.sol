// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from 'forge-std/Test.sol';
import {KeyLib} from 'src/KeyLib.sol';

contract KeyLibHarness {
    function isOnCurve(uint256 x, uint256 y) external pure returns (bool) {
        return KeyLib._p256IsOnCurve(x, y);
    }
}

contract KeyLib_OnCurve_Test is Test {
    KeyLibHarness private harness;

    // P-256 field prime p and curve constant b (copied from https://neuromancer.sk/std/x962/prime256v1)
    uint256 internal constant P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 internal constant B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

    // P-256 base point (generator) coordinates (copied from NIST P-256 test vectors)
    uint256 internal constant GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
    uint256 internal constant GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;

    function setUp() public {
        harness = new KeyLibHarness();
    }

    function test__p256IsOnCurve_GeneratorAndNegation_ReturnsTrue() public view {
        // (Gx, Gy) is on-curve.
        bool onCurveG = harness.isOnCurve(GX, GY);
        assertTrue(onCurveG, 'Generator must be on curve');

        // (Gx, p - Gy) is also on-curve (y -> -y mod p).
        uint256 gyNeg = addmod(P, P - (GY % P), P);
        bool onCurveNeg = harness.isOnCurve(GX, gyNeg);
        assertTrue(onCurveNeg, 'Negation of generator y must be on curve');
    }

    function test__p256IsOnCurve_XZeroSqrtB_ReturnsTrue() public view {
        // For x = 0, curve is y^2 = b (mod p). Since p ≡ 3 (mod 4), sqrt can be computed as b^((p+1)/4) mod p.
        uint256 exp = (P + 1) >> 2;
        uint256 y = _modExp(B % P, exp, P);
        require(y != 0, 'sqrt(b) must be non-zero');

        bool onCurve = harness.isOnCurve(0, y);
        assertTrue(onCurve, 'x=0, y=sqrt(b) must be on curve');

        uint256 yNeg = addmod(P, P - y, P);
        bool onCurveNeg = harness.isOnCurve(0, yNeg);
        assertTrue(onCurveNeg, 'x=0, y=p - sqrt(b) must be on curve');
    }

    function testFuzz__p256IsOnCurve_YZero_ReturnsFalse(uint256 x) public view {
        x = bound(x, 0, P - 1);
        bool onCurve = harness.isOnCurve(x, 0);
        assertFalse(onCurve, '(x,0) should not be on curve for any x');
    }

    function test__p256IsOnCurve_OutOfField_ReturnsFalse() public view {
        assertFalse(harness.isOnCurve(P, 1), 'x >= p must be invalid');
        assertFalse(harness.isOnCurve(1, P), 'y >= p must be invalid');
    }

    function test__p256IsOnCurve_PointAtInfinity_ReturnsFalse() public view {
        assertFalse(harness.isOnCurve(0, 0), 'point at infinity must be invalid');
    }

    function test__p256IsOnCurve_GxWithWrongY_ReturnsFalse() public view {
        uint256 badY = addmod(GY, 1, P);
        assertFalse(harness.isOnCurve(GX, badY), 'Gx with wrong y must be invalid');
    }

    function test__p256IsOnCurve_XZeroWrongY_ReturnsFalse() public view {
        uint256 exp = (P + 1) >> 2;
        uint256 y = _modExp(B % P, exp, P); // sqrt(b)
        uint256 wrongY = addmod(y, 1, P);
        if (wrongY == y || wrongY == addmod(P, P - y, P)) wrongY = addmod(wrongY, 1, P);
        assertFalse(harness.isOnCurve(0, wrongY), 'x=0 with wrong y must be invalid');
    }

    function _modExp(uint256 base, uint256 exponent, uint256 modulus) internal view returns (uint256 result) {
        bytes memory precompileData = abi.encode(32, 32, 32, base, exponent, modulus);
        (bool success, bytes memory result) = address(0x05).staticcall(precompileData);
        return abi.decode(result, (uint256));
    }
}
