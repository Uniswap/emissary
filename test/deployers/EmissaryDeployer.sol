// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from 'forge-std/Test.sol';
import {IEmissary} from 'the-compact/interfaces/IEmissary.sol';

contract EmissaryDeployer is Test {
    function deploy() internal returns (IEmissary emissary) {
        bytes memory bytecode = abi.encodePacked(vm.getCode('KeyManagerEmissary.sol:KeyManagerEmissary'));
        assembly {
            emissary := create(0, add(bytecode, 0x20), mload(bytecode))
        }
    }
}
