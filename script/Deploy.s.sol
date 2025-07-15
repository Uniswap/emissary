// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import 'forge-std/Script.sol';

import {KeyManagerEmissary} from 'src/KeyManagerEmissary.sol';

contract Deploy is Script {
    using stdJson for string;

    function run() public returns (KeyManagerEmissary emissary) {
        bytes memory bytecode = abi.encodePacked(vm.getCode('KeyManagerEmissary.sol:KeyManagerEmissary'));
        assembly {
            emissary := create(0, add(bytecode, 0x20), mload(bytecode))
        }
    }
}
