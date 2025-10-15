// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import 'forge-std/Script.sol';
import {KeyManagerEmissary} from 'src/KeyManagerEmissary.sol';

interface ImmutableCreate2Factory {
    function safeCreate2(bytes32 salt, bytes calldata initializationCode)
        external
        payable
        returns (address deploymentAddress);
}

contract Deploy is Script {
    using stdJson for string;

    event InitCodeHash(bytes32 initCodeHash);

    function run() public returns (KeyManagerEmissary emissary) {
        vm.startBroadcast();
        // to deploy using create2 (need to rederive salt and target address when changing code):
        emit InitCodeHash(keccak256(type(KeyManagerEmissary).creationCode));
        bytes32 salt = bytes32(0x00000000000000000000000000000000000000006c8e1b192c643f327b4d5c28);
        address targetAddress = address(0x00000000000059A79403C99B216981C8B7E40Cd7);
        // ensure create2 deployer is deployed
        address immutableCreate2Factory = address(0x0000000000FFe8B47B3e2130213B802212439497);
        require(immutableCreate2Factory.code.length > 0, 'immutableCreate2Factory not deployed');
        // deploy it and check the target address
        emissary = KeyManagerEmissary(
            ImmutableCreate2Factory(immutableCreate2Factory).safeCreate2(salt, type(KeyManagerEmissary).creationCode)
        );
        require(address(emissary) == targetAddress, 'emissary not deployed at target address');
        vm.stopBroadcast();
    }
}
