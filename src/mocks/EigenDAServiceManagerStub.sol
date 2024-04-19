// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import {EigenDAServiceManager} from "@eigenda/eigenda-utils/contracts/eigenda/EigenDAServiceManager.sol";
import {IAVSDirectory} from "@eigenda/eigenda-utils/interfaces/IAVSDirectory.sol";
import {IPaymentCoordinator} from "@eigenda/eigenda-utils/interfaces/IPaymentCoordinator.sol";
import {IRegistryCoordinator} from "@eigenda/eigenda-utils/interfaces/IRegistryCoordinator.sol";
import {IStakeRegistry} from "@eigenda/eigenda-utils/interfaces/IStakeRegistry.sol";
import {IPauserRegistry} from "@eigenda/eigenda-utils/interfaces/IPauserRegistry.sol";

contract EigenDAServiceManagerStub is EigenDAServiceManager {

    constructor(
        IAVSDirectory __avsDirectory,
        IPaymentCoordinator __paymentCoordinator,
        IRegistryCoordinator __registryCoordinator,
        IStakeRegistry __stakeRegistry,
        IPauserRegistry _pauserRegistry,
        uint256 _initialPausedStatus,
        address _initialOwner,
        address[] memory _batchConfirmers
    ) EigenDAServiceManager(
        __avsDirectory,
        __paymentCoordinator,
        __registryCoordinator,
        __stakeRegistry
    ) {
    }
}
