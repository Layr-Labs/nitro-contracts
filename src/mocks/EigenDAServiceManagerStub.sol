// SPDX-License-Identifier: UNLICENSED

import {IEigenDAServiceManager} from "@eigenda/eigenda-utils/interfaces/IEigenDAServiceManager.sol";
import {BN254} from "@eigenda/eigenda-utils/libraries/BN254.sol";
import {IBLSSignatureChecker} from "@eigenda/eigenda-utils/interfaces/IBLSSignatureChecker.sol";
import {IRegistryCoordinator} from "@eigenda/eigenda-utils/interfaces/IRegistryCoordinator.sol";
import {IStakeRegistry} from "@eigenda/eigenda-utils/interfaces/IStakeRegistry.sol";
import {IBLSApkRegistry} from "@eigenda/eigenda-utils/interfaces/IBLSApkRegistry.sol";
import {IDelegationManager} from "@eigenda/eigenda-utils/interfaces/IDelegationManager.sol";
import {IPaymentCoordinator} from "@eigenda/eigenda-utils/interfaces/IPaymentCoordinator.sol";
import {ISignatureUtils} from "@eigenda/eigenda-utils/interfaces/ISignatureUtils.sol";

contract EigenDAServiceManagerStub is IEigenDAServiceManager, IBLSSignatureChecker {
    function confirmBatch(
        BatchHeader calldata batchHeader,
        NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external override pure {
        revert("NOT_IMPLEMENTED");
    }

    function setBatchConfirmer(address _batchConfirmer) external override pure {
        revert("NOT_IMPLEMENTED");
    }

    function taskNumber() external view override returns (uint32) {
        revert("NOT_IMPLEMENTED");
    }

    function latestServeUntilBlock(uint32 referenceBlockNumber)
        external
        view
        override
        returns (uint32)
    {
        return referenceBlockNumber + 100;
    }

    function checkSignatures(
        bytes32 msgHash,
        bytes calldata quorumNumbers,
        uint32 referenceBlockNumber,
        NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external view override returns (QuorumStakeTotals memory, bytes32) {
        revert("NOT_IMPLEMENTED");
    }

    function registryCoordinator() external view override returns (IRegistryCoordinator) {
        revert("NOT_IMPLEMENTED");
    }

    function stakeRegistry() external view override returns (IStakeRegistry) {
        revert("NOT_IMPLEMENTED");
    }

    function blsApkRegistry() external view override returns (IBLSApkRegistry) {
        revert("NOT_IMPLEMENTED");
    }

    function delegation() external view override returns (IDelegationManager) {
        revert("NOT_IMPLEMENTED");
    }

    function BLOCK_STALE_MEASURE() external view override returns (uint32) {
        revert("NOT_IMPLEMENTED");
    }

    function quorumAdversaryThresholdPercentages() external view override returns (bytes memory) {
        revert("NOT_IMPLEMENTED");
    }

    function quorumConfirmationThresholdPercentages()
        external
        view
        override
        returns (bytes memory)
    {
        revert("NOT_IMPLEMENTED");
    }

    function quorumNumbersRequired() external view override returns (bytes memory) {
        revert("NOT_IMPLEMENTED");
    }

        // Implement missing functions from IServiceManagerUI and IEigenDAServiceManager
    function avsDirectory() external view override returns (address) {
        revert("NOT_IMPLEMENTED");
    }

    function batchIdToBatchMetadataHash(uint32 batchId) external view override returns(bytes32) {
        revert("NOT_IMPLEMENTED");
    }

    function deregisterOperatorFromAVS(address operator) external override pure {
        revert("NOT_IMPLEMENTED");
    }

    function getOperatorRestakedStrategies(address operator) external view override returns (address[] memory) {
        revert("NOT_IMPLEMENTED");
    }

    function getRestakeableStrategies() external view override returns (address[] memory) {
        revert("NOT_IMPLEMENTED");
    }

    function payForRange(IPaymentCoordinator.RangePayment[] calldata rangePayments) external override pure {
        revert("NOT_IMPLEMENTED");
    }

    function registerOperatorToAVS(address operator, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature) external {
        revert("NOT_IMPLEMENTED");
    }

    function updateAVSMetadataURI(string memory _metadataURI) external override pure {
        revert("NOT_IMPLEMENTED");
    }
}
