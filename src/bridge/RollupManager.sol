// SPDX-License-Identifier: MIT

pragma solidity ^0.8.9;

import {Merkle} from "@eigenda/eigenda-utils/libraries/Merkle.sol";
import {BN254} from "@eigenda/eigenda-utils/libraries/BN254.sol";
import {EigenDAHasher} from "@eigenda/eigenda-utils/libraries/EigenDAHasher.sol";
import {IEigenDAServiceManager} from "@eigenda/eigenda-utils/interfaces/IEigenDAServiceManager.sol";
import {BitmapUtils} from "@eigenda/eigenda-utils/libraries/BitmapUtils.sol";
import {EigenDARollupUtils} from "@eigenda/eigenda-utils/libraries/EigenDARollupUtils.sol";
import {IBLSSignatureChecker} from "@eigenda/eigenda-utils/interfaces/IBLSSignatureChecker.sol";
import {IPaymentCoordinator} from "@eigenda/eigenda-utils/interfaces/IPaymentCoordinator.sol";
import {ISignatureUtils} from "@eigenda/eigenda-utils/interfaces/ISignatureUtils.sol";


// DummyServiceManager is a dummy implementation of IEigenDAServiceManager
// and is used in nitro-testnode to avoid the overhead of deploying core EigenDA contracts
// to simplify the testing process.
contract DummyServiceManager is IEigenDAServiceManager {

    constructor() {
    }

    function batchIdToBatchMetadataHash(uint32 batchId) external view override returns (bytes32) {
        return bytes32(0);
    }
    
    function confirmBatch(
        BatchHeader calldata batchHeader,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external override {
    }

    function setBatchConfirmer(address _batchConfirmer) external override {
    }

    function taskNumber() external view override returns (uint32) {
        return 0;
    }
    function latestServeUntilBlock(uint32 referenceBlockNumber) external view override returns (uint32) {
        return 0;
    }
    function BLOCK_STALE_MEASURE() external view override returns (uint32) {
        return 0;
    }

    function quorumAdversaryThresholdPercentages() external view override returns (bytes memory) {
        return "";
    }

    function quorumConfirmationThresholdPercentages() external view override returns (bytes memory) {
        return "";
    }

    function quorumNumbersRequired() external view override returns (bytes memory) {
        return "";
    }

    function payForRange(IPaymentCoordinator.RangePayment[] calldata rangePayments) external override {
        return;
    }

    function updateAVSMetadataURI(string memory _metadataURI) external override {
            return;
     }

    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) external override {
        return;
    }

    function deregisterOperatorFromAVS(address operator) external override {
        return;
    }

    function getOperatorRestakedStrategies(address operator) external view override returns (address[] memory){
        address[] memory dummyAddresses = new address[](2);
        dummyAddresses[0] = 0x0000000000000000000000000000000000000001;
        dummyAddresses[1] = 0x0000000000000000000000000000000000000002;
        return dummyAddresses;
    }

    function getRestakeableStrategies() external view override returns (address[] memory) {
                address[] memory dummyAddresses = new address[](2);
        dummyAddresses[0] = 0x0000000000000000000000000000000000000001;
        dummyAddresses[1] = 0x0000000000000000000000000000000000000002;
        return dummyAddresses;
    }

    function avsDirectory() external view returns (address) {
        address x = 0x0000000000000000000000000000000000000001;
        return x;
    }

}

interface IRollupManager {

      function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        IEigenDAServiceManager eigenDAServiceManager,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view;

    function openCommitment(
        uint256 point, 
        uint256 evaluation,
        BN254.G1Point memory tau, 
        BN254.G1Point memory commitment, 
        BN254.G2Point memory proof 
    ) external view returns(bool);

}

// EigenDADummyManager is a dummy implementation of IRollupManager
// and is used in nitro-testnode to avoid the overhead of deploying core EigenDA contracts
// to simplify the testing process.
contract EigenDADummyManager {

    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata,
        IEigenDAServiceManager,
        EigenDARollupUtils.BlobVerificationProof calldata
    ) external view {
       return ;
    }

    function openCommitment(
        uint256 point, 
        uint256 evaluation,
        BN254.G1Point memory tau, 
        BN254.G1Point memory commitment, 
        BN254.G2Point memory proof 
    ) internal view returns(bool) {

        return EigenDARollupUtils.openCommitment(point, evaluation, tau, commitment, proof);
    }
}

contract EigenDARollupManager {
    using BN254 for BN254.G1Point;

    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        IEigenDAServiceManager eigenDAServiceManager,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view {
       return EigenDARollupUtils.verifyBlob(blobHeader, eigenDAServiceManager, blobVerificationProof);
    }

    function openCommitment(
        uint256 point, 
        uint256 evaluation,
        BN254.G1Point memory tau, 
        BN254.G1Point memory commitment, 
        BN254.G2Point memory proof 
    ) external view returns(bool) {

        return EigenDARollupUtils.openCommitment(point, evaluation, tau, commitment, proof);
    }
}
