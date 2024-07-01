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


contract DummyServiceManager is IEigenDAServiceManager {
    // EVENTS

    // CONSTRUCTOR
    constructor() {
        // Constructor code can be added here if needed
    }

    /// @notice mapping between the batchId to the hash of the metadata of the corresponding Batch
    function batchIdToBatchMetadataHash(uint32 batchId) external view override returns (bytes32) {
        // Stubbed implementation
        return bytes32(0);
    }
    

    /**
     * @notice This function is used for
     * - submitting data availability certificates,
     * - check that the aggregate signature is valid,
     * - and check whether quorum has been achieved or not.
     */
    function confirmBatch(
        BatchHeader calldata batchHeader,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external override {
        // Stubbed implementation
    }

    /// @notice This function is used for changing the batch confirmer
    function setBatchConfirmer(address _batchConfirmer) external override {
        // Stubbed implementation
    }

    /// @notice Returns the current batchId
    function taskNumber() external view override returns (uint32) {
        // Stubbed implementation
        return 0;
    }

    /// @notice Given a reference block number, returns the block until which operators must serve.
    function latestServeUntilBlock(uint32 referenceBlockNumber) external view override returns (uint32) {
        // Stubbed implementation
        return 0;
    }

    /// @notice The maximum amount of blocks in the past that the service will consider stake amounts to still be 'valid'.
    function BLOCK_STALE_MEASURE() external view override returns (uint32) {
        // Stubbed implementation
        return 0;
    }

    /// @notice Returns the bytes array of quorumAdversaryThresholdPercentages
    function quorumAdversaryThresholdPercentages() external view override returns (bytes memory) {
        // Stubbed implementation
        return "";
    }

    /// @notice Returns the bytes array of quorumAdversaryThresholdPercentages
    function quorumConfirmationThresholdPercentages() external view override returns (bytes memory) {
        // Stubbed implementation
        return "";
    }

    /// @notice Returns the bytes array of quorumsNumbersRequired
    function quorumNumbersRequired() external view override returns (bytes memory) {
        // Stubbed implementation
        return "";
    }

    function payForRange(IPaymentCoordinator.RangePayment[] calldata rangePayments) external override {
        return;
    }

    function updateAVSMetadataURI(string memory _metadataURI) external override {
            return;
     }

    /**
     * @notice Forwards a call to EigenLayer's DelegationManager contract to confirm operator registration with the AVS
     * @param operator The address of the operator to register.
     * @param operatorSignature The signature, salt, and expiry of the operator's signature.
     */
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) external override {
        return;
    }

    /**
     * @notice Forwards a call to EigenLayer's DelegationManager contract to confirm operator deregistration from the AVS
     * @param operator The address of the operator to deregister.
     */
    function deregisterOperatorFromAVS(address operator) external override {
        return;
    }

    /**
     * @notice Returns the list of strategies that the operator has potentially restaked on the AVS
     * @param operator The address of the operator to get restaked strategies for
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on whether the operator has shares for a strategy in a quorum or uniqueness 
     *      of each element in the returned array. The off-chain service should do that validation separately
     */
    function getOperatorRestakedStrategies(address operator) external view override returns (address[] memory){
        address[] memory dummyAddresses = new address[](2);
        dummyAddresses[0] = 0x0000000000000000000000000000000000000001;
        dummyAddresses[1] = 0x0000000000000000000000000000000000000002;
        return dummyAddresses;
    }

    /**
     * @notice Returns the list of strategies that the AVS supports for restaking
     * @dev This function is intended to be called off-chain
     * @dev No guarantee is made on uniqueness of each element in the returned array. 
     *      The off-chain service should do that validation separately
     */
    function getRestakeableStrategies() external view override returns (address[] memory) {
                address[] memory dummyAddresses = new address[](2);
        dummyAddresses[0] = 0x0000000000000000000000000000000000000001;
        dummyAddresses[1] = 0x0000000000000000000000000000000000000002;
        return dummyAddresses;
    }

    /// @notice Returns the EigenLayer AVSDirectory contract.
    function avsDirectory() external view returns (address) {
        address x = 0x0000000000000000000000000000000000000001;
        return x;
    }

}

interface IRollupManager {

    struct ProofMetadata {
        uint32 batchID;
        uint32 blobIndex;
        bytes32 signatoryRecordHash;
        uint32 confirmationBlockNumber;
        bytes inclusionProof;
        bytes quorumIndices;
    }

    struct SequenceMetadata {
        uint256 afterDelayedMessagesRead;
        uint256 prevMessageCount;
        uint256 newMessageCount;
    }

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
