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

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

interface IRollupManager {

      function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
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

contract EigenDARollupManager is Ownable, IRollupManager {
    using BN254 for BN254.G1Point;

    address public eigenDAServiceManager;

    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view {
       return EigenDARollupUtils.verifyBlob(blobHeader, IEigenDAServiceManager(eigenDAServiceManager), blobVerificationProof);
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

    function setEigenDAServiceManager(address _eigenDAServiceManager) external onlyOwner {
        eigenDAServiceManager = _eigenDAServiceManager;
    }
}
