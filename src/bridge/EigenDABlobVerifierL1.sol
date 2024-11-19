// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./IRollupManager.sol";
import {
    ExpiredEigenDACert
} from "../libraries/Error.sol";

contract EigenDABlobVerifierL1 is IRollupManager {
    IEigenDAServiceManager public immutable EIGEN_DA_SERVICE_MANAGER;
    uint256 internal constant MAX_CERTIFICATE_DRIFT = 100; 

    constructor(address _eigenDAServiceManager) {
        EIGEN_DA_SERVICE_MANAGER = IEigenDAServiceManager(_eigenDAServiceManager);
    }

    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view {
        /*
            Verify that the certificate is less than 2 epochs old from the L1 reference block number
            This is to prevent timing attacks where the sequencer could submit an expired or close to expired
            certificate which could impact liveness of full nodes as well as the safety of the bridge
        */
        if (
            (blobVerificationProof.batchMetadata.confirmationBlockNumber +
                MAX_CERTIFICATE_DRIFT) < block.number
        ) {
            revert ExpiredEigenDACert(
                block.number,
                blobVerificationProof.batchMetadata.confirmationBlockNumber +
                    MAX_CERTIFICATE_DRIFT
            );
        }


        EigenDARollupUtils.verifyBlob(blobHeader, EIGEN_DA_SERVICE_MANAGER, blobVerificationProof);
    }
}
