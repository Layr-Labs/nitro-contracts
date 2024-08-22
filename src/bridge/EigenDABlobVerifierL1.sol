// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./IRollupManager.sol";

contract EigenDABlobVerifierL1 is IRollupManager {
    IEigenDAServiceManager public immutable EIGEN_DA_SERVICE_MANAGER;

    constructor(address _eigenDAServiceManager) {
        EIGEN_DA_SERVICE_MANAGER = IEigenDAServiceManager(_eigenDAServiceManager);
    }

    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view {
        EigenDARollupUtils.verifyBlob(blobHeader, EIGEN_DA_SERVICE_MANAGER, blobVerificationProof);
    }
}
