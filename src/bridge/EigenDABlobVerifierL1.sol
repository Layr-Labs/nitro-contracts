// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./IRollupManager.sol";

contract EigenDABlobVerifierL1 is IRollupManager {

    IEigenDAServiceManager public immutable eigenDAServiceManager;

    constructor(address _eigenDAServiceManager) {
        eigenDAServiceManager = IEigenDAServiceManager(_eigenDAServiceManager);
    }

    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view {
        EigenDARollupUtils.verifyBlob(blobHeader, eigenDAServiceManager, blobVerificationProof);
    }
}