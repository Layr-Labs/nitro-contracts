// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "../../src/bridge/IRollupManager.sol";

contract DummyEigenDABlobVerifier is IRollupManager {
    function verifyBlob(
        IEigenDAServiceManager.BlobHeader calldata blobHeader,
        EigenDARollupUtils.BlobVerificationProof calldata blobVerificationProof
    ) external view {}
}
