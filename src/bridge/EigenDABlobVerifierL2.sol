// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./IRollupManager.sol";
import {
    BlobHeader,
    BlobVerificationProof
} from "@eigenda/contracts/src/interfaces/IEigenDAStructs.sol";

contract EigenDABlobVerifierL2 is IRollupManager {
    function verifyBlob(
        BlobHeader calldata blobHeader,
        BlobVerificationProof calldata blobVerificationProof
    ) external view {
        //EigenDA blob verifcation is only supported on L1 currently
    }
}
