// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import {
    BlobHeader,
    BlobVerificationProof
} from "@eigenda/contracts/src/interfaces/IEigenDAStructs.sol";

interface IRollupManager {
    function verifyBlob(
        BlobHeader calldata blobHeader,
        BlobVerificationProof calldata blobVerificationProof
    ) external view;
}
