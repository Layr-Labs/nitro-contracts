// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "./IRollupManager.sol";
import {ExpiredEigenDACert} from "../libraries/Error.sol";
import {IEigenDABlobVerifier} from "@eigenda/contracts/src/interfaces/IEigenDABlobVerifier.sol";

contract EigenDABlobVerifierL1 is IRollupManager {
    IEigenDABlobVerifier public immutable VERIFIER;
    uint256 internal constant MAX_CERTIFICATE_DRIFT = 100;

    constructor(
        address _eigenDABlobVerifier
    ) {
        VERIFIER = IEigenDABlobVerifier(_eigenDABlobVerifier);
    }

    function verifyBlob(
        BlobHeader calldata blobHeader,
        BlobVerificationProof calldata blobVerificationProof
    ) external view {
        /*
            Verify that the certificate is less than 2 epochs old from the L1 confirmation block number
            This is to prevent timing attacks where the sequencer could submit an expired or close to expired
            certificate which could impact liveness of full nodes as well as the safety of the bridge
        */
        if (
            (blobVerificationProof.batchMetadata.confirmationBlockNumber + MAX_CERTIFICATE_DRIFT)
                < block.number
        ) {
            revert ExpiredEigenDACert(
                block.number,
                blobVerificationProof.batchMetadata.confirmationBlockNumber + MAX_CERTIFICATE_DRIFT
            );
        }

        VERIFIER.verifyBlobV1(blobHeader, blobVerificationProof);
    }
}
