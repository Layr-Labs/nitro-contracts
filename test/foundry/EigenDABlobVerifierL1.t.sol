// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "forge-std/Test.sol";
import "../../src/bridge/EigenDABlobVerifierL1.sol";
import "../../src/libraries/Error.sol";
import {EigenDARollupUtils} from "@eigenda/eigenda-utils/libraries/EigenDARollupUtils.sol";
import {IEigenDAServiceManager} from "@eigenda/eigenda-utils/interfaces/IEigenDAServiceManager.sol";
import {BN254} from "@eigenda/eigenda-utils/libraries/BN254.sol";
import {SequencerInboxTest} from "./SequencerInbox.t.sol";
import {ExpiredEigenDACert} from "../../src/libraries/Error.sol";

contract EigenDABlobVerifierL1Test is Test {
    EigenDABlobVerifierL1 public verifier;
    IEigenDAServiceManager dummyEigenDAServiceManager = IEigenDAServiceManager(address(138));

    SequencerInboxTest inboxTest = new SequencerInboxTest();

    function setUp() public {
        // Deploy the verifier contract with a mock EigenDA Service Manager
        verifier = new EigenDABlobVerifierL1(address(dummyEigenDAServiceManager));
    }

    function testCertificateTooOld() public {
        (
            IEigenDAServiceManager.BlobHeader memory blobHeader,
            EigenDARollupUtils.BlobVerificationProof memory blobVerificationProof
        ) = inboxTest.readAndParseBlobInfo();

        // Set the confirmation block number to be MAX_CERTIFICATE_DRIFT + 1
        blobVerificationProof.batchMetadata.confirmationBlockNumber = 0;

        vm.roll(101);
        vm.expectRevert(abi.encodeWithSelector(ExpiredEigenDACert.selector, block.number, 100));

        verifier.verifyBlob(blobHeader, blobVerificationProof);
    }

    function testCertificateWithinSafetyBound() public {
        (
            IEigenDAServiceManager.BlobHeader memory blobHeader,
            EigenDARollupUtils.BlobVerificationProof memory blobVerificationProof
        ) = inboxTest.readAndParseBlobInfo();

        // Set the confirmation block number to be MAX_CERTIFICATE_DRIFT + 1
        blobVerificationProof.batchMetadata.confirmationBlockNumber = 100;

        vm.roll(101);
        vm.expectRevert(bytes(""));

        verifier.verifyBlob(blobHeader, blobVerificationProof);
    }
}
