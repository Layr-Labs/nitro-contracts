// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "../../src/osp/OneStepProverHostIo.sol";
import "forge-std/Test.sol";

import {BN254} from "eigenlayer-middleware/libraries/BN254.sol";

contract VerifyCommitentTest  {
    OneStepProverHostIo public osp;

    BN254.G1Point public commitment;
    BN254.G1Point public proof;
    uint256 public value;
    uint256 public evaluationPoint;

    function setUp() public {
        osp = new OneStepProverHostIo();
    }


    function testVerifyCommitment() public {
        commitment = BN254.G1Point(2961155957874067312593973807786254905069537311739090798303675273531563528369, 159565752702690920280451512738307422982252330088949702406468210607852362941);
        proof = BN254.G1Point(20889584344688264775152566886162369109335964682277058078504426815999095925704, 216054499853810563509078220646136944393866292849931571513515988346637933611);
        value = 400194862503576342918173310331854693478403117005444701857659884415883371564;
        evaluationPoint = 42;

        osp.verifyEigenDACommitment(commitment, proof, value, evaluationPoint);
    }

    // function testVerifyIllegalCommitmentReverts() public {
    //     OneStepProverHostIo.verifyCommitment(commitment, proof, value, evaluationPoint);
    // }
}
