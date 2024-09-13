// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "../../src/osp/OneStepProverHostIo.sol";
import "forge-std/Test.sol";

contract VerifyKzgBN245Commitment is Test {
    OneStepProverHostIo public osp;

    function setUp() public {
        osp = new OneStepProverHostIo();
    }

    function testVerifyCommitment() public {
        uint256 commitX = 19070058680970706162154662779699659917241938423048978712039328696898981234708;
        uint256 commitY = 11823711927945062212181456259672826202645633805996688691575607391116183704220;
        uint256 evaluationY = 124448554745810004944228143885327110275920855486363883336842102793103679599;

        uint256[2] memory commit = [commitX, commitY];

        uint256 proofX = 3494873036786265278705899204171091912768379376170087008335233101540628332609;
        uint256 proofY = 8608960508439403080401521741368234568803206554328273041427052980854260749148;

        uint256[2] memory proofArray = [proofX, proofY];

        uint256 z = 1;

        uint256 alphaMinusZG2x0 = 3835064393148581205232814970864979673787834430112792762416742772525023890054;
        uint256 alphaMinusZG2x1 = 21870966891160875056996525725939836296469570838755910925871109003952938425221;
        uint256 alphaMinusZG2y0 = 1003462328537511635851373881294094113215131010279982437048829782051523402493;
        uint256 alphaMinusZG2y1 = 1812648663781569755056741449255719259077856056456933971984290530760064403988;

        uint256[4] memory alphaMinusZG2 = [
            alphaMinusZG2x0,
            alphaMinusZG2x1,
            alphaMinusZG2y0,
            alphaMinusZG2y1
        ];

        assertTrue(
            osp.VerifyKzgProofWithG1Equivalence(commit, evaluationY, proofArray, z, alphaMinusZG2)
        );

        // Test with bad z which should fail

        uint256 bad_z = 69;
        assertFalse(
            osp.VerifyKzgProofWithG1Equivalence(
                commit,
                evaluationY,
                proofArray,
                bad_z,
                alphaMinusZG2
            )
        );
    }
}
