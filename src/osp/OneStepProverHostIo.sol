// Copyright 2021-2024, Offchain Labs, Inc.
// For license information, see https://github.com/OffchainLabs/nitro-contracts/blob/main/LICENSE
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.0;

import "../state/Value.sol";
import "../state/Machine.sol";
import "../state/MerkleProof.sol";
import "../state/MultiStack.sol";
import "../state/Deserialize.sol";
import "../state/ModuleMemory.sol";
import "./IOneStepProver.sol";
import "../bridge/Messages.sol";
import "../bridge/IBridge.sol";

import {BN254} from "@eigenda/eigenda-utils/libraries/BN254.sol";

library BN254Precompiles {

    function ecAdd(uint256[4] memory input) internal view returns (uint256[2] memory result) {
        assembly {
            // Call precompiled contract 0x06 for ECADD
            if iszero(staticcall(gas(), 0x06, input, 0x80, result, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function ecMul(uint256[3] memory input) internal view returns (uint256[2] memory result) {
        assembly {
            // Call precompiled contract 0x07 for ECMUL
            if iszero(staticcall(gas(), 0x07, input, 0x60, result, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function ecPairing(uint256[12] memory input) internal view returns (bool) {
        uint256[1] memory result;
        assembly {
            // Call precompiled contract 0x08 for ECPAIRING
            if iszero(staticcall(gas(), 0x08, input, 0x180, result, 0x20)) {
                revert(0, 0)
            }
        }
        return result[0] == 1;
    }
}

contract OneStepProverHostIo is IOneStepProver {
    using GlobalStateLib for GlobalState;
    using MachineLib for Machine;
    using MerkleProofLib for MerkleProof;
    using ModuleMemoryLib for ModuleMemory;
    using MultiStackLib for MultiStack;
    using ValueLib for Value;
    using ValueStackLib for ValueStack;
    using StackFrameLib for StackFrameWindow;

    uint256 private constant LEAF_SIZE = 32;
    uint256 private constant INBOX_NUM = 2;
    uint64 private constant INBOX_HEADER_LEN = 40;
    uint64 private constant DELAYED_HEADER_LEN = 112 + 1;
    using BN254Precompiles for uint256[4];
    using BN254Precompiles for uint256[3];

    // Generator point G1 on BN254 curve
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    // AlphaG1
    // This is from the SRS points being used.
    // This is the point at index 1, since index 0 is the generator value of the G1 group.
    uint256 private constant ALPHA_G1x = 5421624913032980671919055010798735843841011930764711817607050648427876929258;
    uint256 private constant ALPHA_G1y = 12995821280260994872112541311010834261076556242291585164372488699033268245381;

    // AlphaG2
    // This is from the SRS points.
    // This is the point at index 1, since index 0 is the generator value of the G2 group.
    uint256 private constant ALPHA_G2xa0 = 7912312892787135728292535536655271843828059318189722219035249994421084560563;
    uint256 private constant ALPHA_G2xa1 = 21039730876973405969844107393779063362038454413254731404052240341412356318284;
    uint256 private constant ALPHA_G2ya0 = 18697407556011630376420900106252341752488547575648825575049647403852275261247;
    uint256 private constant ALPHA_G2ya1 = 7586489485579523767759120334904353546627445333297951253230866312564920951171;

    // Generator point G2 on BN254 curve
    uint256 private constant G2xa0 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 private constant G2xa1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 private constant G2ya0 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 private constant G2ya1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;

    // Prime order of BN254
    uint256 private constant BN254_FR_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function computeGamma(uint256 z, uint256 y, uint256[2] p, uint256[4] memory alpha_minus_z_g2) internal pure returns (uint256) {
        // Encode the variables and compute the keccak256 hash
        return uint256(keccak256(abi.encodePacked(z, y, p[0], p[1], alpha_minus_z_g2[0], alpha_minus_z_g2[1], alpha_minus_z_g2[2], alpha_minus_z_g2[3]))) % BN254_FR_FIELD_MODULUS;
    }

    //  e((P - y) + gamma . (alpha - z), G2) = e((Q + gamma), (alpha - z)) 
    function VerifyKzgProofWithG1Equivalence(
        uint256[2] memory commitment,
        uint256 y,
        uint256[2] memory proof,
        uint256 z,
        uint256[4] memory alpha_minus_z_g2
    ) public {

        uint256[2] memory yG1Neg = [G1_X, G1_Y, ((BN254_FR_FIELD_MODULUS - y) % BN254_FR_FIELD_MODULUS)].ecMul();
        uint256[2] memory P_minus_y = [commitment[0], commitment[1], yG1Neg[0], yG1Neg[1]].ecAdd();

        // zG1
        uint256[2] memory zG1Neg = [G1_X, G1_Y, ((BN254_FR_FIELD_MODULUS - z) % BN254_FR_FIELD_MODULUS)].ecMul();

        // (alphaG1 - zG1) 
        uint256[2] memory alpha_minus_z_g1 = [ALPHA_G1x, ALPHA_G1y, zG1Neg[0], zG1Neg[1]].ecAdd();

        // gamma
        uint256 gamma = computeGamma(z, y, commitment, alpha_minus_z_g2);
        
        // gamma . (alpha - z)G1
        uint256[2] memory gamma_alpha_minus_z_g1 = [alpha_minus_z_g1[0], alpha_minus_z_g1[1], gamma].ecMul();
        
        // gammaG1
        uint256[2] memory gammaG1 = [G1_X, G1_Y, gamma].ecMul(); 
        
        // Q + gamma
        uint256[2] memory q_plus_gamma = [proof[0], proof[1], gammaG1[0], gammaG1[1]].ecAdd();
        uint256[2] memory lhsG1 = [P_minus_y[0], P_minus_y[1], gamma_alpha_minus_z_g1[0], gamma_alpha_minus_z_g1[1]].ecAdd();
        uint256[12] memory Input = [lhsG1[0], lhsG1[1], G2xa1, G2xa0, G2ya1, G2ya0, q_plus_gamma[0], 
        q_plus_gamma[1], alpha_minus_z_g2[1], alpha_minus_z_g2[0], alpha_minus_z_g2[3], alpha_minus_z_g2[2]].ecPairing();

    }

    function setLeafByte(
        bytes32 oldLeaf,
        uint256 idx,
        uint8 val
    ) internal pure returns (bytes32) {
        require(idx < LEAF_SIZE, "BAD_SET_LEAF_BYTE_IDX");
        // Take into account that we are casting the leaf to a big-endian integer
        uint256 leafShift = (LEAF_SIZE - 1 - idx) * 8;
        uint256 newLeaf = uint256(oldLeaf);
        newLeaf &= ~(0xFF << leafShift);
        newLeaf |= uint256(val) << leafShift;
        return bytes32(newLeaf);
    }

    function executeGetOrSetBytes32(
        Machine memory mach,
        Module memory mod,
        GlobalState memory state,
        Instruction calldata inst,
        bytes calldata proof
    ) internal pure {
        uint256 ptr = mach.valueStack.pop().assumeI32();
        uint32 idx = mach.valueStack.pop().assumeI32();

        if (idx >= GlobalStateLib.BYTES32_VALS_NUM) {
            mach.status = MachineStatus.ERRORED;
            return;
        }
        if (!mod.moduleMemory.isValidLeaf(ptr)) {
            mach.status = MachineStatus.ERRORED;
            return;
        }

        uint256 leafIdx = ptr / LEAF_SIZE;
        uint256 proofOffset = 0;
        bytes32 startLeafContents;
        MerkleProof memory merkleProof;
        (startLeafContents, proofOffset, merkleProof) = mod.moduleMemory.proveLeaf(
            leafIdx,
            proof,
            proofOffset
        );

        if (inst.opcode == Instructions.GET_GLOBAL_STATE_BYTES32) {
            mod.moduleMemory.merkleRoot = merkleProof.computeRootFromMemory(
                leafIdx,
                state.bytes32Vals[idx]
            );
        } else if (inst.opcode == Instructions.SET_GLOBAL_STATE_BYTES32) {
            state.bytes32Vals[idx] = startLeafContents;
        } else {
            revert("BAD_GLOBAL_STATE_OPCODE");
        }
    }

    function executeGetU64(Machine memory mach, GlobalState memory state) internal pure {
        uint32 idx = mach.valueStack.pop().assumeI32();

        if (idx >= GlobalStateLib.U64_VALS_NUM) {
            mach.status = MachineStatus.ERRORED;
            return;
        }

        mach.valueStack.push(ValueLib.newI64(state.u64Vals[idx]));
    }

    function executeSetU64(Machine memory mach, GlobalState memory state) internal pure {
        uint64 val = mach.valueStack.pop().assumeI64();
        uint32 idx = mach.valueStack.pop().assumeI32();

        if (idx >= GlobalStateLib.U64_VALS_NUM) {
            mach.status = MachineStatus.ERRORED;
            return;
        }
        state.u64Vals[idx] = val;
    }

    uint256 internal constant BLS_MODULUS =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;
    uint256 internal constant PRIMITIVE_ROOT_OF_UNITY =
        10238227357739495823651030575849232062558860180284477541189508159991286009131;

    // Computes b**e % m
    // Really pure but the Solidity compiler sees the staticcall and requires view
    function modExp256(
        uint256 b,
        uint256 e,
        uint256 m
    ) internal view returns (uint256) {
        bytes memory modExpInput = abi.encode(32, 32, 32, b, e, m);
        (bool modexpSuccess, bytes memory modExpOutput) = address(0x05).staticcall(modExpInput);
        require(modexpSuccess, "MODEXP_FAILED");
        require(modExpOutput.length == 32, "MODEXP_WRONG_LENGTH");
        return uint256(bytes32(modExpOutput));
    }


    uint256 internal constant BN_254_PRIMITIVE_ROOT_OF_UNITY =
        19103219067921713944291392827692070036145651957329286315305642004821462161904;

    // see: https://github.com/Layr-Labs/eigenda/blob/master/disperser/apiserver/server.go#L35
    uint256 internal constant eigenDAMaxFieldElementsPerBlob = (2 * 1024 * 1024) / 32;

    function executeReadPreImage(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory mod,
        Instruction calldata inst,
        bytes calldata proof
    ) internal view {
        uint256 preimageOffset = mach.valueStack.pop().assumeI32();
        uint256 ptr = mach.valueStack.pop().assumeI32();
        if (preimageOffset % 32 != 0 || ptr + 32 > mod.moduleMemory.size || ptr % LEAF_SIZE != 0) {
            mach.status = MachineStatus.ERRORED;
            return;
        }

        uint256 leafIdx = ptr / LEAF_SIZE;
        uint256 proofOffset = 0;
        bytes32 leafContents;
        MerkleProof memory merkleProof;
        (leafContents, proofOffset, merkleProof) = mod.moduleMemory.proveLeaf(
            leafIdx,
            proof,
            proofOffset
        );

        bytes memory extracted;
        uint8 proofType = uint8(proof[proofOffset]);
        proofOffset++;
        // These values must be kept in sync with `arbitrator/arbutil/src/types.rs`
        // and `arbutil/preimage_type.go` (both in the nitro repo).
        if (inst.argumentData == 0) {
            // The machine is asking for a keccak256 preimage

            if (proofType == 0) {
                bytes calldata preimage = proof[proofOffset:];
                require(keccak256(preimage) == leafContents, "BAD_PREIMAGE");

                uint256 preimageEnd = preimageOffset + 32;
                if (preimageEnd > preimage.length) {
                    preimageEnd = preimage.length;
                }
                extracted = preimage[preimageOffset:preimageEnd];
            } else {
                // TODO: support proving via an authenticated contract
                revert("UNKNOWN_PREIMAGE_PROOF");
            }
        } else if (inst.argumentData == 1) {
            // The machine is asking for a sha2-256 preimage

            require(proofType == 0, "UNKNOWN_PREIMAGE_PROOF");
            bytes calldata preimage = proof[proofOffset:];
            require(sha256(preimage) == leafContents, "BAD_PREIMAGE");

            uint256 preimageEnd = preimageOffset + 32;
            if (preimageEnd > preimage.length) {
                preimageEnd = preimage.length;
            }
            extracted = preimage[preimageOffset:preimageEnd];
        } else if (inst.argumentData == 2) {
            // The machine is asking for an Ethereum versioned hash preimage

            require(proofType == 0, "UNKNOWN_PREIMAGE_PROOF");

            // kzgProof should be a valid input to the EIP-4844 point evaluation precompile at address 0x0A.
            // It should prove the preimageOffset/32'th word of the machine's requested KZG commitment.
            bytes calldata kzgProof = proof[proofOffset:];

            require(bytes32(kzgProof[:32]) == leafContents, "KZG_PROOF_WRONG_HASH");

            uint256 fieldElementsPerBlob;
            uint256 blsModulus;
            {
                (bool success, bytes memory kzgParams) = address(0x0A).staticcall(kzgProof);
                require(success, "INVALID_KZG_PROOF");
                require(kzgParams.length > 0, "KZG_PRECOMPILE_MISSING");
                (fieldElementsPerBlob, blsModulus) = abi.decode(kzgParams, (uint256, uint256));
            }

            // With a hardcoded PRIMITIVE_ROOT_OF_UNITY, we can only support this BLS modulus.
            // It may be worth in the future supporting arbitrary BLS moduli, but we would likely need to
            // validate a user-supplied root of unity.
            require(blsModulus == BLS_MODULUS, "UNKNOWN_BLS_MODULUS");

            // If preimageOffset is greater than or equal to the blob size, leave extracted empty and call it here.
            if (preimageOffset < fieldElementsPerBlob * 32) {
                // We need to compute what point the polynomial should be evaluated at to get the right part of the preimage.
                // KZG commitments use a bit reversal permutation to order the roots of unity.
                // To account for that, we reverse the bit order of the index.
                uint256 bitReversedIndex = 0;
                // preimageOffset was required to be 32 byte aligned above
                uint256 tmp = preimageOffset / 32;
                for (uint256 i = 1; i < fieldElementsPerBlob; i <<= 1) {
                    bitReversedIndex <<= 1;
                    if (tmp & 1 == 1) {
                        bitReversedIndex |= 1;
                    }
                    tmp >>= 1;
                }

                // First, we get the root of unity of order 2**fieldElementsPerBlob.
                // We start with a root of unity of order 2**32 and then raise it to
                // the power of (2**32)/fieldElementsPerBlob to get root of unity we need.
                uint256 rootOfUnityPower = (1 << 32) / fieldElementsPerBlob;
                // Then, we raise the root of unity to the power of bitReversedIndex,
                // to retrieve this word of the KZG commitment.
                rootOfUnityPower *= bitReversedIndex;
                // z is the point the polynomial is evaluated at to retrieve this word of data
                uint256 z = modExp256(PRIMITIVE_ROOT_OF_UNITY, rootOfUnityPower, blsModulus);
                require(bytes32(kzgProof[32:64]) == bytes32(z), "KZG_PROOF_WRONG_Z");

                extracted = kzgProof[64:96];
            }
        } else if (inst.argumentData == 3) {
            // The machine is asking for a EigenDA versioned hash preimage

            require(proofType == 0, "UNKNOWN_EIGENDA_PREIMAGE_PROOF");

            bytes calldata kzgProof = proof[proofOffset:];

            // NOTE we are expecting the following layout for our proof data, similar
            // to that expected for the point evaluation precompile
            // [:32] - versionhash (eigenlayer)
            // [32:64] - evaluation point
            // [64:96] - expected output
            // [96:224] - g2TauMinusG2z
            // [224:288] - kzg commitment (g1 point)
            // [288:352] - proof (g1 point)
            // [352:385] - preimage length
            
            // expect first 32 bytes of proof to be the expected version hash
            require(bytes32(kzgProof[:32]) == leafContents, "KZG_PROOF_WRONG_HASH");

            {
                
                uint256[2] memory kzgCommitment = [uint256(bytes32(kzgProof[224:256])), uint256(bytes32(kzgProof[256:288]))];
                uint256[4] memory alphaMinusG2 = [uint256(bytes32(kzgProof[96:128])), uint256(bytes32(kzgProof[128:160])), uint256(bytes32(kzgProof[160:192])), uint256(bytes32(kzgProof[192:224]))];
                uint256[2] memory proof = [uint256(bytes32(kzgProof[288:320])), uint256(bytes32(kzgProof[320:352]))];
                uint256 z = uint256(bytes32(kzgProof[32:64]));
                uint256 y = uint256(bytes32(kzgProof[64:96]));

                require(kzgCommitment[0] < BN254_FR_FIELD_MODULUS, "COMMIT_X_LARGER_THAN_FIELD");
                require(kzgCommitment[1] < BN254_FR_FIELD_MODULUS, "COMMIT_Y_LARGER_THAN_FIELD");

                require(proof[0] < BN254_FR_FIELD_MODULUS, "PROOF_X_LARGER_THAN_FIELD");
                require(proof[1] < BN254_FR_FIELD_MODULUS, "PROOF_Y_LARGER_THAN_FIELD");

                require(z < BN254_FR_FIELD_MODULUS, "Z_LARGER_THAN_FIELD");
                require(y < BN254_FR_FIELD_MODULUS, "Y_LARGER_THAN_FIELD");

                // must be valid proof
                require(VerifyKzgProofWithG1Equivalence(kzgCommitment, y, proof, z, alphaMinusG2), "INVALID_KZG_PROOF");
            }

            // read the preimage length
            uint256 preimageLength = uint256(bytes32(kzgProof[352:384]));

            // If preimageOffset is greater than or equal to the blob size, leave extracted empty and call it here.
            if (preimageOffset < preimageLength) {
                // preimageOffset was required to be 32 byte aligned above
                uint256 tmp = preimageOffset / 32;
                                // First, we get the root of unity of order 2**fieldElementsPerBlob.
                // We start with a root of unity of order 2**32 and then raise it to
                // the power of (2**32)/fieldElementsPerBlob to get root of unity we need.
                uint256 rootOfUnityPower = (1 << 28) / preimageLength * 32;
                // Then, we raise the root of unity to the power of bitReversedIndex,
                // to retrieve this word of the KZG commitment.
                rootOfUnityPower *= tmp;
                // z is the point the polynomial is evaluated at to retrieve this word of data
                uint256 z = modExp256(BN_254_PRIMITIVE_ROOT_OF_UNITY, rootOfUnityPower, BN254.FR_MODULUS);
                require(bytes32(kzgProof[32:64]) == bytes32(z), "KZG_PROOF_WRONG_Z");

                extracted = kzgProof[64:96];
            }

        } else {
            revert("UNKNOWN_PREIMAGE_TYPE");
        }

        for (uint256 i = 0; i < extracted.length; i++) {
            leafContents = setLeafByte(leafContents, i, uint8(extracted[i]));
        }

        mod.moduleMemory.merkleRoot = merkleProof.computeRootFromMemory(leafIdx, leafContents);

        mach.valueStack.push(ValueLib.newI32(uint32(extracted.length)));
    }

    function validateSequencerInbox(
        ExecutionContext calldata execCtx,
        uint64 msgIndex,
        bytes calldata message
    ) internal view returns (bool) {
        require(message.length >= INBOX_HEADER_LEN, "BAD_SEQINBOX_PROOF");

        uint64 afterDelayedMsg;
        (afterDelayedMsg, ) = Deserialize.u64(message, 32);
        bytes32 messageHash = keccak256(message);
        bytes32 beforeAcc;
        bytes32 delayedAcc;

        if (msgIndex > 0) {
            beforeAcc = execCtx.bridge.sequencerInboxAccs(msgIndex - 1);
        }
        if (afterDelayedMsg > 0) {
            delayedAcc = execCtx.bridge.delayedInboxAccs(afterDelayedMsg - 1);
        }
        bytes32 acc = keccak256(abi.encodePacked(beforeAcc, messageHash, delayedAcc));
        require(acc == execCtx.bridge.sequencerInboxAccs(msgIndex), "BAD_SEQINBOX_MESSAGE");
        return true;
    }

    function validateDelayedInbox(
        ExecutionContext calldata execCtx,
        uint64 msgIndex,
        bytes calldata message
    ) internal view returns (bool) {
        require(message.length >= DELAYED_HEADER_LEN, "BAD_DELAYED_PROOF");

        bytes32 beforeAcc;

        if (msgIndex > 0) {
            beforeAcc = execCtx.bridge.delayedInboxAccs(msgIndex - 1);
        }

        bytes32 messageDataHash = keccak256(message[DELAYED_HEADER_LEN:]);
        bytes1 kind = message[0];
        uint256 sender;
        (sender, ) = Deserialize.u256(message, 1);

        bytes32 messageHash = keccak256(
            abi.encodePacked(kind, uint160(sender), message[33:DELAYED_HEADER_LEN], messageDataHash)
        );
        bytes32 acc = Messages.accumulateInboxMessage(beforeAcc, messageHash);

        require(acc == execCtx.bridge.delayedInboxAccs(msgIndex), "BAD_DELAYED_MESSAGE");
        return true;
    }

    function executeReadInboxMessage(
        ExecutionContext calldata execCtx,
        Machine memory mach,
        Module memory mod,
        Instruction calldata inst,
        bytes calldata proof
    ) internal view {
        uint256 messageOffset = mach.valueStack.pop().assumeI32();
        uint256 ptr = mach.valueStack.pop().assumeI32();
        uint256 msgIndex = mach.valueStack.pop().assumeI64();
        if (
            inst.argumentData == Instructions.INBOX_INDEX_SEQUENCER &&
            msgIndex >= execCtx.maxInboxMessagesRead
        ) {
            mach.status = MachineStatus.TOO_FAR;
            return;
        }

        if (ptr + 32 > mod.moduleMemory.size || ptr % LEAF_SIZE != 0) {
            mach.status = MachineStatus.ERRORED;
            return;
        }

        uint256 leafIdx = ptr / LEAF_SIZE;
        uint256 proofOffset = 0;
        bytes32 leafContents;
        MerkleProof memory merkleProof;
        (leafContents, proofOffset, merkleProof) = mod.moduleMemory.proveLeaf(
            leafIdx,
            proof,
            proofOffset
        );

        {
            // TODO: support proving via an authenticated contract
            require(proof[proofOffset] == 0, "UNKNOWN_INBOX_PROOF");
            proofOffset++;

            function(ExecutionContext calldata, uint64, bytes calldata)
                internal
                view
                returns (bool) inboxValidate;

            bool success;
            if (inst.argumentData == Instructions.INBOX_INDEX_SEQUENCER) {
                inboxValidate = validateSequencerInbox;
            } else if (inst.argumentData == Instructions.INBOX_INDEX_DELAYED) {
                inboxValidate = validateDelayedInbox;
            } else {
                mach.status = MachineStatus.ERRORED;
                return;
            }
            success = inboxValidate(execCtx, uint64(msgIndex), proof[proofOffset:]);
            if (!success) {
                mach.status = MachineStatus.ERRORED;
                return;
            }
        }

        require(proof.length >= proofOffset, "BAD_MESSAGE_PROOF");
        uint256 messageLength = proof.length - proofOffset;

        uint32 i = 0;
        for (; i < 32 && messageOffset + i < messageLength; i++) {
            leafContents = setLeafByte(
                leafContents,
                i,
                uint8(proof[proofOffset + messageOffset + i])
            );
        }

        mod.moduleMemory.merkleRoot = merkleProof.computeRootFromMemory(leafIdx, leafContents);
        mach.valueStack.push(ValueLib.newI32(i));
    }

    function executeHaltAndSetFinished(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory,
        Instruction calldata,
        bytes calldata
    ) internal pure {
        mach.status = MachineStatus.FINISHED;
    }

    function isPowerOfTwo(uint256 value) internal pure returns (bool) {
        return value != 0 && (value & (value - 1) == 0);
    }

    function proveLastLeaf(
        Machine memory mach,
        uint256 offset,
        bytes calldata proof
    )
        internal
        pure
        returns (
            uint256 leaf,
            MerkleProof memory leafProof,
            MerkleProof memory zeroProof
        )
    {
        string memory prefix = "Module merkle tree:";
        bytes32 root = mach.modulesRoot;

        {
            Module memory leafModule;
            uint32 leaf32;
            (leafModule, offset) = Deserialize.module(proof, offset);
            (leaf32, offset) = Deserialize.u32(proof, offset);
            (leafProof, offset) = Deserialize.merkleProof(proof, offset);
            leaf = uint256(leaf32);

            bytes32 compRoot = leafProof.computeRootFromModule(leaf, leafModule);
            require(compRoot == root, "WRONG_ROOT_FOR_LEAF");
        }

        // if tree is unbalanced, check that the next leaf is 0
        bool balanced = isPowerOfTwo(leaf + 1);
        if (balanced) {
            require(1 << leafProof.counterparts.length == leaf + 1, "WRONG_LEAF");
        } else {
            (zeroProof, offset) = Deserialize.merkleProof(proof, offset);
            bytes32 compRoot = zeroProof.computeRootUnsafe(leaf + 1, 0, prefix);
            require(compRoot == root, "WRONG_ROOT_FOR_ZERO");
        }

        return (leaf, leafProof, zeroProof);
    }

    function executeLinkModule(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory mod,
        Instruction calldata,
        bytes calldata proof
    ) internal pure {
        string memory prefix = "Module merkle tree:";
        bytes32 root = mach.modulesRoot;

        uint256 pointer = mach.valueStack.pop().assumeI32();
        if (!mod.moduleMemory.isValidLeaf(pointer)) {
            mach.status = MachineStatus.ERRORED;
            return;
        }
        (bytes32 userMod, uint256 offset, ) = mod.moduleMemory.proveLeaf(
            pointer / LEAF_SIZE,
            proof,
            0
        );

        (uint256 leaf, , MerkleProof memory zeroProof) = proveLastLeaf(mach, offset, proof);

        bool balanced = isPowerOfTwo(leaf + 1);
        if (balanced) {
            mach.modulesRoot = MerkleProofLib.growToNewRoot(root, leaf + 1, userMod, 0, prefix);
        } else {
            mach.modulesRoot = zeroProof.computeRootUnsafe(leaf + 1, userMod, prefix);
        }

        mach.valueStack.push(ValueLib.newI32(uint32(leaf + 1)));
    }

    function executeUnlinkModule(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory,
        Instruction calldata,
        bytes calldata proof
    ) internal pure {
        string memory prefix = "Module merkle tree:";

        (uint256 leaf, MerkleProof memory leafProof, ) = proveLastLeaf(mach, 0, proof);

        bool shrink = isPowerOfTwo(leaf);
        if (shrink) {
            mach.modulesRoot = leafProof.counterparts[leafProof.counterparts.length - 1];
        } else {
            mach.modulesRoot = leafProof.computeRootUnsafe(leaf, 0, prefix);
        }
    }

    function executeGlobalStateAccess(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory mod,
        Instruction calldata inst,
        bytes calldata proof
    ) internal pure {
        uint16 opcode = inst.opcode;

        GlobalState memory state;
        uint256 proofOffset = 0;
        (state, proofOffset) = Deserialize.globalState(proof, proofOffset);
        require(state.hash() == mach.globalStateHash, "BAD_GLOBAL_STATE");

        if (
            opcode == Instructions.GET_GLOBAL_STATE_BYTES32 ||
            opcode == Instructions.SET_GLOBAL_STATE_BYTES32
        ) {
            executeGetOrSetBytes32(mach, mod, state, inst, proof[proofOffset:]);
        } else if (opcode == Instructions.GET_GLOBAL_STATE_U64) {
            executeGetU64(mach, state);
        } else if (opcode == Instructions.SET_GLOBAL_STATE_U64) {
            executeSetU64(mach, state);
        } else {
            revert("INVALID_GLOBALSTATE_OPCODE");
        }

        mach.globalStateHash = state.hash();
    }

    function executeNewCoThread(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory,
        Instruction calldata,
        bytes calldata
    ) internal pure {
        if (mach.recoveryPc != MachineLib.NO_RECOVERY_PC) {
            // cannot create new cothread from inside cothread
            mach.status = MachineStatus.ERRORED;
            return;
        }
        mach.frameMultiStack.pushNew();
        mach.valueMultiStack.pushNew();
    }

    function provePopCothread(MultiStack memory multi, bytes calldata proof) internal pure {
        uint256 proofOffset = 0;
        bytes32 newInactiveCoThread;
        bytes32 newRemaining;
        (newInactiveCoThread, proofOffset) = Deserialize.b32(proof, proofOffset);
        (newRemaining, proofOffset) = Deserialize.b32(proof, proofOffset);
        if (newInactiveCoThread == MultiStackLib.NO_STACK_HASH) {
            require(newRemaining == bytes32(0), "WRONG_COTHREAD_EMPTY");
            require(multi.remainingHash == bytes32(0), "WRONG_COTHREAD_EMPTY");
        } else {
            require(
                keccak256(abi.encodePacked("cothread:", newInactiveCoThread, newRemaining)) ==
                    multi.remainingHash,
                "WRONG_COTHREAD_POP"
            );
        }
        multi.remainingHash = newRemaining;
        multi.inactiveStackHash = newInactiveCoThread;
    }

    function executePopCoThread(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory,
        Instruction calldata,
        bytes calldata proof
    ) internal pure {
        if (mach.recoveryPc != MachineLib.NO_RECOVERY_PC) {
            // cannot pop cothread from inside cothread
            mach.status = MachineStatus.ERRORED;
            return;
        }
        if (mach.frameMultiStack.inactiveStackHash == MultiStackLib.NO_STACK_HASH) {
            // cannot pop cothread if there isn't one
            mach.status = MachineStatus.ERRORED;
            return;
        }
        provePopCothread(mach.valueMultiStack, proof);
        provePopCothread(mach.frameMultiStack, proof[64:]);
    }

    function executeSwitchCoThread(
        ExecutionContext calldata,
        Machine memory mach,
        Module memory,
        Instruction calldata inst,
        bytes calldata
    ) internal pure {
        if (mach.frameMultiStack.inactiveStackHash == MultiStackLib.NO_STACK_HASH) {
            // cannot switch cothread if there isn't one
            mach.status = MachineStatus.ERRORED;
            return;
        }
        if (inst.argumentData == 0) {
            if (mach.recoveryPc == MachineLib.NO_RECOVERY_PC) {
                // switching to main thread, from main thread
                mach.status = MachineStatus.ERRORED;
                return;
            }
            mach.recoveryPc = MachineLib.NO_RECOVERY_PC;
        } else {
            if (mach.recoveryPc != MachineLib.NO_RECOVERY_PC) {
                // switching from cothread to cothread
                mach.status = MachineStatus.ERRORED;
                return;
            }
            mach.setRecoveryFromPc(uint32(inst.argumentData));
        }
        mach.switchCoThreadStacks();
    }

    function executeOneStep(
        ExecutionContext calldata execCtx,
        Machine calldata startMach,
        Module calldata startMod,
        Instruction calldata inst,
        bytes calldata proof
    ) external view override returns (Machine memory mach, Module memory mod) {
        mach = startMach;
        mod = startMod;

        uint16 opcode = inst.opcode;

        function(
            ExecutionContext calldata,
            Machine memory,
            Module memory,
            Instruction calldata,
            bytes calldata
        ) internal view impl;

        if (
            opcode >= Instructions.GET_GLOBAL_STATE_BYTES32 &&
            opcode <= Instructions.SET_GLOBAL_STATE_U64
        ) {
            impl = executeGlobalStateAccess;
        } else if (opcode == Instructions.READ_PRE_IMAGE) {
            impl = executeReadPreImage;
        } else if (opcode == Instructions.READ_INBOX_MESSAGE) {
            impl = executeReadInboxMessage;
        } else if (opcode == Instructions.HALT_AND_SET_FINISHED) {
            impl = executeHaltAndSetFinished;
        } else if (opcode == Instructions.LINK_MODULE) {
            impl = executeLinkModule;
        } else if (opcode == Instructions.UNLINK_MODULE) {
            impl = executeUnlinkModule;
        } else if (opcode == Instructions.NEW_COTHREAD) {
            impl = executeNewCoThread;
        } else if (opcode == Instructions.POP_COTHREAD) {
            impl = executePopCoThread;
        } else if (opcode == Instructions.SWITCH_COTHREAD) {
            impl = executeSwitchCoThread;
        } else {
            revert("INVALID_MEMORY_OPCODE");
        }

        impl(execCtx, mach, mod, inst, proof);
    }


    // G2_SRS_1

    //note might be useful to give back to the bn library
    uint256 internal constant G2Taux1 = 21039730876973405969844107393779063362038454413254731404052240341412356318284;
    uint256 internal constant G2Taux0 = 7912312892787135728292535536655271843828059318189722219035249994421084560563;
    uint256 internal constant G2Tauy1 = 7586489485579523767759120334904353546627445333297951253230866312564920951171;
    uint256 internal constant G2Tauy0 = 18697407556011630376420900106252341752488547575648825575049647403852275261247;

    function g2Tau() internal view returns (BN254.G2Point memory) {
        return BN254.G2Point({
            X: [G2Taux1, G2Taux0],
            Y: [G2Tauy1, G2Tauy0]
        });
    }
}
