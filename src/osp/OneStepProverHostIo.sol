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

    using BN254 for uint256[4];
    using BN254 for uint256[3];
    using BN254 for uint256[12];

    // AlphaG1
    // This is from the SRS points being used.
    // This is the point at index 1, since index 0 is the generator value of the G1 group.
    BN254.G1Point private ALPHA_G1 =
        BN254.G1Point(
            5421624913032980671919055010798735843841011930764711817607050648427876929258,
            12995821280260994872112541311010834261076556242291585164372488699033268245381
        );

    function computeGamma(
        uint256 z,
        uint256 y,
        uint256[2] memory p,
        uint256[4] memory alpha_minus_z_g2,
        uint256[2] memory proof,
        BN254.G1Point memory alpha_minus_z_g1
    ) internal pure returns (uint256) {
        // Encode the variables and compute the keccak256 hash
        bytes32 hash = keccak256(
            abi.encodePacked(
                z,
                y,
                p[0],
                p[1],
                alpha_minus_z_g2[0],
                alpha_minus_z_g2[1],
                alpha_minus_z_g2[2],
                alpha_minus_z_g2[3],
                proof[0],
                proof[1],
                alpha_minus_z_g1.X,
                alpha_minus_z_g1.Y
            )
        );
        return uint256(hash) % BN254.FR_MODULUS;
    }

    //  e((P - y) + gamma . (alpha - z), G2) = e((Q + gamma), (alpha - z))
    function VerifyKzgProofWithG1Equivalence(
        uint256[2] memory commitment,
        uint256 y,
        uint256[2] memory proof,
        uint256 z,
        uint256[4] memory alpha_minus_z_g2
    ) public view returns (bool) {
        BN254.G1Point memory yG1Neg = BN254.negate(BN254.scalar_mul(BN254.generatorG1(), y));
        BN254.G1Point memory P_minus_y = BN254.plus(
            BN254.G1Point(commitment[0], commitment[1]),
            yG1Neg
        );

        // zG1
        BN254.G1Point memory zG1Neg = BN254.negate(BN254.scalar_mul(BN254.generatorG1(), z));

        // (alphaG1 - zG1)
        BN254.G1Point memory alpha_minus_z_g1 = BN254.plus(ALPHA_G1, zG1Neg);

        // gamma
        uint256 gamma = computeGamma(z, y, commitment, alpha_minus_z_g2, proof, alpha_minus_z_g1);

        // gamma . (alpha - z)G1
        BN254.G1Point memory gamma_alpha_minus_z_g1 = BN254.scalar_mul(alpha_minus_z_g1, gamma);

        // gammaG1
        BN254.G1Point memory gammaG1 = BN254.scalar_mul(BN254.generatorG1(), gamma);

        // Q + gamma
        BN254.G1Point memory q_plus_gamma = BN254.plus(BN254.G1Point(proof[0], proof[1]), gammaG1);
        BN254.G1Point memory lhsG1 = BN254.plus(P_minus_y, gamma_alpha_minus_z_g1);
        // The order is switched in the arbitrator already. It is passed as x_c1, x_c0, y_c1, y_c0
        BN254.G2Point memory alpha_minus_z_g2_point = BN254.G2Point(
            [alpha_minus_z_g2[0], alpha_minus_z_g2[1]],
            [alpha_minus_z_g2[2], alpha_minus_z_g2[3]]
        );
        return BN254.pairing(lhsG1, BN254.negGeneratorG2(), q_plus_gamma, alpha_minus_z_g2_point);
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
            // [:32] - hash (eigenlayer) (not versioned like 4844)
            // [32:64] - evaluation point
            // [64:96] - expected output
            // [96:224] - g2TauMinusG2z
            // [224:288] - kzg commitment (g1 point)
            // [288:352] - proof (g1 point)
            // [352:385] - preimage length

            {
                uint256[2] memory kzgCommitment = [
                    uint256(bytes32(kzgProof[224:256])),
                    uint256(bytes32(kzgProof[256:288]))
                ];
                uint256[4] memory alphaMinusG2 = [
                    uint256(bytes32(kzgProof[96:128])),
                    uint256(bytes32(kzgProof[128:160])),
                    uint256(bytes32(kzgProof[160:192])),
                    uint256(bytes32(kzgProof[192:224]))
                ];
                uint256[2] memory proofUint256 = [
                    uint256(bytes32(kzgProof[288:320])),
                    uint256(bytes32(kzgProof[320:352]))
                ];
                uint256 z = uint256(bytes32(kzgProof[32:64]));
                uint256 y = uint256(bytes32(kzgProof[64:96]));
                uint256 length = uint32(uint256(bytes32(kzgProof[352:384])));
                uint32 length_u32 = uint32(length);

                require(kzgCommitment[0] < BN254.FP_MODULUS, "COMMIT_X_LARGER_THAN_FIELD");
                require(kzgCommitment[1] < BN254.FP_MODULUS, "COMMIT_Y_LARGER_THAN_FIELD");

                require(proofUint256[0] < BN254.FP_MODULUS, "PROOF_X_LARGER_THAN_FIELD");
                require(proofUint256[1] < BN254.FP_MODULUS, "PROOF_Y_LARGER_THAN_FIELD");

                require(z < BN254.FR_MODULUS, "Z_LARGER_THAN_FIELD");
                require(y < BN254.FR_MODULUS, "Y_LARGER_THAN_FIELD");

                require(
                    keccak256(abi.encodePacked(kzgProof[224:288], length_u32)) == leafContents,
                    "BN254_KZG_PROOF_WRONG_HASH"
                );

                // must be valid proof
                require(
                    VerifyKzgProofWithG1Equivalence(
                        kzgCommitment,
                        y,
                        proofUint256,
                        z,
                        alphaMinusG2
                    ),
                    "INVALID_BN254_KZG_PROOF"
                );
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
                uint256 rootOfUnityPower = ((1 << 28) / preimageLength) * 32;
                // Then, we raise the root of unity to the power of bitReversedIndex,
                // to retrieve this word of the KZG commitment.
                rootOfUnityPower *= tmp;
                // z is the point the polynomial is evaluated at to retrieve this word of data
                uint256 z = modExp256(
                    BN_254_PRIMITIVE_ROOT_OF_UNITY,
                    rootOfUnityPower,
                    BN254.FR_MODULUS
                );
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
    uint256 internal constant G2Taux1 =
        21039730876973405969844107393779063362038454413254731404052240341412356318284;
    uint256 internal constant G2Taux0 =
        7912312892787135728292535536655271843828059318189722219035249994421084560563;
    uint256 internal constant G2Tauy1 =
        7586489485579523767759120334904353546627445333297951253230866312564920951171;
    uint256 internal constant G2Tauy0 =
        18697407556011630376420900106252341752488547575648825575049647403852275261247;

    function g2Tau() internal pure returns (BN254.G2Point memory) {
        return BN254.G2Point({X: [G2Taux1, G2Taux0], Y: [G2Tauy1, G2Tauy0]});
    }
}
