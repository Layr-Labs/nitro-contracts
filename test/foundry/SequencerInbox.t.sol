// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "./util/TestUtil.sol";
import "../../src/bridge/Bridge.sol";
import "../../src/bridge/SequencerInbox.sol";
import {ERC20Bridge} from "../../src/bridge/ERC20Bridge.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol";

import "../../src/bridge/EigenDABlobVerifierL2.sol";
import {BN254} from "@eigenda/eigenda-utils/libraries/BN254.sol";

contract RollupMock {
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }
}

contract SequencerInboxTest is Test {
    // cannot reference events outside of the original contract until 0.8.21
    // we currently use 0.8.9
    event MessageDelivered(
        uint256 indexed messageIndex,
        bytes32 indexed beforeInboxAcc,
        address inbox,
        uint8 kind,
        address sender,
        bytes32 messageDataHash,
        uint256 baseFeeL1,
        uint64 timestamp
    );
    event InboxMessageDelivered(uint256 indexed messageNum, bytes data);
    event SequencerBatchDelivered(
        uint256 indexed batchSequenceNumber,
        bytes32 indexed beforeAcc,
        bytes32 indexed afterAcc,
        bytes32 delayedAcc,
        uint256 afterDelayedMessagesRead,
        IBridge.TimeBounds timeBounds,
        IBridge.BatchDataLocation dataLocation
    );

    Random RAND = new Random();
    address rollupOwner = address(137);
    uint256 maxDataSize = 10_000;
    ISequencerInbox.MaxTimeVariation maxTimeVariation =
        ISequencerInbox.MaxTimeVariation({
            delayBlocks: 10,
            futureBlocks: 10,
            delaySeconds: 100,
            futureSeconds: 100
        });
    address dummyInbox = address(139);
    address proxyAdmin = address(140);
    IReader4844 dummyReader4844 = IReader4844(address(137));
    IEigenDAServiceManager dummyEigenDAServiceManager = IEigenDAServiceManager(address(138));
    IRollupManager rollupManager = IRollupManager(address(139));

    uint256 public constant MAX_DATA_SIZE = 117_964;

    function deployRollup(bool isArbHosted) internal returns (SequencerInbox, Bridge) {
        RollupMock rollupMock = new RollupMock(rollupOwner);
        Bridge bridgeImpl = new Bridge();
        Bridge bridge = Bridge(
            address(new TransparentUpgradeableProxy(address(bridgeImpl), proxyAdmin, ""))
        );

        bridge.initialize(IOwnable(address(rollupMock)));
        vm.prank(rollupOwner);
        bridge.setDelayedInbox(dummyInbox, true);

        SequencerInbox seqInboxImpl = new SequencerInbox(
            maxDataSize,
            isArbHosted ? IReader4844(address(0)) : dummyReader4844,
            false
        );
        SequencerInbox seqInbox = SequencerInbox(
            address(new TransparentUpgradeableProxy(address(seqInboxImpl), proxyAdmin, ""))
        );
        seqInbox.initialize(bridge, maxTimeVariation);

        vm.prank(rollupOwner);
        seqInbox.setIsBatchPoster(tx.origin, true);

        vm.prank(rollupOwner);
        bridge.setSequencerInbox(address(seqInbox));

        return (seqInbox, bridge);
    }

    function deployFeeTokenBasedRollup() internal returns (SequencerInbox, ERC20Bridge) {
        RollupMock rollupMock = new RollupMock(rollupOwner);
        ERC20Bridge bridgeImpl = new ERC20Bridge();
        ERC20Bridge bridge = ERC20Bridge(
            address(new TransparentUpgradeableProxy(address(bridgeImpl), proxyAdmin, ""))
        );
        address nativeToken = address(new ERC20PresetMinterPauser("Appchain Token", "App"));

        bridge.initialize(IOwnable(address(rollupMock)), nativeToken);
        vm.prank(rollupOwner);
        bridge.setDelayedInbox(dummyInbox, true);

        /// this will result in 'hostChainIsArbitrum = true'
        vm.mockCall(
            address(100),
            abi.encodeWithSelector(ArbSys.arbOSVersion.selector),
            abi.encode(uint256(11))
        );
        SequencerInbox seqInboxImpl = new SequencerInbox(
            maxDataSize,
            IReader4844(address(0)),
            true
        );
        SequencerInbox seqInbox = SequencerInbox(
            address(new TransparentUpgradeableProxy(address(seqInboxImpl), proxyAdmin, ""))
        );
        seqInbox.initialize(bridge, maxTimeVariation);

        vm.prank(rollupOwner);
        seqInbox.setIsBatchPoster(tx.origin, true);

        vm.prank(rollupOwner);
        bridge.setSequencerInbox(address(seqInbox));

        return (seqInbox, bridge);
    }

    // Split the logic that deals with calculating and emitting the spending report into a separate function because of stack too deep limits
    function _handleSpendingReport(
        IBridge bridge,
        SequencerInbox seqInbox,
        uint256 delayedMessagesRead,
        bytes32 dataHash,
        uint256 sequenceNumber,
        bool hostChainIsArbitrum
    ) internal {
        if (!hostChainIsArbitrum) return; // If not Arbitrum, no need to process this part

        // set 0.1 gwei basefee
        uint256 basefee = 100_000_000;
        vm.fee(basefee);
        // 30 gwei TX L1 fees
        uint256 l1Fees = 30_000_000_000;
        vm.mockCall(
            address(0x6c),
            abi.encodeWithSignature("getCurrentTxL1GasFees()"),
            abi.encode(l1Fees)
        );
        uint256 expectedReportedExtraGas = l1Fees / basefee;

        bytes memory spendingReportMsg = abi.encodePacked(
            block.timestamp,
            msg.sender,
            dataHash,
            sequenceNumber,
            block.basefee,
            uint64(expectedReportedExtraGas)
        );

        // spending report
        vm.expectEmit();
        emit MessageDelivered(
            delayedMessagesRead,
            bridge.delayedInboxAccs(delayedMessagesRead - 1), // directly use the call here to reduce a variable
            address(seqInbox),
            L1MessageType_batchPostingReport,
            tx.origin,
            keccak256(spendingReportMsg),
            block.basefee,
            uint64(block.timestamp)
        );

        // spending report event in seq inbox
        vm.expectEmit();
        emit InboxMessageDelivered(delayedMessagesRead, spendingReportMsg);
    }

    function expectEvents(
        IBridge bridge,
        SequencerInbox seqInbox,
        bytes memory data,
        bool hostChainIsArbitrum,
        bool isUsingFeeToken,
        bool isUsingEigenDA
    ) internal {
        uint256 delayedMessagesRead = bridge.delayedMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();

        IBridge.TimeBounds memory timeBounds;
        if (block.timestamp > maxTimeVariation.delaySeconds) {
            timeBounds.minTimestamp = uint64(block.timestamp - maxTimeVariation.delaySeconds);
        }
        timeBounds.maxTimestamp = uint64(block.timestamp + maxTimeVariation.futureSeconds);
        if (block.number > maxTimeVariation.delayBlocks) {
            timeBounds.minBlockNumber = uint64(block.number - maxTimeVariation.delayBlocks);
        }
        timeBounds.maxBlockNumber = uint64(block.number + maxTimeVariation.futureBlocks);

        bytes32 dataHash;

        if (isUsingEigenDA) {
            dataHash = keccak256(
                bytes.concat(
                    abi.encodePacked(
                        timeBounds.minTimestamp,
                        timeBounds.maxTimestamp,
                        timeBounds.minBlockNumber,
                        timeBounds.maxBlockNumber,
                        uint64(delayedMessagesRead)
                    ),
                    data
                )
            );
        } else {
            dataHash = keccak256(
                bytes.concat(
                    abi.encodePacked(
                        timeBounds.minTimestamp,
                        timeBounds.maxTimestamp,
                        timeBounds.minBlockNumber,
                        timeBounds.maxBlockNumber,
                        uint64(delayedMessagesRead)
                    ),
                    data
                )
            );
        }

        bytes32 beforeAcc = bytes32(0);
        bytes32 delayedAcc = bridge.delayedInboxAccs(delayedMessagesRead - 1);
        bytes32 afterAcc = keccak256(abi.encodePacked(beforeAcc, dataHash, delayedAcc));

        if (!isUsingFeeToken && !isUsingEigenDA) {
            _handleSpendingReport(
                bridge,
                seqInbox,
                delayedMessagesRead,
                dataHash,
                sequenceNumber,
                hostChainIsArbitrum
            );
        }

        // sequencer batch delivered

        vm.expectEmit();
        emit SequencerBatchDelivered(
            sequenceNumber,
            beforeAcc,
            afterAcc,
            delayedAcc,
            delayedMessagesRead,
            timeBounds,
            !isUsingEigenDA ? IBridge.BatchDataLocation.TxInput : IBridge.BatchDataLocation.EigenDA
        );
    }

    bytes invalidHeaderData =
        hex"ab4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a";

    function testAddSequencerL2BatchFromOrigin_InvalidHeader() public {
        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(false);
        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        bytes memory data = invalidHeaderData; // ab is not any valid header flag

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        // set 60 gwei basefee
        uint256 basefee = 60000000000;
        vm.fee(basefee);

        vm.prank(tx.origin);
        vm.expectRevert(
            abi.encodeWithSignature(
                "InvalidHeaderFlag(bytes1)",
                0xab00000000000000000000000000000000000000000000000000000000000000
            )
        );
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            data,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );
    }

    bytes biggerData =
        hex"00a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890";

    function testAddSequencerL2BatchFromOrigin() public {
        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(false);
        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        bytes memory data = biggerData; // 00 is BROTLI_MESSAGE_HEADER_FLAG

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        // set 60 gwei basefee
        uint256 basefee = 60_000_000_000;
        vm.fee(basefee);
        expectEvents(bridge, seqInbox, data, false, false, false);

        vm.prank(tx.origin);
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            data,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );
    }

    /* solhint-disable func-name-mixedcase */
    function testConstructor() public {
        SequencerInbox seqInboxLogic = new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, false);
        assertEq(seqInboxLogic.maxDataSize(), MAX_DATA_SIZE, "Invalid MAX_DATA_SIZE");
        assertEq(seqInboxLogic.isUsingFeeToken(), false, "Invalid isUsingFeeToken");

        SequencerInbox seqInboxProxy = SequencerInbox(TestUtil.deployProxy(address(seqInboxLogic)));
        assertEq(seqInboxProxy.maxDataSize(), MAX_DATA_SIZE, "Invalid MAX_DATA_SIZE");
        assertEq(seqInboxProxy.isUsingFeeToken(), false, "Invalid isUsingFeeToken");

        SequencerInbox seqInboxLogicFeeToken = new SequencerInbox(
            MAX_DATA_SIZE,
            dummyReader4844,
            true
        );
        assertEq(seqInboxLogicFeeToken.maxDataSize(), MAX_DATA_SIZE, "Invalid MAX_DATA_SIZE");
        assertEq(seqInboxLogicFeeToken.isUsingFeeToken(), true, "Invalid isUsingFeeToken");

        SequencerInbox seqInboxProxyFeeToken = SequencerInbox(
            TestUtil.deployProxy(address(seqInboxLogicFeeToken))
        );
        assertEq(seqInboxProxyFeeToken.maxDataSize(), MAX_DATA_SIZE, "Invalid MAX_DATA_SIZE");
        assertEq(seqInboxProxyFeeToken.isUsingFeeToken(), true, "Invalid isUsingFeeToken");
    }

    function testInitialize() public {
        Bridge _bridge = Bridge(
            address(new TransparentUpgradeableProxy(address(new Bridge()), proxyAdmin, ""))
        );
        _bridge.initialize(IOwnable(address(new RollupMock(rollupOwner))));

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, false));
        SequencerInbox seqInboxProxy = SequencerInbox(TestUtil.deployProxy(seqInboxLogic));
        seqInboxProxy.initialize(IBridge(_bridge), maxTimeVariation);

        assertEq(seqInboxProxy.isUsingFeeToken(), false, "Invalid isUsingFeeToken");
        assertEq(address(seqInboxProxy.bridge()), address(_bridge), "Invalid bridge");
        assertEq(address(seqInboxProxy.rollup()), address(_bridge.rollup()), "Invalid rollup");
    }

    function testInitialize_FeeTokenBased() public {
        ERC20Bridge _bridge = ERC20Bridge(
            address(new TransparentUpgradeableProxy(address(new ERC20Bridge()), proxyAdmin, ""))
        );
        address nativeToken = address(new ERC20PresetMinterPauser("Appchain Token", "App"));
        _bridge.initialize(IOwnable(address(new RollupMock(rollupOwner))), nativeToken);

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, true));
        SequencerInbox seqInboxProxy = SequencerInbox(TestUtil.deployProxy(seqInboxLogic));
        seqInboxProxy.initialize(IBridge(_bridge), maxTimeVariation);

        assertEq(seqInboxProxy.isUsingFeeToken(), true, "Invalid isUsingFeeToken");
        assertEq(address(seqInboxProxy.bridge()), address(_bridge), "Invalid bridge");
        assertEq(address(seqInboxProxy.rollup()), address(_bridge.rollup()), "Invalid rollup");
    }

    function testInitialize_revert_NativeTokenMismatch_EthFeeToken() public {
        Bridge _bridge = Bridge(
            address(new TransparentUpgradeableProxy(address(new Bridge()), proxyAdmin, ""))
        );
        _bridge.initialize(IOwnable(address(new RollupMock(rollupOwner))));

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, true));
        SequencerInbox seqInboxProxy = SequencerInbox(TestUtil.deployProxy(seqInboxLogic));

        vm.expectRevert(abi.encodeWithSelector(NativeTokenMismatch.selector));
        seqInboxProxy.initialize(IBridge(_bridge), maxTimeVariation);
    }

    function testInitialize_revert_NativeTokenMismatch_FeeTokenEth() public {
        ERC20Bridge _bridge = ERC20Bridge(
            address(new TransparentUpgradeableProxy(address(new ERC20Bridge()), proxyAdmin, ""))
        );
        address nativeToken = address(new ERC20PresetMinterPauser("Appchain Token", "App"));
        _bridge.initialize(IOwnable(address(new RollupMock(rollupOwner))), nativeToken);

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, false));
        SequencerInbox seqInboxProxy = SequencerInbox(TestUtil.deployProxy(seqInboxLogic));

        vm.expectRevert(abi.encodeWithSelector(NativeTokenMismatch.selector));
        seqInboxProxy.initialize(IBridge(_bridge), maxTimeVariation);
    }

    function testAddSequencerL2BatchFromOrigin_ArbitrumHosted() public {
        // this will result in 'hostChainIsArbitrum = true'
        vm.mockCall(
            address(100),
            abi.encodeWithSelector(ArbSys.arbOSVersion.selector),
            abi.encode(uint256(11))
        );
        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(true);

        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        bytes memory data = hex"00567890";

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        expectEvents(bridge, seqInbox, data, true, false, false);

        vm.prank(tx.origin);
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            data,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );
    }

    function testAddSequencerL2BatchFromOrigin_ArbitrumHostedFeeTokenBased() public {
        (SequencerInbox seqInbox, ERC20Bridge bridge) = deployFeeTokenBasedRollup();
        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        bytes memory data = hex"80567890";

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash, 0);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        // set 40 gwei basefee
        uint256 basefee = 40_000_000_000;
        vm.fee(basefee);

        expectEvents(IBridge(address(bridge)), seqInbox, data, true, true, false);

        vm.prank(tx.origin);
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            data,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );
    }

    function testAddSequencerL2BatchFromOriginReverts() public {
        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(false);
        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        bytes memory data = biggerData; // 00 is BROTLI_MESSAGE_HEADER_FLAG

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        vm.expectRevert(abi.encodeWithSelector(NotOrigin.selector));
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            data,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );

        vm.prank(rollupOwner);
        seqInbox.setIsBatchPoster(tx.origin, false);

        vm.expectRevert(abi.encodeWithSelector(NotBatchPoster.selector));
        vm.prank(tx.origin);
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            data,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );

        vm.prank(rollupOwner);
        seqInbox.setIsBatchPoster(tx.origin, true);

        bytes memory bigData = bytes.concat(
            seqInbox.BROTLI_MESSAGE_HEADER_FLAG(),
            RAND.Bytes(maxDataSize - seqInbox.HEADER_LENGTH())
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                DataTooLarge.selector,
                bigData.length + seqInbox.HEADER_LENGTH(),
                maxDataSize
            )
        );
        vm.prank(tx.origin);
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            bigData,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );

        bytes memory authenticatedData = bytes.concat(seqInbox.DATA_BLOB_HEADER_FLAG(), data);
        vm.expectRevert(abi.encodeWithSelector(InvalidHeaderFlag.selector, authenticatedData[0]));
        vm.prank(tx.origin);
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber,
            authenticatedData,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );

        vm.expectRevert(
            abi.encodeWithSelector(BadSequencerNumber.selector, sequenceNumber, sequenceNumber + 5)
        );
        vm.prank(tx.origin);
        seqInbox.addSequencerL2BatchFromOrigin(
            sequenceNumber + 5,
            data,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1
        );
    }

    function testAddSequencerL2BatchFromEigenDA() public {
        EigenDABlobVerifierL2 rollupManagerImpl = new EigenDABlobVerifierL2();
        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(false);
        // update the dummyEigenDAServiceManager to use the holesky serviceManager contract

        vm.startPrank(rollupOwner);
        // deploy rollup
        seqInbox.setEigenDARollupManager(address(rollupManagerImpl));
        vm.stopPrank();

        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);

        (
            IEigenDAServiceManager.BlobHeader memory blobHeader,
            EigenDARollupUtils.BlobVerificationProof memory blobVerificationProof
        ) = readAndParseBlobInfo();
        ISequencerInbox.EigenDACert memory cert = ISequencerInbox.EigenDACert({
            blobHeader: blobHeader,
            blobVerificationProof: blobVerificationProof
        });

        bytes memory data = bytes.concat(hex"ed", abi.encode(cert));

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        expectEvents(bridge, seqInbox, data, false, false, true);

        vm.prank(tx.origin);

        seqInbox.addSequencerL2BatchFromEigenDA(
            sequenceNumber,
            cert,
            IGasRefunder(address(0)),
            delayedMessagesRead,
            subMessageCount,
            subMessageCount + 1
        );
    }

    // TODO: put these in jsons later
    // create illegal commitment
    BN254.G1Point illegalCommitment =
        BN254.G1Point({
            X: 11151623676041303181597631684634074376466382703418354161831688442589830350329,
            Y: 4222041728992406478862708226745479381252734858741080790666424175645694456140
        });

    IEigenDAServiceManager.BlobHeader illegalBlobHeader;

    IEigenDAServiceManager.BatchHeader illegalBatchHeader =
        IEigenDAServiceManager.BatchHeader({
            blobHeadersRoot: bytes32(0),
            quorumNumbers: bytes(""),
            signedStakeForQuorums: bytes(""),
            referenceBlockNumber: 1
        });

    IEigenDAServiceManager.BatchMetadata illegalBatchMetadata =
        IEigenDAServiceManager.BatchMetadata({
            batchHeader: illegalBatchHeader,
            signatoryRecordHash: bytes32(0),
            confirmationBlockNumber: 1
        });

    EigenDARollupUtils.BlobVerificationProof illegalBlobVerificationProof =
        EigenDARollupUtils.BlobVerificationProof({
            batchId: 1,
            blobIndex: 1,
            batchMetadata: illegalBatchMetadata,
            inclusionProof: bytes(""),
            quorumIndices: bytes("")
        });

    function testAddSequencerL2BatchFrom() public {
        // finish filling out the illegalBlobHeader
        illegalBlobHeader.commitment = illegalCommitment;
        illegalBlobHeader.dataLength = 20;
        illegalBlobHeader.quorumBlobParams.push(
            IEigenDAServiceManager.QuorumBlobParam({
                quorumNumber: uint8(1),
                adversaryThresholdPercentage: uint8(1),
                confirmationThresholdPercentage: uint8(1),
                chunkLength: uint32(1)
            })
        );

        ISequencerInbox.EigenDACert memory illegalCert = ISequencerInbox.EigenDACert({
            blobHeader: illegalBlobHeader,
            blobVerificationProof: illegalBlobVerificationProof
        });

        // change the eigenDAServiceManager to use the holesky testnet contract
        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(false);
        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        bytes memory data = biggerData; // 00 is BROTLI_MESSAGE_HEADER_FLAG

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        vm.prank(tx.origin);

        vm.expectRevert();
        seqInbox.addSequencerL2BatchFromEigenDA(
            sequenceNumber,
            illegalCert,
            IGasRefunder(address(0)),
            delayedMessagesRead,
            subMessageCount,
            subMessageCount + 1
        );
    }

    function testPostUpgradeInitAlreadyInit() public returns (SequencerInbox, SequencerInbox) {
        (SequencerInbox seqInbox, ) = deployRollup(false);
        SequencerInbox seqInboxImpl = new SequencerInbox(maxDataSize, dummyReader4844, false);

        vm.expectRevert(abi.encodeWithSelector(AlreadyInit.selector));
        vm.prank(proxyAdmin);
        TransparentUpgradeableProxy(payable(address(seqInbox))).upgradeToAndCall(
            address(seqInboxImpl),
            abi.encodeWithSelector(SequencerInbox.postUpgradeInit.selector)
        );
        return (seqInbox, seqInboxImpl);
    }

    function testPostUpgradeInit(
        uint64 delayBlocks,
        uint64 futureBlocks,
        uint64 delaySeconds,
        uint64 futureSeconds
    ) public {
        vm.assume(delayBlocks != 0 || futureBlocks != 0 || delaySeconds != 0 || futureSeconds != 0);

        (SequencerInbox seqInbox, SequencerInbox seqInboxImpl) = testPostUpgradeInitAlreadyInit();

        vm.expectRevert(abi.encodeWithSelector(AlreadyInit.selector));
        vm.prank(proxyAdmin);
        TransparentUpgradeableProxy(payable(address(seqInbox))).upgradeToAndCall(
            address(seqInboxImpl),
            abi.encodeWithSelector(SequencerInbox.postUpgradeInit.selector)
        );

        vm.store(address(seqInbox), bytes32(uint256(4)), bytes32(uint256(delayBlocks))); // slot 4: delayBlocks
        vm.store(address(seqInbox), bytes32(uint256(5)), bytes32(uint256(futureBlocks))); // slot 5: futureBlocks
        vm.store(address(seqInbox), bytes32(uint256(6)), bytes32(uint256(delaySeconds))); // slot 6: delaySeconds
        vm.store(address(seqInbox), bytes32(uint256(7)), bytes32(uint256(futureSeconds))); // slot 7: futureSeconds
        vm.prank(proxyAdmin);
        TransparentUpgradeableProxy(payable(address(seqInbox))).upgradeToAndCall(
            address(seqInboxImpl),
            abi.encodeWithSelector(SequencerInbox.postUpgradeInit.selector)
        );

        (
            uint256 delayBlocks_,
            uint256 futureBlocks_,
            uint256 delaySeconds_,
            uint256 futureSeconds_
        ) = seqInbox.maxTimeVariation();
        assertEq(delayBlocks_, delayBlocks);
        assertEq(futureBlocks_, futureBlocks);
        assertEq(delaySeconds_, delaySeconds);
        assertEq(futureSeconds_, futureSeconds);

        vm.expectRevert(abi.encodeWithSelector(AlreadyInit.selector));
        vm.prank(proxyAdmin);
        TransparentUpgradeableProxy(payable(address(seqInbox))).upgradeToAndCall(
            address(seqInboxImpl),
            abi.encodeWithSelector(SequencerInbox.postUpgradeInit.selector)
        );
    }

    function testPostUpgradeInitBadInit(
        uint256 delayBlocks,
        uint256 futureBlocks,
        uint256 delaySeconds,
        uint256 futureSeconds
    ) public {
        vm.assume(delayBlocks > uint256(type(uint64).max));
        vm.assume(futureBlocks > uint256(type(uint64).max));
        vm.assume(delaySeconds > uint256(type(uint64).max));
        vm.assume(futureSeconds > uint256(type(uint64).max));

        (SequencerInbox seqInbox, SequencerInbox seqInboxImpl) = testPostUpgradeInitAlreadyInit();

        vm.store(address(seqInbox), bytes32(uint256(4)), bytes32(delayBlocks)); // slot 4: delayBlocks
        vm.store(address(seqInbox), bytes32(uint256(5)), bytes32(futureBlocks)); // slot 5: futureBlocks
        vm.store(address(seqInbox), bytes32(uint256(6)), bytes32(delaySeconds)); // slot 6: delaySeconds
        vm.store(address(seqInbox), bytes32(uint256(7)), bytes32(futureSeconds)); // slot 7: futureSeconds
        vm.expectRevert(abi.encodeWithSelector(BadPostUpgradeInit.selector));
        vm.prank(proxyAdmin);
        TransparentUpgradeableProxy(payable(address(seqInbox))).upgradeToAndCall(
            address(seqInboxImpl),
            abi.encodeWithSelector(SequencerInbox.postUpgradeInit.selector)
        );
    }

    function testSetMaxTimeVariation(
        uint256 delayBlocks,
        uint256 futureBlocks,
        uint256 delaySeconds,
        uint256 futureSeconds
    ) public {
        vm.assume(delayBlocks <= uint256(type(uint64).max));
        vm.assume(futureBlocks <= uint256(type(uint64).max));
        vm.assume(delaySeconds <= uint256(type(uint64).max));
        vm.assume(futureSeconds <= uint256(type(uint64).max));
        (SequencerInbox seqInbox, ) = deployRollup(false);
        vm.prank(rollupOwner);
        seqInbox.setMaxTimeVariation(
            ISequencerInbox.MaxTimeVariation({
                delayBlocks: delayBlocks,
                futureBlocks: futureBlocks,
                delaySeconds: delaySeconds,
                futureSeconds: futureSeconds
            })
        );
    }

    function testSetMaxTimeVariationOverflow(
        uint256 delayBlocks,
        uint256 futureBlocks,
        uint256 delaySeconds,
        uint256 futureSeconds
    ) public {
        vm.assume(delayBlocks > uint256(type(uint64).max));
        vm.assume(futureBlocks > uint256(type(uint64).max));
        vm.assume(delaySeconds > uint256(type(uint64).max));
        vm.assume(futureSeconds > uint256(type(uint64).max));
        (SequencerInbox seqInbox, ) = deployRollup(false);
        vm.expectRevert(abi.encodeWithSelector(BadMaxTimeVariation.selector));
        vm.prank(rollupOwner);
        seqInbox.setMaxTimeVariation(
            ISequencerInbox.MaxTimeVariation({
                delayBlocks: delayBlocks,
                futureBlocks: futureBlocks,
                delaySeconds: delaySeconds,
                futureSeconds: futureSeconds
            })
        );
    }

    function readAndParseBlobInfo()
        public
        returns (
            IEigenDAServiceManager.BlobHeader memory,
            EigenDARollupUtils.BlobVerificationProof memory
        )
    {
        string memory json = vm.readFile("test/foundry/blob_info/blob_info.json");

        // parse the blob header

        IEigenDAServiceManager.BlobHeader memory blobHeader;

        BN254.G1Point memory commitment = BN254.G1Point({
            X: uint256(vm.parseJsonInt(json, ".blob_info.blob_header.commitment.x")),
            Y: uint256(vm.parseJsonInt(json, ".blob_info.blob_header.commitment.y"))
        });

        blobHeader.commitment = commitment;
        blobHeader.dataLength = uint32(
            uint256(vm.parseJsonInt(json, ".blob_info.blob_header.data_length"))
        );

        //bytes memory quorumParamsBytes = vm.parseJson(json, ".blob_info.blob_header.blob_quorum_params");

        // TODO: Parse these from the array, for some reason parsing them reads in the wrong order
        IEigenDAServiceManager.QuorumBlobParam[]
            memory quorumParams = new IEigenDAServiceManager.QuorumBlobParam[](2);

        quorumParams[0].quorumNumber = 0;
        quorumParams[0].adversaryThresholdPercentage = 33;
        quorumParams[0].confirmationThresholdPercentage = 55;
        quorumParams[0].chunkLength = 1;

        quorumParams[1].quorumNumber = 1;
        quorumParams[1].adversaryThresholdPercentage = 33;
        quorumParams[1].confirmationThresholdPercentage = 55;
        quorumParams[1].chunkLength = 1;

        blobHeader.quorumBlobParams = quorumParams;

        // parse the blob verification proof

        IEigenDAServiceManager.BatchHeader memory batchHeader = IEigenDAServiceManager.BatchHeader({
            blobHeadersRoot: vm.parseJsonBytes32(
                json,
                ".blob_info.blob_verification_proof.batch_metadata.batch_header.batch_root"
            ),
            quorumNumbers: vm.parseJsonBytes(
                json,
                ".blob_info.blob_verification_proof.batch_metadata.batch_header.quorum_numbers"
            ),
            signedStakeForQuorums: vm.parseJsonBytes(
                json,
                ".blob_info.blob_verification_proof.batch_metadata.batch_header.quorum_signed_percentages"
            ),
            referenceBlockNumber: uint32(
                uint256(
                    vm.parseJsonUint(
                        json,
                        ".blob_info.blob_verification_proof.batch_metadata.batch_header.reference_block_number"
                    )
                )
            )
        });

        IEigenDAServiceManager.BatchMetadata memory batchMetadata = IEigenDAServiceManager
            .BatchMetadata({
                batchHeader: batchHeader,
                signatoryRecordHash: vm.parseJsonBytes32(
                    json,
                    ".blob_info.blob_verification_proof.batch_metadata.signatory_record_hash"
                ),
                confirmationBlockNumber: uint32(
                    uint256(
                        vm.parseJsonUint(
                            json,
                            ".blob_info.blob_verification_proof.batch_metadata.confirmation_block_number"
                        )
                    )
                )
            });

        EigenDARollupUtils.BlobVerificationProof memory blobVerificationProof = EigenDARollupUtils
            .BlobVerificationProof({
                batchId: uint32(
                    uint256(vm.parseJsonUint(json, ".blob_info.blob_verification_proof.batch_id"))
                ),
                blobIndex: uint32(
                    uint256(vm.parseJsonUint(json, ".blob_info.blob_verification_proof.blob_index"))
                ),
                batchMetadata: batchMetadata,
                inclusionProof: vm.parseJsonBytes(
                    json,
                    ".blob_info.blob_verification_proof.inclusion_proof"
                ),
                quorumIndices: vm.parseJsonBytes(
                    json,
                    ".blob_info.blob_verification_proof.quorum_indexes"
                )
            });
        console.logBytes32(keccak256(abi.encode(blobHeader)));
        return (blobHeader, blobVerificationProof);
    }
}
