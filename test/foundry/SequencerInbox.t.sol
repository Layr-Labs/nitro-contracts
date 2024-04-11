// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "./util/TestUtil.sol";
import "../../src/bridge/Bridge.sol";
import "../../src/bridge/SequencerInbox.sol";
import {ERC20Bridge} from "../../src/bridge/ERC20Bridge.sol";
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol";

import {EigenDARollupUtils} from "eigenda/contracts/libraries/EigenDARollupUtils.sol";
import {IEigenDAServiceManager} from "eigenda/contracts/interfaces/IEigenDAServiceManager.sol";
import {BN254} from "eigenlayer-middleware/libraries/BN254.sol";

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
    uint256 maxDataSize = 10000;
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

    uint256 public constant MAX_DATA_SIZE = 117964;

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
            dummyEigenDAServiceManager,
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
            dummyEigenDAServiceManager,
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
    uint256 basefee = 100000000;
    vm.fee(basefee);
    // 30 gwei TX L1 fees
    uint256 l1Fees = 30000000000;
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
    //vm.expectEmit();
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
    //vm.expectEmit();
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
        bytes32 dataHash = keccak256(
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

        bytes32 beforeAcc = bytes32(0);
        bytes32 delayedAcc = bridge.delayedInboxAccs(delayedMessagesRead - 1);
        bytes32 afterAcc = keccak256(abi.encodePacked(beforeAcc, dataHash, delayedAcc));

        if (!isUsingFeeToken) {
            _handleSpendingReport(bridge, seqInbox, delayedMessagesRead, dataHash, sequenceNumber, hostChainIsArbitrum);
        }

        // sequencer batch delivered

        //vm.expectEmit();
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

    bytes eigenDAData =
        hex"ed4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a4567890a";

    function testAddSequencerL2BatchFromOrigin_EigenDaHeader() public {
        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(false);
        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        bytes memory data = eigenDAData; // ed is EIGENDA_MESSAGE_HEADER_FLAG

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        // set 60 gwei basefee
        uint256 basefee = 60000000000;
        vm.fee(basefee);
        expectEvents(bridge, seqInbox, data, false, false);

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
        vm.expectRevert(abi.encodeWithSignature("InvalidHeaderFlag(bytes1)", 0xab00000000000000000000000000000000000000000000000000000000000000));
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
        uint256 basefee = 60000000000;
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
        SequencerInbox seqInboxLogic = new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, dummyEigenDAServiceManager, false);
        assertEq(seqInboxLogic.maxDataSize(), MAX_DATA_SIZE, "Invalid MAX_DATA_SIZE");
        assertEq(seqInboxLogic.isUsingFeeToken(), false, "Invalid isUsingFeeToken");

        SequencerInbox seqInboxProxy = SequencerInbox(TestUtil.deployProxy(address(seqInboxLogic)));
        assertEq(seqInboxProxy.maxDataSize(), MAX_DATA_SIZE, "Invalid MAX_DATA_SIZE");
        assertEq(seqInboxProxy.isUsingFeeToken(), false, "Invalid isUsingFeeToken");

        SequencerInbox seqInboxLogicFeeToken = new SequencerInbox(
            MAX_DATA_SIZE,
            dummyReader4844,
            dummyEigenDAServiceManager,
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

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, dummyEigenDAServiceManager, false));
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

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, dummyEigenDAServiceManager, true));
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

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, dummyEigenDAServiceManager, true));
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

        address seqInboxLogic = address(new SequencerInbox(MAX_DATA_SIZE, dummyReader4844, dummyEigenDAServiceManager, false));
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
        uint256 basefee = 40000000000;
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


    // TODO: put these in jsons later
    // https://blobs-holesky.eigenda.xyz/blobs/6e04196ba671fc98bab64f3410e10fbed4629c3cfac273292e2feec778f8adde-313731323832363234373430323533333033332f302f33332f312f33332fe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    BN254.G1Point commitment = BN254.G1Point({
        X: 11973800683352706081745043032492841023821816921595457420358142752350183450007,
        Y: 2805225659489681354691976220137232537594717765057043399317547797368322962514
    });
    
    IEigenDAServiceManager.BlobHeader blobHeader; 
    
    IEigenDAServiceManager.BatchHeader batchHeader = IEigenDAServiceManager.BatchHeader({
        blobHeadersRoot: 0x2f3d0afe00f1a3eccb2a77a053c9fa850d4809913ece2f6a5dcdc9ecb5347c8b,
        quorumNumbers: hex"0001",
        signedStakeForQuorums: hex"4d4f", // quorum_signed_percentages
        referenceBlockNumber: 1325741
    });

    IEigenDAServiceManager.BatchMetadata batchMetadata = IEigenDAServiceManager.BatchMetadata({
        batchHeader: batchHeader,
        signatoryRecordHash: 0x9c2295a45e69a5369008e65fa2afc40eccb8e8be2f453998207e9b0a8d3bc72b,
        confirmationBlockNumber: 1325845
    });

    EigenDARollupUtils.BlobVerificationProof blobVerificationProof = EigenDARollupUtils.BlobVerificationProof({
        batchId: 9869,
        blobIndex: 570,
        batchMetadata: batchMetadata,
        inclusionProof: hex"86d042bea74e8fc60ce55410490d2e8bf312ff03aca9d369296d8cb25cd622096d79ebf24023971807ca680bfeac081bca250544e65147ffc0f7fdd3f3f973b885c252331c8385b767138702b5ba6155ae518fd98ebb966c5d2dfc2364ee0d49c203f38ebd01f85755bd59903ad850ea040fb94611fd554deb03c35ce43453f616866b1248350c1f1af7f3ce0f9b1beb712de850ce4e9cdfee6073fd54b8bca69011c9eca7800d59e6831f055972ae7430b8b52423cf455c2e0a3b11343890c713b16d87b5458476d589dd0f2146b14b9380f69aa8b1b546c75de4bfe925167204dd92138a76c02a4854973ed7016c6c110d41563acbc8cafefbe5d2f0ff490a83cd05a84bdfdd1542ebbbf20ca8b8968407a993919ffe5e159faf5941a95ae878a69d797b170a7a375d88b92c000c70871ae9ed5042f481743a27e97cf8665e8ebdea8f3dc226cc4c9a1cf3863ab4e60900a600fbfe5381cc0912f7aab88686",
        quorumIndices: hex"0001"
    });

    function _fillBlobHeader(IEigenDAServiceManager.BlobHeader storage blobHeader) internal {
        blobHeader.commitment = commitment;
        blobHeader.dataLength = 1;
        blobHeader.quorumBlobParams.push(IEigenDAServiceManager.QuorumBlobParam({
            quorumNumber: 0,
            adversaryThresholdPercentage: 33,
            confirmationThresholdPercentage: 55,
            chunkLength:1
        }));  
    }



    function testAddSequencerL2BatchFromEigenDA() public {
        _fillBlobHeader(blobHeader);


        (SequencerInbox seqInbox, Bridge bridge) = deployRollup(false);
        // update the dummyEigenDAServiceManager to use the holesky serviceManager contract
        vm.prank(rollupOwner);
        seqInbox.updateEigenDAServiceManager(0x870679E138bCdf293b7Ff14dD44b70FC97e12fc0);
        address delayedInboxSender = address(140);
        uint8 delayedInboxKind = 3;
        bytes32 messageDataHash = RAND.Bytes32();
        

        vm.prank(dummyInbox);
        bridge.enqueueDelayedMessage(delayedInboxKind, delayedInboxSender, messageDataHash);


        bytes memory data =  hex"0068656c6c6f"; // ed is EIGEN_DA_MESSAGE_HEADER_FLAG rest is tools/kzgpad/bin/kzgpad -e hello);

        uint256 subMessageCount = bridge.sequencerReportedSubMessageCount();
        uint256 sequenceNumber = bridge.sequencerMessageCount();
        uint256 delayedMessagesRead = bridge.delayedMessageCount();

        expectEvents(bridge, seqInbox, data, true, false, true);

        vm.prank(tx.origin);

        seqInbox.addSequencerL2BatchFromEigenDA(
            sequenceNumber,
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1,
            blobHeader,
            blobVerificationProof
        );



    }

    
    // TODO: put these in jsons later
    // create illegal commitment
    BN254.G1Point illegalCommitment = BN254.G1Point({
        X: 11151623676041303181597631684634074376466382703418354161831688442589830350329,
        Y: 4222041728992406478862708226745479381252734858741080790666424175645694456140

    });
    
    IEigenDAServiceManager.BlobHeader illegalBlobHeader; 
    
    IEigenDAServiceManager.BatchHeader illegalBatchHeader = IEigenDAServiceManager.BatchHeader({
        blobHeadersRoot: bytes32(0),
        quorumNumbers: bytes(""),
        signedStakeForQuorums: bytes(""),
        referenceBlockNumber: 1
    });

    IEigenDAServiceManager.BatchMetadata illegalBatchMetadata = IEigenDAServiceManager.BatchMetadata({
        batchHeader: illegalBatchHeader,
        signatoryRecordHash: bytes32(0),
        confirmationBlockNumber: 1
    });

    EigenDARollupUtils.BlobVerificationProof illegalBlobVerificationProof = EigenDARollupUtils.BlobVerificationProof({
        batchId: 1,
        blobIndex: 1,
        batchMetadata: illegalBatchMetadata,
        inclusionProof: bytes(""),
        quorumIndices: bytes("")
    });

    function testAddSequencerL2BatchFromEigenD() public {

        // finish filling out the illegalBlobHeader
        illegalBlobHeader.commitment = illegalCommitment;
        illegalBlobHeader.dataLength = 20;
        illegalBlobHeader.quorumBlobParams.push(IEigenDAServiceManager.QuorumBlobParam({
            quorumNumber: uint8(1),
            adversaryThresholdPercentage: uint8(1),
            confirmationThresholdPercentage: uint8(1),
            chunkLength:uint32(1)
        }));

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
            delayedMessagesRead,
            IGasRefunder(address(0)),
            subMessageCount,
            subMessageCount + 1,
            illegalBlobHeader,
            illegalBlobVerificationProof
        );
    }

    function testPostUpgradeInitAlreadyInit() public returns (SequencerInbox, SequencerInbox) {
        (SequencerInbox seqInbox, ) = deployRollup(false);
        SequencerInbox seqInboxImpl = new SequencerInbox(maxDataSize, dummyReader4844, dummyEigenDAServiceManager, false);

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

        // IMPORTANT: slots have moved down by one because we have added additional variables for eigenDA
        vm.store(address(seqInbox), bytes32(uint256(5)), bytes32(uint256(delayBlocks))); // slot 5: delayBlocks
        vm.store(address(seqInbox), bytes32(uint256(6)), bytes32(uint256(futureBlocks))); // slot 6: futureBlocks
        vm.store(address(seqInbox), bytes32(uint256(7)), bytes32(uint256(delaySeconds))); // slot 7: delaySeconds
        vm.store(address(seqInbox), bytes32(uint256(8)), bytes32(uint256(futureSeconds))); // slot 8: futureSeconds
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
}
