import { BigNumber } from '@ethersproject/bignumber'
import { Bytes } from 'ethers'

export type DelayedMsgHeader = {
  kind: number
  sender: string
  blockNumber: number
  timestamp: number
  totalDelayedMessagesRead: number
  baseFee: number
  messageDataHash: string
}

export type DelayedMsg = {
  header: DelayedMsgHeader
  messageData: string
}

export type DelayedMsgDelivered = {
  delayedMessage: DelayedMsg
  delayedAcc: string
  delayedCount: number
}

export type MaxTimeVariation = {
  delaySeconds: number
  futureSeconds: number
  delayBlocks: number
  futureBlocks: number
}

export type DelayConfig = {
  threshold: BigNumber
  max: number
  replenishRateInBasis: number
}

export type QuorumBlobParamStruct = {
  quorumNumber: BigNumber
  adversaryThresholdPercentage: BigNumber
  confirmationThresholdPercentage: BigNumber
  chunkLength: BigNumber
}

export type G1PointStruct = {
  X: BigNumber
  Y: BigNumber
}

export type EigenDACertStruct = {
  blobVerificationProof: BlobVerificationProofStruct
  blobHeader: BlobHeaderStruct
}

export type BlobHeaderStruct = {
  commitment: G1PointStruct
  dataLength: BigNumber
  quorumBlobParams: QuorumBlobParamStruct[]
}

export type BatchMetadataStruct = {
  batchHeader: BatchHeaderStruct
  signatoryRecordHash: Bytes
  confirmationBlockNumber: BigNumber
}

export type BatchHeaderStruct = {
  blobHeadersRoot: Bytes
  quorumNumbers: Bytes
  signedStakeForQuorums: Bytes
  referenceBlockNumber: BigNumber
}

export type BlobVerificationProofStruct = {
  batchId: BigNumber
  blobIndex: BigNumber
  batchMetadata: BatchMetadataStruct
  inclusionProof: Bytes
  quorumIndices: Bytes
}
