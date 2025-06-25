import { parseEther } from 'ethers/lib/utils'
import { Config } from '../../boldUpgradeCommon'
import { hoursToBlocks } from './utils'

export const local: Config = {
  contracts: {
    bridge: '0x517a626131162F32E08A788a60491bB61cF5928d',
    inbox: '0x60571c8F4B52954A24A5E7306d435E951528d963',
    outbox: '0x4e5b65FB12d4165E22f5861D97A33BA45c006114',
    rollup: '0x9dF23e34ac13A7145ebA1164660E701839197B1b',
    sequencerInbox: '0xb075b82c7a23e0994dF4793422A1f03Dbcf9136F',
    rollupEventInbox: '0x9f1ece352cE8D540738Ccb38aA3fA3d44D00a259',
    upgradeExecutor: '0x82A3c114b40ecF1FC34745400A1B9B9115c33d31',
    excessStakeReceiver: '0x0bdad990640A488400565fe6fB1D879fFE12DA37',
  },
  proxyAdmins: {
    outbox: '0x5e36Aa9cAAf5F708FCA5C04d2D4c776A62B2b258',
    inbox: '0x5e36Aa9cAAf5F708FCA5C04d2D4c776A62B2b258',
    bridge: '0x5e36Aa9cAAf5F708FCA5C04d2D4c776A62B2b258',
    rei: '0x5e36Aa9cAAf5F708FCA5C04d2D4c776A62B2b258',
    seqInbox: '0x5e36Aa9cAAf5F708FCA5C04d2D4c776A62B2b258',
  },
  settings: {
    challengeGracePeriodBlocks: 10,
    confirmPeriodBlocks: 100,
    challengePeriodBlocks: 110,
    stakeToken: '0x43C9c3Ab961c49f8d42227628617747b1da7bcF0',
    stakeAmt: parseEther('1'),
    miniStakeAmounts: [
      parseEther('6'),
      parseEther('5'),
      parseEther('4'),
      parseEther('3'),
      parseEther('2'),
      parseEther('1'),
    ],
    chainId: 412346,
    minimumAssertionPeriod: 15,
    validatorAfkBlocks: 201600,
    disableValidatorWhitelist: true,
    blockLeafSize: 1048576,
    bigStepLeafSize: 512,
    smallStepLeafSize: 128,
    numBigStepLevel: 4,
    maxDataSize: 117964,
    isDelayBufferable: true,
    bufferConfig: {
      max: 2 ** 32, // effectively disableing and will be enabled later
      threshold: 2 ** 32, // effectively disableing and will be enabled later
      replenishRateInBasis: 500,
    },
  },
  validators: ['0x139A0b6B1Dd1e7F912361B32A09cAD89e82F29db'],
}
