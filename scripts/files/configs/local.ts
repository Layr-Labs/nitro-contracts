import { parseEther } from 'ethers/lib/utils'
import { Config } from '../../boldUpgradeCommon'
import { hoursToBlocks } from './utils'

export const local: Config = {
  contracts: {
    bridge: '0x7DD3F2a3fAeF3B9F2364c335163244D3388Feb83',
    inbox: '0x4e5b65FB12d4165E22f5861D97A33BA45c006114',
    outbox: '0x9f1ece352cE8D540738Ccb38aA3fA3d44D00a259',
    rollup: '0x6C960Ff944a6283cc50F03041bbA724b17FAa640',
    sequencerInbox: '0x60571c8F4B52954A24A5E7306d435E951528d963',
    rollupEventInbox: '0x9dF23e34ac13A7145ebA1164660E701839197B1b',
    upgradeExecutor: '0x82A3c114b40ecF1FC34745400A1B9B9115c33d31',
    excessStakeReceiver: '0xC3124dD1FA0e5D6135c25279760DBF9d9286467B', // left unchanged
  },
  proxyAdmins: {
    outbox: '0x2a1f38c9097e7883570e0b02bfbe6869cc25d8a3',
    inbox: '0x2a1f38c9097e7883570e0b02bfbe6869cc25d8a3',
    bridge: '0x2a1f38c9097e7883570e0b02bfbe6869cc25d8a3',
    rei: '0x2a1f38c9097e7883570e0b02bfbe6869cc25d8a3',
    seqInbox: '0x2a1f38c9097e7883570e0b02bfbe6869cc25d8a3',
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
    chainId: 1337, // unchanged
    minimumAssertionPeriod: 15,
    validatorAfkBlocks: 201600,
    disableValidatorWhitelist: true,
    blockLeafSize: 1048576,
    bigStepLeafSize: 512,
    smallStepLeafSize: 128,
    numBigStepLevel: 4,
    maxDataSize: 117964, // confirmed in logs
    isDelayBufferable: true,
    bufferConfig: {
      max: 2 ** 32, // effectively disabling and will be enabled later
      threshold: 2 ** 32, // effectively disabling and will be enabled later
      replenishRateInBasis: 500,
    },
  },
  validators: ['0x139A0b6B1Dd1e7F912361B32A09cAD89e82F29db'], // unchanged
}
