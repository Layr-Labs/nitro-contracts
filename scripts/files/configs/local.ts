import { parseEther } from 'ethers/lib/utils'
import { Config } from '../../boldUpgradeCommon'
import { hoursToBlocks } from './utils'

export const local: Config = {
  contracts: {
    bridge: '0x7DD3F2a3fAeF3B9F2364c335163244D3388Feb83',
    inbox: '0xb075b82c7a23e0994dF4793422A1f03Dbcf9136F',
    outbox: '0x9dF23e34ac13A7145ebA1164660E701839197B1b',
    rollup: '0xBd4Cc2f69fFd94b5F62DCc5a27c2eb805093FC0d',
    sequencerInbox: '0x60571c8F4B52954A24A5E7306d435E951528d963',
    rollupEventInbox: '0x4e5b65FB12d4165E22f5861D97A33BA45c006114',
    upgradeExecutor: '0xd0155e735c9dffb5bf0e6d3452650338827c4192',
    excessStakeReceiver: '0xC3124dD1FA0e5D6135c25279760DBF9d9286467B',
  },
  proxyAdmins: {
    outbox: '0x45f46662EE4e19B7e714F829b07b6abdbD291Ca8',
    inbox: '0x58feD87D5DD9B1c2FA78f8443F8D521b6720f967',
    bridge: '0xBe22437ebc73b587ae55989C1cc3D0A92aED51E9',
    rei: '0xafe0cBd8DC4D70A22D57C365DCA009c6e001E39c',
    seqInbox: '0xFAEFd51010919ed44982D1C3a2133E2761DC8c67',
  },
  settings: {
    challengeGracePeriodBlocks: 10,
    confirmPeriodBlocks: 100,
    challengePeriodBlocks: 110,
    stakeToken: '0x8D771f053023F3b10f6d5364168BcB4449C14AA1',
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
    minimumAssertionPeriod: 0,
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
  validators: [],
}
