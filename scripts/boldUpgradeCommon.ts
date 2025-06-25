import { BigNumber, providers } from 'ethers'
import { isAddress, parseUnits } from 'ethers/lib/utils'
import fs from 'fs'

import { configs } from './files/configs'
import { ERC20__factory } from '../build/types'

export interface DeployedContracts {
  bridge: string
  seqInbox: string
  rei: string
  outbox: string
  inbox: string
  newRollupUser: string
  newRollupAdmin: string
  challengeManager: string
  boldAction: string
  preImageHashLookup: string
  osp: string
}

export const getJsonFile = (fileLocation: string) => {
  return JSON.parse(fs.readFileSync(fileLocation).toString())
}

export const getConfig = async (
  configName: string,
  l1Rpc: providers.Provider
): Promise<Config> => {
  const config = configs[configName as keyof typeof configs]
  if (!config) {
    throw new Error('config not found')
  }
  // in testnode mode we allow some config to be overridden from env for easier testing
  if (process.env.TESTNODE_MODE) {
    console.log('In testnode mode')
    if (process.env.ROLLUP_ADDRESS) {
      console.log('Using ROLLUP_ADDRESS from env:', process.env.ROLLUP_ADDRESS)
      config.contracts.rollup = process.env.ROLLUP_ADDRESS
    }
    if (process.env.STAKE_TOKEN) {
      console.log('Using STAKE_TOKEN from env:', process.env.STAKE_TOKEN)
      config.settings.stakeToken = process.env.STAKE_TOKEN
    }
  }
  await validateConfig(config, l1Rpc)
  return config
}

export interface Config {
  contracts: {
    excessStakeReceiver: string
    rollup: string
    bridge: string
    sequencerInbox: string
    rollupEventInbox: string
    outbox: string
    inbox: string
    upgradeExecutor: string
  }
  proxyAdmins: {
    outbox: string
    inbox: string
    bridge: string
    rei: string
    seqInbox: string
  }
  settings: {
    challengeGracePeriodBlocks: number
    confirmPeriodBlocks: number
    challengePeriodBlocks: number
    stakeToken: string
    stakeAmt: BigNumber
    miniStakeAmounts: BigNumber[]
    chainId: number
    minimumAssertionPeriod: number
    validatorAfkBlocks: number
    disableValidatorWhitelist: boolean
    maxDataSize: number
    blockLeafSize: number
    bigStepLeafSize: number
    smallStepLeafSize: number
    numBigStepLevel: number
    isDelayBufferable: boolean
    bufferConfig: {
      max: number
      threshold: number
      replenishRateInBasis: number
    }
  }
  validators: string[]
}

export type RawConfig = Omit<Config, 'settings'> & {
  settings: Omit<Config['settings'], 'stakeAmt' | 'miniStakeAmounts'> & {
    stakeAmt: string
    miniStakeAmounts: string[]
  }
}

export const validateConfig = async (
  config: Config,
  l1Rpc: providers.Provider
) => {
  const checkCode = async (label: string, addr: string) => {
    const code = await l1Rpc.getCode(addr);
    console.log(`${label} (${addr}): code length = ${code?.length ?? 'undefined'}`);
    if (!code || code.length <= 2) {
      console.warn(`${label} address is not a contract`);
    }
  };

  // Check main contracts
  await checkCode('rollup', config.contracts.rollup);
  await checkCode('bridge', config.contracts.bridge);
  await checkCode('sequencerInbox', config.contracts.sequencerInbox);
  await checkCode('rollupEventInbox', config.contracts.rollupEventInbox);
  await checkCode('outbox', config.contracts.outbox);
  await checkCode('inbox', config.contracts.inbox);
  await checkCode('upgradeExecutor', config.contracts.upgradeExecutor);

  if (!isAddress(config.contracts.excessStakeReceiver)) {
    throw new Error('excessStakeReceiver is not a valid address');
  }

  // Check proxy admins
  await checkCode('proxyAdmins.outbox', config.proxyAdmins.outbox);
  await checkCode('proxyAdmins.inbox', config.proxyAdmins.inbox);
  await checkCode('proxyAdmins.bridge', config.proxyAdmins.bridge);
  await checkCode('proxyAdmins.rei', config.proxyAdmins.rei);
  await checkCode('proxyAdmins.seqInbox', config.proxyAdmins.seqInbox);

  // Check settings
  if (config.settings.confirmPeriodBlocks === 0) throw new Error('confirmPeriodBlocks is 0');
  if (config.settings.challengePeriodBlocks === 0) throw new Error('challengePeriodBlocks is 0');
  await checkCode('stakeToken', config.settings.stakeToken);
  if (config.settings.chainId === 0) throw new Error('chainId is 0');
  if (config.settings.minimumAssertionPeriod === 0) throw new Error('minimumAssertionPeriod is 0');
  if (config.settings.blockLeafSize === 0) throw new Error('blockLeafSize is 0');
  if (config.settings.bigStepLeafSize === 0) throw new Error('bigStepLeafSize is 0');
  if (config.settings.smallStepLeafSize === 0) throw new Error('smallStepLeafSize is 0');
  if (config.settings.numBigStepLevel === 0) throw new Error('numBigStepLevel is 0');
  if (config.settings.maxDataSize === 0) throw new Error('maxDataSize is 0');

  const stakeAmount = BigNumber.from(config.settings.stakeAmt);
  if (stakeAmount.eq(0)) throw new Error('stakeAmt is 0');

  const miniStakeAmounts = config.settings.miniStakeAmounts.map(BigNumber.from);
  if (miniStakeAmounts.length !== config.settings.numBigStepLevel + 2) {
    throw new Error('miniStakeAmts length is not numBigStepLevel + 2');
  }

  if (!config.settings.disableValidatorWhitelist) {
    if (config.validators.length === 0) throw new Error('no validators');
    for (let i = 0; i < config.validators.length; i++) {
      if (!isAddress(config.validators[i])) {
        throw new Error(`Invalid address for validator ${i}`);
      }
    }
  }

  if (config.settings.isDelayBufferable) {
    const buf = config.settings.bufferConfig;
    if (buf.max === 0) throw new Error('bufferConfig.max is 0');
    if (buf.threshold === 0) throw new Error('bufferConfig.threshold is 0');
    if (buf.replenishRateInBasis === 0) throw new Error('bufferConfig.replenishRateInBasis is 0');
  }
};