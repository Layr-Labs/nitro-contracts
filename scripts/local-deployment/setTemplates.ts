import { ethers } from 'hardhat'
import '@nomiclabs/hardhat-ethers'
import { deployAllContracts } from '../deploymentUtils'
import { createRollup } from '../rollupCreation'
import { promises as fs } from 'fs'
import { BigNumber } from 'ethers'
import { RollupCreator__factory } from '../../build/types'

async function main() {
  /// read env vars needed for deployment
  let childChainName = process.env.CHILD_CHAIN_NAME as string
  if (!childChainName) {
    throw new Error('CHILD_CHAIN_NAME not set')
  }

  let deployerPrivKey = process.env.DEPLOYER_PRIVKEY as string
  if (!deployerPrivKey) {
    throw new Error('DEPLOYER_PRIVKEY not set')
  }

  let parentChainRpc = process.env.PARENT_CHAIN_RPC as string
  if (!parentChainRpc) {
    throw new Error('PARENT_CHAIN_RPC not set')
  }

  if (!process.env.PARENT_CHAIN_ID) {
    throw new Error('PARENT_CHAIN_ID not set')
  }

  const deployerWallet = new ethers.Wallet(
    deployerPrivKey,
    new ethers.providers.JsonRpcProvider(parentChainRpc)
  )

  const maxDataSize =
    process.env.MAX_DATA_SIZE !== undefined
      ? ethers.BigNumber.from(process.env.MAX_DATA_SIZE)
      : ethers.BigNumber.from(117964)

  /// get fee token address, if undefined use address(0) to have ETH as fee token
  let feeToken = process.env.FEE_TOKEN_ADDRESS as string
  if (!feeToken) {
    feeToken = ethers.constants.AddressZero
  }

  /// deploy templates and rollup creator
  console.log('Connect to Rollup Creator')
  
  const rollupCreatorFac = (await ethers.getContractFactory(
    'RollupCreator'
  )) as RollupCreator__factory
  const rollupCreator = rollupCreatorFac.attach("0xbcEb6Ac6Aa7a2073813Ad648770b6A5957303BAc").connect(deployerWallet)

  console.log('Grab contract addresses')
  //TODO: read contracts from a local file such as rollup_creator_contracts.json (assuming it has been stored after deployContracts)
  //For now just read from env vars; update when there's an example rollup_creator_contracts.json file to parse
  const requiredEnvVars = [
    'BRIDGE_CREATOR_ADDRESS',
    'OSP_ADDRESS',
    'CHALLENGE_MANAGER_ADDRESS',
    'ROLLUP_ADMIN_ADDRESS',
    'ROLLUP_USER_ADDRESS',
    'UPGRADE_EXECUTOR_ADDRESS',
    'VALIDATOR_UTILS_ADDRESS',
    'VALIDATOR_WALLET_CREATOR_ADDRESS',
    'DEPLOY_HELPER_ADDRESS'
  ]

  requiredEnvVars.forEach(varName => {
    if (!process.env[varName]) {
      throw new Error(`${varName} not set`)
    }
  })

  const bridgeCreator = process.env.BRIDGE_CREATOR_ADDRESS as string
  const osp = process.env.OSP_ADDRESS as string
  const challengeManager = process.env.CHALLENGE_MANAGER_ADDRESS as string
  const rollupAdmin = process.env.ROLLUP_ADMIN_ADDRESS as string
  const rollupUser = process.env.ROLLUP_USER_ADDRESS as string
  const upgradeExecutor = process.env.UPGRADE_EXECUTOR_ADDRESS as string
  const validatorUtils = process.env.VALIDATOR_UTILS_ADDRESS as string
  const validatorWalletCreator = process.env.VALIDATOR_WALLET_CREATOR_ADDRESS as string
  const deployHelper = process.env.DEPLOY_HELPER_ADDRESS as string

  console.log('Set templates on the Rollup Creator')
  await (
    await rollupCreator.setTemplates(
      bridgeCreator,
      osp,
      challengeManager,
      rollupAdmin,
      rollupUser,
      upgradeExecutor,
      validatorUtils,
      validatorWalletCreator,
      deployHelper,
      { gasLimit: BigNumber.from('30000000') }
    )
  ).wait()
}

main()
  .then(() => process.exit(0))
  .catch((error: Error) => {
    console.error(error)
    process.exit(1)
  })
