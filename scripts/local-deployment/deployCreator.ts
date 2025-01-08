import { ethers } from 'hardhat'
import '@nomiclabs/hardhat-ethers'
import { deployAllContracts, deployBlobVerifierL1 } from '../deploymentUtils'
import { createRollup } from '../rollupCreation'
import { promises as fs } from 'fs'
import { BigNumber } from 'ethers'
import { RollupAdminLogic__factory } from '../../build/types'

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
  console.log('Fee token address:', feeToken)

  // deploy templates and rollup creator
  console.log('Deploy RollupCreator')

  const contracts = await deployAllContracts(deployerWallet, maxDataSize, false)

  console.log('Set templates on the Rollup Creator')
  await (
    await contracts.rollupCreator.setTemplates(
      contracts.bridgeCreator.address,
      contracts.osp.address,
      contracts.challengeManager.address,
      contracts.rollupAdmin.address,
      contracts.rollupUser.address,
      contracts.upgradeExecutor.address,
      contracts.validatorUtils.address,
      contracts.validatorWalletCreator.address,
      contracts.deployHelper.address,
      { gasLimit: BigNumber.from('300000') }
    )
  ).wait()

  console.log('Rollup creator is ready for rollup creation')

  /// store deployment address
  // chain deployment info
  const chainDeploymentInfo =
    process.env.CHAIN_DEPLOYMENT_INFO !== undefined
      ? process.env.CHAIN_DEPLOYMENT_INFO
      : 'rollupCreatorContracts.json'
  await fs.writeFile(
    chainDeploymentInfo,
    JSON.stringify(contracts, null, 2),
    'utf8'
  )
}

main()
  .then(() => process.exit(0))
  .catch((error: Error) => {
    console.error(error)
    process.exit(1)
  })
