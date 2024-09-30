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

  /// get fee token address, if undefined use address(0) to have ETH as fee token
  let feeToken = process.env.FEE_TOKEN_ADDRESS as string
  if (!feeToken) {
    feeToken = ethers.constants.AddressZero
  }
  console.log('Fee token address:', feeToken)

  const rollupCreatorAddress = process.env.ROLLUP_CREATOR as string
  if (!rollupCreatorAddress) {
    throw new Error('ROLLUP_CREATOR not set')
  }
  const rollupCreatorFac = await ethers.getContractFactory('RollupCreator')
  const rollupCreator = rollupCreatorFac.attach(rollupCreatorAddress)

  const eigenDARollupManager = process.env.EIGENDA_ROLLUP_MANAGER as string
  if (!eigenDARollupManager) {
    throw new Error('EIGENDA_ROLLUP_MANAGER not set')
  }

  /// Create rollup
  const chainId = (await deployerWallet.provider.getNetwork()).chainId
  console.log(
    'Create rollup on top of chain',
    chainId,
    'using RollupCreator',
    rollupCreator.address
  )
  const result = await createRollup(
    deployerWallet,
    true,
    rollupCreator.address,
    feeToken,
    eigenDARollupManager
  )

  if (!result) {
    throw new Error('Rollup creation failed')
  }

  const { rollupCreationResult, chainInfo } = result

  /// store deployment address
  // chain deployment info
  const chainDeploymentInfo =
    process.env.CHAIN_DEPLOYMENT_INFO !== undefined
      ? process.env.CHAIN_DEPLOYMENT_INFO
      : 'deploy.json'
  await fs.writeFile(
    chainDeploymentInfo,
    JSON.stringify(rollupCreationResult, null, 2),
    'utf8'
  )

  // child chain info
  chainInfo['chain-name'] = childChainName
  const childChainInfo =
    process.env.CHILD_CHAIN_INFO !== undefined
      ? process.env.CHILD_CHAIN_INFO
      : 'l2_chain_info.json'
  await fs.writeFile(
    childChainInfo,
    JSON.stringify([chainInfo], null, 2),
    'utf8'
  )
}

main()
  .then(() => process.exit(0))
  .catch((error: Error) => {
    console.error(error)
    process.exit(1)
  })
