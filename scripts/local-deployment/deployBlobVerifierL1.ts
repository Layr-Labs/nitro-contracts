import { ethers } from 'hardhat'
import '@nomiclabs/hardhat-ethers'
import { deployBlobVerifierL1 } from '../deploymentUtils'
import { promises as fs } from 'fs'

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

  let eigenDAServiceManagerAddress = process.env
    .EIGENDA_SERVICE_MANAGER_ADDRESS as string
  if (!eigenDAServiceManagerAddress) {
    throw new Error('EIGENDA_SERVICE_MANAGER_ADDRESS not set')
  }

  if (!process.env.PARENT_CHAIN_ID) {
    throw new Error('PARENT_CHAIN_ID not set')
  }

  const deployerWallet = new ethers.Wallet(
    deployerPrivKey,
    new ethers.providers.JsonRpcProvider(parentChainRpc)
  )

  // deploy templates and rollup creator
  const blobVerifierL1 = await deployBlobVerifierL1(
    'EigenDABlobVerifierL1',
    deployerWallet,
    [eigenDAServiceManagerAddress],
    true
  )
  console.log('BlobVerifierL1 deployed at', blobVerifierL1.address)

  /// store deployment address
  // chain deployment info
  const verifierDeploymentInfo = 'blob_verifier_l1_deploy.json'
  await fs.writeFile(
    verifierDeploymentInfo,
    JSON.stringify(blobVerifierL1.address, null, 2),
    'utf8'
  )
}

main()
  .then(() => process.exit(0))
  .catch((error: Error) => {
    console.error(error)
    process.exit(1)
  })
