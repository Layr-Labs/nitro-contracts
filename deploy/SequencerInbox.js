module.exports = async hre => {
  const { deployments, getNamedAccounts, ethers } = hre
  const { deploy } = deployments
  const { deployer } = await getNamedAccounts()

  const blobBasefeeReader = await ethers.getContract('BlobBasefeeReader')
  const dataHashReader = await ethers.getContract('DataHashReader')

  const EigenDARollupUtils = await ethers.getContract('EigenDARollupUtils')



  await deploy('SequencerInbox', { from: deployer, args: [117964], libraries: { EigenDARollupUtils: EigenDARollupUtils.address } })
}

module.exports.tags = ['SequencerInbox']
module.exports.dependencies = []
