module.exports = async hre => {
    const { deployments, getNamedAccounts, ethers } = hre
    const { deploy } = deployments
    const { deployer } = await getNamedAccounts()
  
    await deploy('EigenDABlobVerifierL2', { from: deployer, args: [] })
  }
  
  module.exports.tags = ['EigenDABlobVerifierL2']
  module.exports.dependencies = []
  