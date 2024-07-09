module.exports = async hre => {
    const { deployments, getNamedAccounts, ethers } = hre
    const { deploy } = deployments
    const { deployer } = await getNamedAccounts()
  
    await deploy('EigenDADummyManager', { from: deployer, args: [] })
  }
  
  module.exports.tags = ['EigenDADummyManager']
  module.exports.dependencies = []
  