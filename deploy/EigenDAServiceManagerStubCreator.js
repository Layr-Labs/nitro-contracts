module.exports = async hre => {
  const { deployments, getNamedAccounts, ethers } = hre
  const { deploy } = deployments
  const { deployer } = await getNamedAccounts()

  await deploy('EigenDAServiceManagerStub', { from: deployer, args: [] })
}

module.exports.tags = ['EigenDAServiceManagerStub', 'test']
module.exports.dependencies = []
