// This script tells Truffle how to deploy your smart contract(s).

const AuthChain = artifacts.require("AuthChain");

module.exports = function (deployer) {
  // Deploy the AuthChain contract
  deployer.deploy(AuthChain);
};