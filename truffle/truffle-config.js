/**
 * Standard Truffle config for connecting to a local Ganache instance.
 */
module.exports = {
  networks: {
    // Development network (Ganache)
    development: {
      host: "127.0.0.1",     // Localhost
      port: 7545,            // Standard Ganache GUI port
      network_id: "*",       // Match any network id
    },
  },

  // Configure your compilers
  compilers: {
    solc: {
      version: "0.8.19", // Fetch exact version from solc-bin
      // settings: {
      //   optimizer: {
      //     enabled: false,
      //     runs: 200
      //   },
      // }
    },
  },
};