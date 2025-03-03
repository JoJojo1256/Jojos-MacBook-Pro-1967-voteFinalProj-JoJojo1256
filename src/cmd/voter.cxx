#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/pkg/voter.hpp"

/*
 * Usage: ./vote_voter <config file>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (!(argc == 3)) {
    std::cout << "Usage: ./vote_voter <config file> <common config file>"
              << std::endl;
    return 1;
  }

  // Initialize drivers
  std::shared_ptr<NetworkDriver> network_driver =
      std::make_shared<NetworkDriverImpl>();
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();

  // Create voter object and run
  VoterConfig voter_config = load_voter_config(argv[1]);
  CommonConfig common_config = load_common_config(argv[2]);
  VoterClient voter =
      VoterClient(network_driver, crypto_driver, voter_config, common_config);
  voter.run();
  return 0;
}
