#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/pkg/tallyer.hpp"

/*
 * Usage: ./vote_tallyer <config file>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (!(argc == 4)) {
    std::cout
        << "Usage: ./vote_tallyer <port> <config file> <common config file>"
        << std::endl;
    return 1;
  }
  int port = std::stoi(argv[1]);

  // Create tallyer object and run
  TallyerConfig tallyer_config = load_tallyer_config(argv[2]);
  CommonConfig common_config = load_common_config(argv[3]);
  TallyerClient tallyer = TallyerClient(tallyer_config, common_config);
  tallyer.run(port);
  return 0;
}
