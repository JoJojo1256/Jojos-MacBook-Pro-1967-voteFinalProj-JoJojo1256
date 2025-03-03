#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/pkg/arbiter.hpp"

/*
 * Usage: ./vote_arbiter <config file>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (!(argc == 3)) {
    std::cout
        << "Usage: ./vote_arbiter <arbiter config file> <common config file>"
        << std::endl;
    return 1;
  }

  // Create arbiter object and run
  ArbiterConfig arbiter_config = load_arbiter_config(argv[1]);
  CommonConfig common_config = load_common_config(argv[2]);
  ArbiterClient arbiter = ArbiterClient(arbiter_config, common_config);
  arbiter.run();
  return 0;
}
