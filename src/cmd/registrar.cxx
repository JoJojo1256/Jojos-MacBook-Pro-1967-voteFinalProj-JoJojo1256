#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include-shared/config.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/pkg/registrar.hpp"

/*
 * Usage: ./vote_registrar <config file>
 */
int main(int argc, char *argv[]) {
  // Initialize logger
  initLogger();

  // Parse args
  if (!(argc == 4)) {
    std::cout
        << "Usage: ./vote_registrar <port> <config file> <common config file>"
        << std::endl;
    return 1;
  }
  int port = std::stoi(argv[1]);

  // Create registrar object and run
  RegistrarConfig registrar_config = load_registrar_config(argv[2]);
  CommonConfig common_config = load_common_config(argv[3]);
  RegistrarClient registrar = RegistrarClient(registrar_config, common_config);
  registrar.run(port);
  return 0;
}
