#pragma once

#include <cstdlib>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/pkg/arbiter.hpp"
#include "../../include/pkg/voter.hpp"

template <class T> class REPLDriver {
public:
  REPLDriver(T *owner);
  void add_action(std::string trigger, std::string guide,
                  void (T::*func)(std::string line));
  void run();

private:
  T *owner;
  std::shared_ptr<CLIDriver> cli_driver;
  std::map<std::string, void (T::*)(std::string line)> actions;
  std::map<std::string, std::string> guides;
};
template class REPLDriver<ArbiterClient>;
template class REPLDriver<VoterClient>;
