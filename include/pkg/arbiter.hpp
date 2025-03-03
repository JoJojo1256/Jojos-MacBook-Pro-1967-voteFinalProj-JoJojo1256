#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rsa.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"

class ArbiterClient {
public:
  ArbiterClient(ArbiterConfig arbiter_config, CommonConfig common_config);
  void run();
  void HandleKeygen(std::string input);
  void HandleAdjudicate(std::string input);

private:
  ArbiterConfig arbiter_config;
  CommonConfig common_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<DBDriver> db_driver;

  CryptoPP::Integer EG_arbiter_secret_key;   // Our EG secret key
  CryptoPP::Integer EG_arbiter_public_key;   // The election's EG public key
  CryptoPP::Integer EG_arbiter_public_key_i; // Our EG public key
  CryptoPP::RSA::PublicKey RSA_registrar_verification_key;
  CryptoPP::RSA::PublicKey RSA_tallyer_verification_key;
};
