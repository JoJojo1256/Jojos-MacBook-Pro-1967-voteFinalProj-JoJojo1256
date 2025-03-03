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
#include "../../include/drivers/network_driver.hpp"

class VoterClient {
public:
  VoterClient(std::shared_ptr<NetworkDriver> network_driver,
              std::shared_ptr<CryptoDriver> crypto_driver,
              VoterConfig voter_config, CommonConfig common_config);
  void run();
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key);
  void HandleRegister(std::string input);
  void HandleVote(std::string input);
  void HandleVerify(std::string input);
  std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> DoVerify();

private:
  VoterConfig voter_config;
  CommonConfig common_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<DBDriver> db_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  CryptoPP::Integer EG_arbiter_public_key; // The election's EG public key
  CryptoPP::SecByteBlock AES_key;
  CryptoPP::SecByteBlock HMAC_key;

  Vote_Ciphertext vote;
  VoteZKP_Struct vote_zkp;
  CryptoPP::Integer registrar_signature;
  CryptoPP::Integer blind;

  CryptoPP::RSA::PrivateKey RSA_voter_signing_key;
  CryptoPP::RSA::PublicKey RSA_registrar_verification_key;
  CryptoPP::RSA::PublicKey RSA_tallyer_verification_key;
};
