#pragma once

#include <iostream>
#include <string>
#include <vector>

#include "boost/property_tree/json_parser.hpp"
#include "boost/property_tree/ptree.hpp"

template <typename T>
std::vector<T> as_vector(boost::property_tree::ptree const &pt,
                         boost::property_tree::ptree::key_type const &key);

struct CommonConfig {
  std::string db_path;
  std::vector<std::string> arbiter_public_key_paths;
  std::string registrar_verification_key_path;
  std::string tallyer_verification_key_path;
};
CommonConfig load_common_config(std::string filename);

struct VoterConfig {
  std::string voter_id;
  std::string voter_vote_path;
  std::string voter_vote_zkp_path;
  std::string voter_registrar_signature_path;
  std::string voter_blind_path;
};
VoterConfig load_voter_config(std::string filename);

struct RegistrarConfig {
  std::string registrar_signing_key_path;
};
RegistrarConfig load_registrar_config(std::string filename);

struct TallyerConfig {
  std::string tallyer_signing_key_path;
};
TallyerConfig load_tallyer_config(std::string filename);

struct ArbiterConfig {
  std::string arbiter_id;
  std::string arbiter_public_key_path;
  std::string arbiter_secret_key_path;
};
ArbiterConfig load_arbiter_config(std::string filename);
