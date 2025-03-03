#include <stdexcept>

#include "../include-shared/config.hpp"

#include "boost/property_tree/json_parser.hpp"
#include "boost/property_tree/ptree.hpp"

// Helper function to load vector
// https://stackoverflow.com/questions/23481262/using-boost-property-tree-to-read-int-array
template <typename T>
std::vector<T> as_vector(boost::property_tree::ptree const &pt,
                         boost::property_tree::ptree::key_type const &key) {
  std::vector<T> r;
  for (auto &item : pt.get_child(key))
    r.push_back(item.second.get_value<T>());
  return r;
}

/**
 * Load common config.
 */
CommonConfig load_common_config(std::string filename) {
  std::ifstream jsonFile(filename);
  if (!jsonFile) {
    std::cerr << "File not found: " << filename << std::endl;
    throw "Invalid file path";
  }
  boost::property_tree::ptree root;
  boost::property_tree::read_json(jsonFile, root);

  CommonConfig config;
  config.db_path = root.get<std::string>("db_path", "");

  std::vector<std::string> arbiter_public_key_paths;
  for (auto path : as_vector<std::string>(root, "arbiter_public_key_paths")) {
    arbiter_public_key_paths.push_back(path);
  }
  config.arbiter_public_key_paths = arbiter_public_key_paths;

  config.registrar_verification_key_path =
      root.get<std::string>("registrar_verification_key_path", "");
  config.tallyer_verification_key_path =
      root.get<std::string>("tallyer_verification_key_path", "");

  return config;
}

/**
 * Load voter config.
 */
VoterConfig load_voter_config(std::string filename) {
  std::ifstream jsonFile(filename);
  if (!jsonFile) {
    std::cerr << "File not found: " << filename << std::endl;
    throw "Invalid file path";
  }
  boost::property_tree::ptree root;
  boost::property_tree::read_json(jsonFile, root);

  VoterConfig config;
  config.voter_id = root.get<std::string>("voter_id", "");
  config.voter_vote_path = root.get<std::string>("voter_vote_path", "");
  config.voter_vote_zkp_path = root.get<std::string>("voter_vote_zkp_path", "");
  config.voter_registrar_signature_path =
      root.get<std::string>("voter_registrar_signature_path", "");
  config.voter_blind_path = root.get<std::string>("voter_blind_path", "");

  return config;
}

/**
 * Load registrar config.
 */
RegistrarConfig load_registrar_config(std::string filename) {
  std::ifstream jsonFile(filename);
  if (!jsonFile) {
    std::cerr << "File not found: " << filename << std::endl;
    throw "Invalid file path";
  }
  boost::property_tree::ptree root;
  boost::property_tree::read_json(jsonFile, root);

  RegistrarConfig config;
  config.registrar_signing_key_path =
      root.get<std::string>("registrar_signing_key_path", "");

  return config;
}

/**
 * Load tallyer config.
 */
TallyerConfig load_tallyer_config(std::string filename) {
  std::ifstream jsonFile(filename);
  if (!jsonFile) {
    std::cerr << "File not found: " << filename << std::endl;
    throw "Invalid file path";
  }
  boost::property_tree::ptree root;
  boost::property_tree::read_json(jsonFile, root);

  TallyerConfig config;
  config.tallyer_signing_key_path =
      root.get<std::string>("tallyer_signing_key_path", "");

  return config;
}

/**
 * Load arbiter config.
 */
ArbiterConfig load_arbiter_config(std::string filename) {
  std::ifstream jsonFile(filename);
  if (!jsonFile) {
    std::cerr << "File not found: " << filename << std::endl;
    throw "Invalid file path";
  }
  boost::property_tree::ptree root;
  boost::property_tree::read_json(jsonFile, root);

  ArbiterConfig config;
  config.arbiter_id = root.get<std::string>("arbiter_id", "");
  config.arbiter_public_key_path =
      root.get<std::string>("arbiter_public_key_path", "");
  config.arbiter_secret_key_path =
      root.get<std::string>("arbiter_secret_key_path", "");

  return config;
}
