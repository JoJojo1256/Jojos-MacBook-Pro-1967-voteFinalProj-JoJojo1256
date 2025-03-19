#include "../../include/pkg/arbiter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
ArbiterClient::ArbiterClient(ArbiterConfig arbiter_config,
                             CommonConfig common_config) {
  // Make shared variables.
  this->arbiter_config = arbiter_config;
  this->common_config = common_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = std::make_shared<CryptoDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load arbiter keys.
  try {
    LoadInteger(arbiter_config.arbiter_secret_key_path,
                this->EG_arbiter_secret_key);
    LoadInteger(arbiter_config.arbiter_public_key_path,
                this->EG_arbiter_public_key_i);
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find arbiter keys; you might consider generating some!");
  }

  // Load registrar public key
  try {
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }
}

void ArbiterClient::run() {
  // Start REPL
  REPLDriver<ArbiterClient> repl = REPLDriver<ArbiterClient>(this);
  repl.add_action("keygen", "keygen", &ArbiterClient::HandleKeygen);
  repl.add_action("adjudicate", "adjudicate", &ArbiterClient::HandleAdjudicate);
  repl.run();
}

/**
 * Handle generating election keys
 */
void ArbiterClient::HandleKeygen(std::string _) {
  // Generate keys
  this->cli_driver->print_info("Generating keys, this may take some time...");
  std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
      this->crypto_driver->EG_generate();

  // Save keys
  SaveInteger(this->arbiter_config.arbiter_secret_key_path, keys.first);
  SaveInteger(this->arbiter_config.arbiter_public_key_path, keys.second);
  LoadInteger(arbiter_config.arbiter_secret_key_path,
              this->EG_arbiter_secret_key);
  LoadInteger(arbiter_config.arbiter_public_key_path,
              this->EG_arbiter_public_key_i);
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  this->cli_driver->print_success("Keys succesfully generated and saved!");
}

/**
 * Handle partial decryption. This function:
 * 1) Updates the ElectionPublicKey to the most up to date (done for you).
 * 2) Gets all of the votes from the database.
 * 3) Verifies all of the vote ZKPs and their signatures.
 *    If a vote is invalid, simply ignore it.
 * 4) Combines all valid votes into one vote via `Election::CombineVotes`.
 * 5) Partially decrypts the combined vote.
 * 6) Publishes the decryption and zkp to the database.
 */
void ArbiterClient::HandleAdjudicate(std::string _) {
  // Ensure we have the most up-to-date election key
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  // TODO: implement me!
   std::vector<TallyerToWorld_Vote_Message> votes = this->db_driver->all_votes();

  // Step 2: Verify votes and signatures
  std::vector<TallyerToWorld_Vote_Message> valid_votes;
  ElectionClient election;

  for (const auto& vote_row : votes) {
    const Vote_Ciphertext& vote = vote_row.vote;
    const VoteZKP_Struct& zkp = vote_row.zkp;
    const CryptoPP::Integer& unblinded_signature = vote_row.unblinded_signature;

    // Verify the vote ZKP
    bool zkp_valid = election.VerifyVoteZKP(std::make_pair(vote, zkp), this->EG_arbiter_public_key);

    // Hash the serialized vote
    std::vector<unsigned char> serialized_vote;
    Vote_Ciphertext vote_copy = vote;
    vote_copy.serialize(serialized_vote);

    // Verify the registrar's unblinded signature on the vote hash
    bool sig_valid = this->crypto_driver->RSA_BLIND_verify(
        this->RSA_registrar_verification_key, vote_copy, string_to_integer(vote_row.tallyer_signature));

    if (zkp_valid && sig_valid) {
      VoteRow valid_vote;
      valid_votes.push_back(valid_vote);
    } else {
      this->cli_driver->print_warning("Invalid vote detected; skipping.");
    }
  }

  if (valid_votes.empty()) {
    this->cli_driver->print_warning("No valid votes found after verification.");
    return;
  }

  // Step 4: Combine all valid votes
  Vote_Ciphertext combined_vote = election.CombineVotes(valid_votes);

  // Step 5: Partially decrypt the combined vote
  auto partial_decryption_result = election.PartialDecrypt(
      combined_vote,
      this->EG_arbiter_public_key,
      this->EG_arbiter_secret_key
  );

  PartialDecryption_Struct partial_dec = partial_decryption_result.first;

  // Step 5: Generate ZKP for the partial decryption
  DecryptionZKP_Struct decrypt_zkp = partial_decryption_result.second;

  // Step 6: Publish the partial decryption
  ArbiterToWorld_PartialDecryption_Message partial_decryption_msg;
  partial_decryption_msg.arbiter_id = this->arbiter_config.arbiter_id;
  partial_decryption_msg.dec = partial_dec;
  partial_decryption_msg.zkp = decrypt_zkp;
  partial_decryption_msg.arbiter_vk_path = this->arbiter_config.arbiter_public_key_path;

  this->db_driver->insert_partial_decryption(partial_decryption_msg);


}
