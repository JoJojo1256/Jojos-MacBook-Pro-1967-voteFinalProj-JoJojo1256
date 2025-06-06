#include "../../include/pkg/voter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "util.hpp"

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
VoterClient::VoterClient(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         VoterConfig voter_config, CommonConfig common_config) {
  // Make shared variables.
  this->voter_config = voter_config;
  this->common_config = common_config;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();
  initLogger();

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
                                    "application may be non-functional.");
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

  // Load vote info (vote, zkp, registrar signature, and blind)
  // This is info voter should generate or receive after registering
  try {
    Vote_Ciphertext vote;
    LoadVote(this->voter_config.voter_vote_path, vote);
    this->vote = vote;

    VoteZKP_Struct zkp;
    LoadVoteZKP(this->voter_config.voter_vote_zkp_path, zkp);
    this->vote_zkp = zkp;

    CryptoPP::Integer registrar_signature;
    LoadInteger(this->voter_config.voter_registrar_signature_path,
                registrar_signature);
    this->registrar_signature = registrar_signature;

    CryptoPP::Integer blind;
    LoadInteger(this->voter_config.voter_blind_path, blind);
    this->blind = blind;
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading vote info; voter may still need to register.");
  }
}

/**
 * Run REPL
 */
void VoterClient::run() {
  // Start REPL
  REPLDriver<VoterClient> repl = REPLDriver<VoterClient>(this);
  repl.add_action("register", "register <address> <port> {0, 1}",
                  &VoterClient::HandleRegister);
  repl.add_action("vote", "vote <address> <port>", &VoterClient::HandleVote);
  repl.add_action("verify", "verify", &VoterClient::HandleVerify);
  repl.run();
}

/**
 * Key exchange with either registrar or tallyer
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
VoterClient::HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key) {
  // Generate private/public DH values
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^a
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> user_public_value_data;
  user_public_value_s.serialize(user_public_value_data);
  this->network_driver->send(user_public_value_data);

  // 2) Receive m = (g^a, g^b) signed by the server
  std::vector<unsigned char> server_public_value_data =
      this->network_driver->read();
  ServerToUser_DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value_data);

  // Verify signature
  bool verified = this->crypto_driver->RSA_verify(
      verification_key,
      concat_byteblocks(server_public_value_s.server_public_value,
                        server_public_value_s.user_public_value),
      server_public_value_s.server_signature);
  if (!verified) {
    this->cli_driver->print_warning("Signature verification failed");
    throw std::runtime_error("Voter: failed to verify server signature.");
  }
  if (server_public_value_s.user_public_value != std::get<2>(dh_values)) {
    this->cli_driver->print_warning("Session validation failed");
    throw std::runtime_error(
        "Voter: inconsistencies in voter public DH value.");
  }

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle registering with the registrar. This function:
 * 1) Handle key exchange.
 * 2) ElGamal encrypt the raw vote and generate a ZKP for it
 *    through `ElectionClient::GenerateVote`.
 * 2) Blind the vote and send it to the registrar.
 * 3) Receive the blind signature from the registrar and save it.
 * 3) Receives and saves the signature from the server.
 */void VoterClient::HandleRegister(std::string input) {
  // Split user input into arguments
  std::vector<std::string> args = string_split(input, ' ');

  // Check for minimum required arguments: register <address> <port> <n> <vote_0> ... <vote_n>
  if (args.size() < 4) {
    this->cli_driver->print_warning("usage: register <address> <port> <n> <vote_0> ... <vote_n>");
    return;
  }

  // Connect to the registrar using the provided address and port
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Load voter's ID from configuration
  std::string voter_id = this->voter_config.voter_id;

  // Parse number of votes (n) — how many bits will be in the vote vector
  CryptoPP::Integer num_votes = CryptoPP::Integer(std::stoi(args[3]));

  // Ensure that the correct number of vote values were provided
  if (args.size() != 4 + num_votes) {
    this->cli_driver->print_warning("usage: wrong number of votes ");
    return;
  }

  // Parse the individual vote bits (0 or 1) into raw_votes
  std::vector<CryptoPP::Integer> raw_votes;
  for (size_t i = 4; i < args.size(); ++i) {
    raw_votes.push_back(CryptoPP::Integer(std::stoi(args[i])));
  }

  // Perform RSA-based key exchange with the registrar to get AES & HMAC keys
  auto keys = this->HandleKeyExchange(this->RSA_registrar_verification_key);
  CryptoPP::SecByteBlock AES_key = keys.first;
  CryptoPP::SecByteBlock HMAC_key = keys.second;
  CUSTOM_LOG(lg, debug) << "Made keys";

  // Prepare to store vote ciphertexts and their individual ZKPs
  std::vector<Vote_Ciphertext> vector_s;
  std::vector<VoteZKP_Struct> vector_zkp;

  // Accumulate randomness across votes for the exact-k ZKP
  CryptoPP::Integer R;

  // Encrypt each vote bit and generate a ZKP proving it's 0 or 1
  for (size_t i = 0; i < raw_votes.size(); ++i) {
    Vote_Ciphertext vote_s;
    VoteZKP_Struct vote_zkp;
    CryptoPP::Integer r;

    // Encrypt vote[i] with ElGamal and produce a ZKP and its randomness
    std::tie(vote_s, vote_zkp, r) = ElectionClient::GenerateVote(
      raw_votes[i], this->EG_arbiter_public_key
    );

    // Accumulate total randomness modulo the ElGamal group order
    R = (R + r) % DL_P;

    // Store ciphertext and ZKP
    vector_s.push_back(vote_s);
    vector_zkp.push_back(vote_zkp);
  }

  // Generate ZKP that total number of 1s in encrypted vector equals k
  Vector_Vote_ZKP k_vote_zkp = ElectionClient::GenerateVectorVotesZKP(
    vector_s, this->EG_arbiter_public_key, R
  );

  // auto vote = ElectionClient::GenerateVote(raw_vote, this->EG_arbiter_public_key);
  // Vote_Ciphertext vote_s = vote.first;
  // VoteZKP_Struct vote_zkp = vote.second;
  // CUSTOM_LOG(lg, debug) << "Generated vote and zkp";

  // Blind each encrypted vote to prevent registrar from linking them to the voter
  std::vector<CryptoPP::Integer> blind_msg_vec, blind_factor_vec;
  for (size_t i = 0; i < vector_s.size(); ++i) {
    CryptoPP::Integer blind_msg, blind_factor;
    std::tie(blind_msg, blind_factor) = this->crypto_driver->RSA_BLIND_blind(
      this->RSA_registrar_verification_key, vector_s[i]
    );
    blind_msg_vec.push_back(blind_msg);
    blind_factor_vec.push_back(blind_factor);
  }

  // Construct registration message to registrar with ID and blinded ciphertexts
  VoterToRegistrar_Register_Message v2r_reg_s;
  v2r_reg_s.id = voter_id;
  v2r_reg_s.votes = blind_msg_vec;

  // Encrypt and tag the message using AES + HMAC before sending
  std::vector<unsigned char> data_to_send;
  data_to_send = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &v2r_reg_s);
  this->network_driver->send(data_to_send);

  // auto blind_vote = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, vote_s);
  // CryptoPP::Integer blind = blind_vote.second;
  // CryptoPP::Integer blinded_vote = blind_vote.first;
  // CUSTOM_LOG(lg, debug) << "Blinded vote";
  
  // VoterToRegistrar_Register_Message blinded_vote_msg;
  // blinded_vote_msg.id = voter_id;
  // blinded_vote_msg.vote = blinded_vote;
  // std::vector<unsigned char> data_to_send;
  // data_to_send = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &blinded_vote_msg);
  // this->network_driver->send(data_to_send);
  // CUSTOM_LOG(lg, debug) << "Sent blinded";

  // Prepare to receive registrar's blind signature on each blinded vote
  RegistrarToVoter_Blind_Signature_Message r2v_sig_s;
  std::vector<unsigned char> raw_data, decrypted_data;
  bool valid;

  // Read response from network and decrypt/verify using shared AES/HMAC keys
  raw_data = this->network_driver->read();
  std::tie(decrypted_data, valid) = crypto_driver->decrypt_and_verify(AES_key, HMAC_key, raw_data);
  if (!valid) {
    throw std::runtime_error("CryptoDriver decrypt_and_verify failed [VoterClient::HandleRegister].");
  }

  // Deserialize the registrar's signature message
  r2v_sig_s.deserialize(decrypted_data);

  // 2. Receive registrar's blind signature on blinded vote
  //decrypt and verify??
  // std::vector<unsigned char> response_data = this->network_driver->read();
  // auto decrypted_data = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, response_data);
  // if (!decrypted_data.second) {
  //   //this->cli_driver->print_error("MAC verification failed.");
  //   this->network_driver->disconnect();
  //   return;
  // }
  // auto dec_message = decrypted_data.first;
  // CUSTOM_LOG(lg, debug) << "Received blinded";
  // RegistrarToVoter_Blind_Signature_Message r2v_sig_s;
  // r2v_sig_s.deserialize(dec_message);

  // Save votes and proofs to in-memory variables for future use
  this->votes = vector_s;
  this->vote_zkps = vector_zkp;
  this->registrar_signatures = r2v_sig_s.registrar_signatures;
  this->blinds = blind_factor_vec;
  this->vector_vote_zkp = k_vote_zkp;

  // Save metadata to disk for recovery and later submission to tallyer
  SaveInteger(this->voter_config.voter_vote_path + voter_id + "_num_votes", num_votes);

  // Save encrypted vote, ZKP, signature, and blind for each vote in the vector
  for (size_t i = 0; i < blind_msg_vec.size(); ++i) {
    SaveVote(this->voter_config.voter_vote_path + voter_id + "_" + std::to_string(i), vector_s[i]);
    SaveVoteZKP(this->voter_config.voter_vote_zkp_path + voter_id + "_" + std::to_string(i), vector_zkp[i]);
    SaveInteger(this->voter_config.voter_registrar_signature_path + voter_id + "_" + std::to_string(i), r2v_sig_s.registrar_signature);
    SaveInteger(this->voter_config.voter_blind_path + voter_id + "_" + std::to_string(i), blind_factor_vec[i]);
  }

  // [STUDENTS] You may have named the RHS variables below differently.
  // Rename them to match your code.
  // this->vote = vote_s;
  // this->vote_zkp = vote_zkp;
  // this->registrar_signature = r2v_sig_s.registrar_signature;
  // this->blind = blind;
  // SaveVote(this->voter_config.voter_vote_path, vote_s);
  // SaveVoteZKP(this->voter_config.voter_vote_zkp_path, vote_zkp);
  // SaveInteger(this->voter_config.voter_registrar_signature_path,
  //             r2v_sig_s.registrar_signature);
  // SaveInteger(this->voter_config.voter_blind_path, blind);

  // Print confirmation and disconnect
  this->cli_driver->print_info(
      "Voter registered! Vote saved at " + this->voter_config.voter_vote_path +
      " and vote zkp saved at " + this->voter_config.voter_vote_zkp_path);
  this->network_driver->disconnect();
}

/**
 * Handle voting with the tallyer. This function:
 * 1) Handles key exchange.
 * 2) Unblinds the registrar signature that is stored in
 * `this->registrar_signature`.
 * 3) Sends the vote, ZKP, and unblinded signature
 * to the tallyer.
 */void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');

  // Check for correct number of arguments: vote <address> <port>
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: vote <address> <port>");
    return;
  }

  // Connect to the tallyer using the provided address and port
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // TODO: implement me!
  // --------------------------------

  // Log the start of vote submission
  CUSTOM_LOG(lg, debug) << "Handling vote";

  // Perform key exchange with the tallyer to securely derive symmetric AES and HMAC keys
  auto keys = this->HandleKeyExchange(this->RSA_tallyer_verification_key);
  CryptoPP::SecByteBlock AES_key = keys.first;
  CryptoPP::SecByteBlock HMAC_key = keys.second;

  // Prepare to store the unblinded registrar signatures
  std::vector<CryptoPP::Integer> unblind_s_vec;

  // For each vote, unblind the signature received from the registrar using the blinding factor
  for (size_t i = 0; i < this->registrar_signatures.size(); ++i) {
    CryptoPP::Integer unblind_s = this->crypto_driver->RSA_BLIND_unblind(
      this->RSA_registrar_verification_key,
      this->registrar_signatures[i],
      this->blinds[i]
    );
    unblind_s_vec.push_back(unblind_s);
  }

  // Construct the vote message to send to the tallyer, including:
  // - Vector of encrypted votes
  // - Unblinded registrar signatures
  // - Bitproof ZKPs for each vote
  // - A single ZKP proving the sum of the vector is exactly k
  VoterToTallyer_Vote_Message vote_msg;
  vote_msg.votes = this->votes;
  vote_msg.unblinded_signatures = unblind_s_vec;
  vote_msg.zkps = this->vote_zkps;
  vote_msg.vector_vote_zkp = this->vector_vote_zkp;

  // Encrypt and authenticate the message using AES encryption and HMAC authentication
  std::vector<unsigned char> data_to_send;
  data_to_send = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &vote_msg);

  // Send the secure message to the tallyer over the network
  this->network_driver->send(data_to_send);

  // Cleanly disconnect from the tallyer
  this->network_driver->disconnect();

  //   CryptoPP::Integer unblinded_signature = this->crypto_driver->RSA_BLIND_unblind(
  //       this->RSA_registrar_verification_key, this->registrar_signature,
  //       this->blind);
  // VoterToTallyer_Vote_Message vote_msg;
  // vote_msg.vote = this->vote;
  // vote_msg.zkp = this->vote_zkp;
  // vote_msg.unblinded_signature = unblinded_signature;
  // std::vector<unsigned char> data_to_send = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &vote_msg);
  // this->network_driver->send(data_to_send);
  // this->network_driver->disconnect();
}
/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Begin verification process and notify the user
  this->cli_driver->print_info("Verifying election results...");

  // Call internal function to verify the election; returns (vote counts, success flag)
  auto result = this->DoVerify();

  // Check if the election verification failed
  if (!std::get<1>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // If verification succeeded, inform the user
  this->cli_driver->print_success("Election succeeded!");

  // Extract the vector of vote counts from the result
  std::vector<CryptoPP::Integer> num_votes = std::get<0>(result);

  // Print number of candidates (i.e., length of vote vector)
  this->cli_driver->print_success("Number of votes for " + std::to_string(num_votes.size()));

  // Print number of votes received by each candidate
  for (size_t i = 0; i < num_votes.size(); ++i) {
    this->cli_driver->print_success(
      "Number of votes for " + std::to_string(i) + ": " + CryptoPP::IntToString(num_votes[i])
    );
  }
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, simply *ignore* it: do not throw an error.
 */
std::pair<std::vector<CryptoPP::Integer>, bool> VoterClient::DoVerify() {
  // TODO: implement me!
  // Load election public key

  // Log start of verification
  CUSTOM_LOG(lg, debug) << "Verifying election results...";

  // Fetch all submitted votes from the database
  std::vector<VoteRow> all_votes = this->db_driver->all_votes();
  std::vector<VoteRow> valid_votes;                             // Will hold only valid votes
  std::map<size_t, std::vector<VoteRow>> vote_map;              // Group valid votes by candidate index
  bool valid;

  // Validate each submitted vote
  for (size_t i = 0; i < all_votes.size(); ++i) {
    valid = true;

    // For each vote entry in the vote vector
    for (size_t j = 0; j < all_votes[i].votes.size(); ++j) {
      Vote_Ciphertext vote = all_votes[i].votes[j];
      VoteZKP_Struct zkp = all_votes[i].zkps[j];

      // Check tallyer's signature over vote + ZKP + registrar's signature
      bool valid_signature = this->crypto_driver->RSA_verify(
        this->RSA_tallyer_verification_key,
        concat_vote_zkp_and_signature(vote, zkp, all_votes[i].unblinded_signatures[j]),
        all_votes[i].tallyer_signatures[j]
      );

      // Check ZKP proving this vote is either 0 or 1
      bool valid_vote = ElectionClient::VerifyVoteZKP(std::make_pair(vote, zkp), this->EG_arbiter_public_key);

      // If either check fails, discard the entire vote vector
      if (!valid_signature || !valid_vote) {
        valid = false;
        break;
      }
    }

    // If vote vector is valid, save it and group by candidate
    if (valid) {
      valid_votes.push_back(all_votes[i]);
      for (size_t j = 0; j < all_votes[i].votes.size(); ++j) {
        if (vote_map.find(j) == vote_map.end()) {
          vote_map[j] = std::vector<VoteRow>();
        }

        // Store the j-th vote and its ZKP
        VoteRow vote_row;
        vote_row.vote = all_votes[i].votes[j];
        vote_row.zkp = all_votes[i].zkps[j];
        vote_map[j].push_back(vote_row);
      }
    }
  }

  // Fetch all published partial decryptions from arbiters
  std::vector<PartialDecryptionRow> all_partial_dec = this->db_driver->all_partial_decryptions();

  // Organize partial decryptions by candidate index
  std::map<size_t, std::vector<PartialDecryptionRow>> partial_dec_map;
  for (size_t i = 0; i < all_partial_dec.size(); ++i) {
    if (partial_dec_map.find(all_partial_dec[i].candidate_id) == partial_dec_map.end()) {
      partial_dec_map[all_partial_dec[i].candidate_id] = std::vector<PartialDecryptionRow>();
    }
    partial_dec_map[all_partial_dec[i].candidate_id].push_back(all_partial_dec[i]);
  }

  // Verify all partial decryptions with corresponding arbiter verification keys
  CryptoPP::Integer pki;
  for (auto it = partial_dec_map.begin(); it != partial_dec_map.end(); ++it) {
    for (size_t i = 0; i < it->second.size(); ++i) {
      PartialDecryptionRow partial_dec = it->second[i];

      // Load verification key for this partial decryptor
      LoadInteger(partial_dec.arbiter_vk_path, pki);

      // Check ZKP proving this partial decryption was done correctly
      valid = ElectionClient::VerifyPartialDecryptZKP(partial_dec, pki);

      if (!valid) {
        // Abort: if any partial decryption is invalid, the whole election is invalid
        return std::make_pair(std::vector<CryptoPP::Integer>(), false);
      }
    }
  }

  // If all votes and partial decryptions are valid, compute final result
  std::vector<CryptoPP::Integer> num_votes;

  // For each candidate, combine valid encrypted votes and apply partial decryptions
  for (auto it = partial_dec_map.begin(); it != partial_dec_map.end(); ++it) {
    Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(vote_map[it->first]);
    num_votes.push_back(ElectionClient::CombineResults(combined_vote, it->second));
  }

  // Return final vote counts along with success flag
  return std::make_pair(num_votes, true);


  // -----------------------------------------------
  // Legacy verification code (prior to vector-based exact-k voting)
  // -----------------------------------------------

  // // Verify all votes
  // CryptoPP::Integer vote_0 = 0;
  // CryptoPP::Integer vote_1 = 0;
  // bool success = true;
  // std::vector<VoteRow> all_votes = this->db_driver->all_votes();
  // std::vector<PartialDecryptionRow> all_partial_decryptions = this->db_driver->all_partial_decryptions();

  // std::vector<VoteRow> valid_votes;
  // for (const auto& vote_row : all_votes) {
  //   Vote_Ciphertext vote = vote_row.vote;
  //   bool registrar_signature_valid = this->crypto_driver->RSA_BLIND_verify(
  //       this->RSA_registrar_verification_key, vote, vote_row.unblinded_signature);

  //   VoteZKP_Struct zkp = vote_row.zkp;
  //   CryptoPP::Integer unblinded_signature = vote_row.unblinded_signature;
  //   auto msg = concat_vote_zkp_and_signature(vote, zkp, unblinded_signature);

  //   bool sig_valid = this->crypto_driver->RSA_verify(
  //       this->RSA_tallyer_verification_key, msg, vote_row.tallyer_signature);
  //   bool zkp_valid = ElectionClient::VerifyVoteZKP(std::make_pair(vote, vote_row.zkp), this->EG_arbiter_public_key);

  //   if (registrar_signature_valid && sig_valid && zkp_valid) {
  //     valid_votes.push_back(vote_row);
  //   }
  // }
  // CUSTOM_LOG(lg, debug) << "Verified votes";
  // std::vector<PartialDecryptionRow> valid_partial_decryptions;
  // for (const auto& partial_decryption_row : all_partial_decryptions) {
  //   CryptoPP::Integer pki;
  //   LoadInteger(partial_decryption_row.arbiter_vk_path, pki);
  //   bool partial_decryption_valid = ElectionClient::VerifyPartialDecryptZKP(partial_decryption_row, pki);
  //   if (partial_decryption_valid) {
  //     valid_partial_decryptions.push_back(partial_decryption_row);
  //   }
  // }
  // CUSTOM_LOG(lg, debug) << "Verified partial decryptions";
  // Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(valid_votes);
  // CryptoPP::Integer total_votes = valid_votes.size();
  // CryptoPP::Integer res = ElectionClient::CombineResults(combined_vote, valid_partial_decryptions);
  // vote_1 = res;
  // vote_0 = total_votes - res;
  // return std::make_tuple(vote_0, vote_1, success);
}