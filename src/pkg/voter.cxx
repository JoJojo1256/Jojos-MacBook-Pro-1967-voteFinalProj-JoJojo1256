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
 */
void VoterClient::HandleRegister(std::string input) {
  // Parse input and connect to registrar
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 4) {
    this->cli_driver->print_warning("usage: register <address> <port> <vote>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));


  // Parse selected candidates
  std::vector<std::string> selected_indices = string_split(args[3], ',');
  size_t num_candidates = this->voter_config.num_candidates; // From config
  CryptoPP::Integer k(selected_indices.size());
  

  // Create vote vector
  std::vector<CryptoPP::Integer> vote_vector(num_candidates, CryptoPP::Integer::Zero());
  for (const auto& index_str : selected_indices) {
    size_t index = std::stoi(index_str);
    if (index >= num_candidates) {
      this->cli_driver->print_warning("Invalid candidate index: " + index_str);
      return;
    }
    vote_vector[index] = CryptoPP::Integer::One();
  }


  auto keys = this->HandleKeyExchange(this->RSA_registrar_verification_key);
  CryptoPP::SecByteBlock AES_key = keys.first;
  CryptoPP::SecByteBlock HMAC_key = keys.second;
  CUSTOM_LOG(lg, debug) << "Made keys";
  // Save the ElGamal encrypted vote, ZKP, registrar signature, and blind
  // to both memory and disk
  
  // Generate vector vote
  auto vote_result = ElectionClient::GenerateVectorVote(vote_vector, this->EG_arbiter_public_key, k);
  Vector_Vote_Ciphertext vote_s = vote_result.first;
  VectorVoteZKP_Struct vote_zkp = vote_result.second;
  
  // Blind the vote
  auto blind_vote = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, vote_s);
  CryptoPP::Integer blind = blind_vote.second;
  CryptoPP::Integer blinded_vote = blind_vote.first;
  CUSTOM_LOG(lg, debug) << "Blinded vote";
  
  VoterToRegistrar_Register_Message blinded_vote_msg;
  blinded_vote_msg.id = this->voter_config.voter_id;
  blinded_vote_msg.vote = blinded_vote;
  std::vector<unsigned char> data_to_send;
  data_to_send = crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &blinded_vote_msg);
  this->network_driver->send(data_to_send);
  CUSTOM_LOG(lg, debug) << "Sent blinded";


  // 2. Receive registrar's blind signature on blinded vote
  //decrypt and verify??
  std::vector<unsigned char> response_data = this->network_driver->read();
  auto decrypted_data = this->crypto_driver->decrypt_and_verify(AES_key, HMAC_key, response_data);
  if (!decrypted_data.second) {
    //this->cli_driver->print_error("MAC verification failed.");
    this->network_driver->disconnect();
    return;
  }
  auto dec_message = decrypted_data.first;
  CUSTOM_LOG(lg, debug) << "Received blinded";
  RegistrarToVoter_Blind_Signature_Message r2v_sig_s;
  r2v_sig_s.deserialize(dec_message);

  // [STUDENTS] You may have named the RHS variables below differently.
  // Rename them to match your code.
  this->vote = vote_s;
  this->vote_zkp = vote_zkp;
  this->registrar_signature = r2v_sig_s.registrar_signature;
  this->blind = blind;
  //SaveVote(this->voter_config.voter_vote_path, vote_s);
  //SaveVoteZKP(this->voter_config.voter_vote_zkp_path, vote_zkp);
  SaveVectorVote(this->voter_config.voter_vector_vote_path, vote_s);
  SaveVectorVoteZKP(this->voter_config.voter_vector_vote_zkp_path, vote_zkp);
  SaveInteger(this->voter_config.voter_registrar_signature_path,
              r2v_sig_s.registrar_signature);
  SaveInteger(this->voter_config.voter_blind_path, blind);

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
 */
void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: vote <address> <port>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // TODO: implement me!
  // --------------------------------
  // Exit cleanly.
  
    CUSTOM_LOG(lg, debug) << "Handling vote";
    auto keys = this->HandleKeyExchange(this->RSA_tallyer_verification_key);
    CryptoPP::SecByteBlock AES_key = keys.first;
    CryptoPP::SecByteBlock HMAC_key = keys.second;

    CryptoPP::Integer unblinded_signature = this->crypto_driver->RSA_BLIND_unblind(
        this->RSA_registrar_verification_key, this->registrar_signature,
        this->blind);
  VoterToTallyer_Vote_Message vote_msg;
  vote_msg.vote = this->vote;
  vote_msg.zkp = this->vote_zkp;
  vote_msg.unblinded_signature = unblinded_signature;
  std::vector<unsigned char> data_to_send = this->crypto_driver->encrypt_and_tag(AES_key, HMAC_key, &vote_msg);
  this->network_driver->send(data_to_send);
  this->network_driver->disconnect();
}

/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Verify
  this->cli_driver->print_info("Verifying election results...");
  auto result = this->DoVerify();

  // Error if election failed
  if (!std::get<2>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  this->cli_driver->print_success("Election succeeded!");
  this->cli_driver->print_success("Number of votes for 0: " +
                                  CryptoPP::IntToString(std::get<0>(result)));
  this->cli_driver->print_success("Number of votes for 1: " +
                                  CryptoPP::IntToString(std::get<1>(result)));
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, simply *ignore* it: do not throw an error.
 */
std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> VoterClient::DoVerify() {
  // TODO: implement me!
    // Load election public key

    // Load all votes
    CUSTOM_LOG(lg, debug) << "Verifying election results...";

    // Verify all votes
    CryptoPP::Integer vote_0 = 0;
    CryptoPP::Integer vote_1 = 0;
    bool success = true;
    std::vector<VoteRow> all_votes = this->db_driver->all_votes();
    std::vector<PartialDecryptionRow> all_partial_decryptions = this->db_driver->all_partial_decryptions();


    std::vector<VoteRow> valid_votes;
    for (const auto& vote_row : all_votes) {
      Vote_Ciphertext vote = vote_row.vote;
      bool registrar_signature_valid = this->crypto_driver->RSA_BLIND_verify(
          this->RSA_registrar_verification_key, vote, vote_row.unblinded_signature);

      VoteZKP_Struct zkp = vote_row.zkp;
      CryptoPP::Integer unblinded_signature = vote_row.unblinded_signature;
     auto msg = concat_vote_zkp_and_signature(vote, zkp, unblinded_signature);

      bool sig_valid = this->crypto_driver->RSA_verify(
          this->RSA_tallyer_verification_key, msg, vote_row.tallyer_signature);
      bool zkp_valid = ElectionClient::VerifyVoteZKP(std::make_pair(vote, vote_row.zkp), this->EG_arbiter_public_key);

      if (registrar_signature_valid && sig_valid && zkp_valid) {
        valid_votes.push_back(vote_row);
      }
    }
    CUSTOM_LOG(lg, debug) << "Verified votes";
    std::vector<PartialDecryptionRow> valid_partial_decryptions;
    for (const auto& partial_decryption_row : all_partial_decryptions) {
      CryptoPP::Integer pki;
      LoadInteger(partial_decryption_row.arbiter_vk_path, pki);
      bool partial_decryption_valid = ElectionClient::VerifyPartialDecryptZKP(partial_decryption_row, pki);
      if (partial_decryption_valid) {
        valid_partial_decryptions.push_back(partial_decryption_row);
      }
    }
    CUSTOM_LOG(lg, debug) << "Verified partial decryptions";
    Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(valid_votes);
    CryptoPP::Integer total_votes = valid_votes.size();
    CryptoPP::Integer res = ElectionClient::CombineResults(combined_vote, valid_partial_decryptions);
    vote_1 = res;
    vote_0 = total_votes - res;
    return std::make_tuple(vote_0, vote_1, success);
  
}

std::tuple<std::vector<CryptoPP::Integer>, bool> VoterClient::DoVerifyVector() {
  // Load election public key
  // Load all vector votes
  std::vector<VectorVoteRow> all_votes = this->db_driver->all_vector_votes();
  std::vector<std::vector<PartialDecryptionRow>> all_partial_decryptions = 
      this->db_driver->all_vector_partial_decryptions();
  
  // Verify all votes
  std::vector<VectorVoteRow> valid_votes;
  for (const auto& vote_row : all_votes) {
    bool registrar_signature_valid = this->crypto_driver->RSA_BLIND_verify(
        this->RSA_registrar_verification_key, vote_row.vote, vote_row.unblinded_signature);
        
    auto msg = concat_vector_vote_zkp_and_signature(
        vote_row.vote, vote_row.zkp, vote_row.unblinded_signature);
        
    bool sig_valid = this->crypto_driver->RSA_verify(
        this->RSA_tallyer_verification_key, msg, vote_row.tallyer_signature);
        
    bool zkp_valid = ElectionClient::VerifyVectorVoteZKP(
        std::make_pair(vote_row.vote, vote_row.zkp), 
        this->EG_arbiter_public_key,
        CryptoPP::Integer(this->voter_config.k_value));
        
    if (registrar_signature_valid && sig_valid && zkp_valid) {
      valid_votes.push_back(vote_row);
    }
  }
  
  // Verify partial decryptions
  std::vector<std::vector<PartialDecryptionRow>> valid_partial_decryptions;
  // ... (similar to existing logic)
  
  // Combine votes for each candidate
  std::vector<Vote_Ciphertext> combined_votes = 
      ElectionClient::CombineVectorVotes(valid_votes);
      
  // Get final results
  std::vector<CryptoPP::Integer> results = 
      ElectionClient::CombineVectorResults(combined_votes, valid_partial_decryptions);
      
  return std::make_tuple(results, true);
}