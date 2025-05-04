#pragma once

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/modarith.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>
#include <crypto++/rsa.h>

#include "../../include-shared/config.hpp"
#include "../../include-shared/constants.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/db_driver.hpp"

class ElectionClient {
public:
  static std::pair<Vote_Ciphertext, VoteZKP_Struct>
  GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk);
  static bool VerifyVoteZKP(std::pair<Vote_Ciphertext, VoteZKP_Struct> vote,
                            CryptoPP::Integer pk);

  static std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
  PartialDecrypt(Vote_Ciphertext combined_vote, CryptoPP::Integer pk,
                 CryptoPP::Integer sk);
  static bool
  VerifyPartialDecryptZKP(ArbiterToWorld_PartialDecryption_Message a2w_dec_s,
                          CryptoPP::Integer pki);

  static Vote_Ciphertext CombineVotes(std::vector<VoteRow> all_votes);
  static CryptoPP::Integer
  CombineResults(Vote_Ciphertext combined_vote,
                 std::vector<PartialDecryptionRow> all_partial_decryptions);

  // Vector vote functions
  static std::pair<Vector_Vote_Ciphertext, VectorVoteZKP_Struct>
  GenerateVectorVote(const std::vector<CryptoPP::Integer>& votes, 
                    CryptoPP::Integer pk,
                    CryptoPP::Integer k);

  static bool VerifyVectorVoteZKP(
                  const std::pair<Vector_Vote_Ciphertext, VectorVoteZKP_Struct>& vector_vote, 
                  CryptoPP::Integer pk,
                  CryptoPP::Integer k);

  static std::vector<Vote_Ciphertext> CombineVectorVotes(
                  const std::vector<VectorVoteRow>& all_votes);
                    
  static std::vector<std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>>
  PartialDecryptVector(
                  const std::vector<Vote_Ciphertext>& combined_votes,
                  CryptoPP::Integer pk, 
                  CryptoPP::Integer sk);
                    
  static std::vector<CryptoPP::Integer> CombineVectorResults(
                  const std::vector<Vote_Ciphertext>& combined_votes,
                  const std::vector<std::vector<PartialDecryptionRow>>& all_partial_decryptions);

  // Helper function for sum ZKP
  static CryptoPP::Integer hash_sum_zkp(
    CryptoPP::Integer pk, 
    CryptoPP::Integer a, 
    CryptoPP::Integer b,
    CryptoPP::Integer A, 
    CryptoPP::Integer B);
};
