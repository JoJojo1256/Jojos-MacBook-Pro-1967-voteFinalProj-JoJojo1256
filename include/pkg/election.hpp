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
  static std::tuple<Vote_Ciphertext, VoteZKP_Struct, CryptoPP::Integer>
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

  static Vector_Vote_ZKP GenerateVectorVotesZKP(
                 std::vector<Vote_Ciphertext>,
                 CryptoPP::Integer pk, CryptoPP::Integer R);
            
  static bool VerifyVectorVotesZKP(Vector_Vote_ZKP zkp, CryptoPP::Integer pk, int k);
};
