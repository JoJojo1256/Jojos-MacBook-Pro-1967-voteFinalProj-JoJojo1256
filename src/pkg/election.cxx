#include "../../include/pkg/election.hpp"
#include "../../include-shared/logger.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Generate Vote and ZKP.
 */
std::tuple<Vote_Ciphertext, VoteZKP_Struct, CryptoPP::Integer>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
  Vote_Ciphertext ciphertext;
  VoteZKP_Struct zkp;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer r(prng, 1, DL_Q - 1);

  ciphertext.a = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
  ciphertext.b = a_times_b_mod_c(CryptoPP::ModularExponentiation(pk, r, DL_P), CryptoPP::ModularExponentiation(DL_G, vote, DL_P), DL_P);



  if (vote == CryptoPP::Integer::One()) {
    CryptoPP::Integer double_r_prime_zero(prng, 1, DL_Q - 1);
    CryptoPP::Integer sigma_zero(prng, 1, DL_Q - 1);
    CryptoPP::Integer a0 = a_times_b_mod_c(CryptoPP::ModularExponentiation(DL_G, double_r_prime_zero, DL_P), CryptoPP::EuclideanMultiplicativeInverse((CryptoPP::ModularExponentiation(ciphertext.a, sigma_zero, DL_P)), DL_P), DL_P);
    CryptoPP::Integer b0 = a_times_b_mod_c(CryptoPP::ModularExponentiation(pk, double_r_prime_zero, DL_P), CryptoPP::EuclideanMultiplicativeInverse((CryptoPP::ModularExponentiation(ciphertext.b, sigma_zero, DL_P)), DL_P), DL_P);
    zkp.a0 = a0;
    zkp.b0 = b0;
    zkp.c0 = sigma_zero;
    zkp.r0 = double_r_prime_zero;
    CryptoPP::Integer r_prime_one = CryptoPP::Integer(prng, 1, DL_Q - 1);
    zkp.a1 = CryptoPP::ModularExponentiation(DL_G, r_prime_one, DL_P);
    zkp.b1 = CryptoPP::ModularExponentiation(pk, r_prime_one, DL_P);
    CryptoPP::Integer big_sigma = hash_vote_zkp(pk, ciphertext.a, ciphertext.b, zkp.a0, zkp.b0, zkp.a1, zkp.b1) % DL_Q;
    zkp.c1 = (big_sigma - sigma_zero) % DL_Q;
    zkp.r1 = (r_prime_one + a_times_b_mod_c(zkp.c1, r, DL_Q))% DL_Q;
  }
  else if (vote == CryptoPP::Integer::Zero()) {
    // vote == 0
    CryptoPP::Integer double_r_prime_one(prng, 2, DL_Q - 1);
    CryptoPP::Integer sigma_one(prng, 2, DL_Q - 1);
    CryptoPP::Integer a1 = a_times_b_mod_c(CryptoPP::ModularExponentiation(DL_G, double_r_prime_one, DL_P), CryptoPP::EuclideanMultiplicativeInverse ((CryptoPP::ModularExponentiation(ciphertext.a, sigma_one, DL_P)), DL_P), DL_P);
    CryptoPP::Integer c2_over_g = a_times_b_mod_c(ciphertext.b, CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P);
    CryptoPP::Integer b1 = a_times_b_mod_c(CryptoPP::ModularExponentiation(pk, double_r_prime_one, DL_P), CryptoPP::EuclideanMultiplicativeInverse((CryptoPP::ModularExponentiation(c2_over_g, sigma_one, DL_P)), DL_P), DL_P);
    zkp.a1 = a1;
    zkp.b1 = b1;
    zkp.c1 = sigma_one;
    zkp.r1 = double_r_prime_one;
    CryptoPP::Integer r_prime_zero = CryptoPP::Integer(prng, 2, DL_Q - 1);
    zkp.a0 = CryptoPP::ModularExponentiation(DL_G, r_prime_zero, DL_P);
    zkp.b0 = CryptoPP::ModularExponentiation(pk, r_prime_zero, DL_P);
    CryptoPP::Integer big_sigma = hash_vote_zkp(pk, ciphertext.a, ciphertext.b, zkp.a0, zkp.b0, a1, b1) % DL_Q;
    zkp.c0 = (big_sigma - sigma_one) % DL_Q;
    zkp.r0 = (r_prime_zero + a_times_b_mod_c(zkp.c0, r, DL_Q) ) % DL_Q;
  } else {
    CUSTOM_LOG(lg, error) << "Vote is not 0 or 1";
    //should never get here
    return std::make_tuple(ciphertext, zkp, r);
  }
  return std::make_tuple(ciphertext, zkp, r);
}

/**
 * Verify vote zkp.
 */
bool ElectionClient::VerifyVoteZKP(
    std::pair<Vote_Ciphertext, VoteZKP_Struct> vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
  VoteZKP_Struct zkp = vote.second;
  Vote_Ciphertext ciphertext = vote.first;
  CryptoPP::Integer a = ciphertext.a;
  CryptoPP::Integer b = ciphertext.b;
  CryptoPP::Integer a0 = vote.second.a0;
  CryptoPP::Integer b0 = vote.second.b0;
  CryptoPP::Integer c0 = vote.second.c0;
  CryptoPP::Integer r0 = vote.second.r0;
  CryptoPP::Integer a1 = vote.second.a1;
  CryptoPP::Integer b1 = vote.second.b1;
  CryptoPP::Integer c1 = vote.second.c1;
  CryptoPP::Integer r1 = vote.second.r1;

  CryptoPP::Integer big_sigma = hash_vote_zkp(pk, a, b, a0, b0, a1, b1) % DL_Q;
  CryptoPP::Integer received_big_sigma = (c0 + c1) % DL_Q;
  if (big_sigma != received_big_sigma) {
    CUSTOM_LOG(lg, debug) << "big_sigma does not match c1 + c0";
    return false;
  }
  if (CryptoPP::ModularExponentiation(DL_G, r1, DL_P) != (a1 * CryptoPP::ModularExponentiation(a, c1, DL_P)) % DL_P) {
    CUSTOM_LOG(lg, debug) << "r1 does not match a1 * a^c1";
    return false;
  }
  CryptoPP::Integer b_over_g = a_times_b_mod_c(b, CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P);
  if (CryptoPP::ModularExponentiation(pk, r1, DL_P) != (b1 * CryptoPP::ModularExponentiation(b_over_g, c1, DL_P)) % DL_P) {
    CUSTOM_LOG(lg, debug) << "r1 does not match b1 * b^c1";
    return false;
  }

  if (CryptoPP::ModularExponentiation(DL_G, r0, DL_P) != (a0 * CryptoPP::ModularExponentiation(a, c0, DL_P)) % DL_P) {
    CUSTOM_LOG(lg, debug) << "r0 does not match a0 * a^c0";
    return false;
  }
  if (CryptoPP::ModularExponentiation(pk, r0, DL_P) != (b0 * CryptoPP::ModularExponentiation(b, c0, DL_P)) % DL_P) {
    CUSTOM_LOG(lg, debug) << "r0 does not match b0 * b^c0";
    return false;
  }
  return true;

}

/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Ciphertext combined_vote,
                               CryptoPP::Integer pk, CryptoPP::Integer sk) {
  initLogger();
  // TODO: implement me!
  PartialDecryption_Struct partial_decryption;
  DecryptionZKP_Struct zkp;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer r = CryptoPP::Integer(prng, 2, DL_Q - 1);
  partial_decryption.aggregate_ciphertext = combined_vote;
  partial_decryption.d = CryptoPP::ModularExponentiation(combined_vote.a, sk, DL_P);
  //not sure if sigma here should have comined_vote.something instead of combined_vote
  zkp.u = CryptoPP::ModularExponentiation(combined_vote.a, r, DL_P);
  zkp.v = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
  CryptoPP::Integer sigma = hash_dec_zkp(pk, combined_vote.a, combined_vote.b, zkp.u, zkp.v);
  zkp.s = (r + a_times_b_mod_c(sigma, sk, DL_Q)) % DL_Q;
  return std::make_pair(partial_decryption, zkp);
}

/**
 * Verify partial decryption zkp.
 */
bool ElectionClient::VerifyPartialDecryptZKP(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  initLogger();
  // TODO: implement me!
  CryptoPP::Integer u = a2w_dec_s.zkp.u;
  CryptoPP::Integer v = a2w_dec_s.zkp.v;
  CryptoPP::Integer s = a2w_dec_s.zkp.s;
  CryptoPP::Integer a = a2w_dec_s.dec.aggregate_ciphertext.a;
  CryptoPP::Integer b = a2w_dec_s.dec.aggregate_ciphertext.b;
  CryptoPP::Integer sigma = hash_dec_zkp(pki, a, b, u, v);
  CryptoPP::Integer d = a2w_dec_s.dec.d;
  if (CryptoPP::ModularExponentiation(a, s, DL_P) != a_times_b_mod_c(u, CryptoPP::ModularExponentiation(d, sigma, DL_P), DL_P)) {
    CUSTOM_LOG(lg, debug) << "g^s does not match a * pk^sigma";
    return false;
  }
  if (CryptoPP::ModularExponentiation(DL_G, s, DL_P) != a_times_b_mod_c(v, CryptoPP::ModularExponentiation(pki, sigma, DL_P), DL_P)) {
    CUSTOM_LOG(lg, debug) << "c1^s does not match b * d^sigma";
    return false;
  }
  return true;
}

/**
 * Combine votes into one using homomorphic encryption.
 */
Vote_Ciphertext ElectionClient::CombineVotes(std::vector<VoteRow> all_votes) {
  initLogger();
  // TODO: implement me!
  CryptoPP::Integer a = 1;
  CryptoPP::Integer b = 1;
  for (const VoteRow& vote : all_votes) {
    Vote_Ciphertext vote_ciphertext = vote.vote;
    a = (a * vote_ciphertext.a) % DL_P;
    b = (b * vote_ciphertext.b) % DL_P;
  }
  Vote_Ciphertext combined_vote;
  combined_vote.a = a;
  combined_vote.b = b;
  return combined_vote;
}

/**
 * Combines partial decryptions and returns final vote count.
 */
CryptoPP::Integer ElectionClient::CombineResults(
    Vote_Ciphertext combined_vote,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  initLogger();
  // TODO: implement me!
  CryptoPP::Integer b = combined_vote.b;
  CryptoPP::Integer d_product = 1;
  for (const auto& partial_decryption : all_partial_decryptions) {
    CryptoPP::Integer d = partial_decryption.dec.d;
    d_product = (d_product * d) % DL_P;
  }
  CryptoPP::Integer d_product_inverse = CryptoPP::EuclideanMultiplicativeInverse(d_product, DL_P);
  CryptoPP::Integer result = (b * d_product_inverse) % DL_P;
  CryptoPP::Integer count = 0;
  CryptoPP::Integer test = 1;
  while (test < DL_P) {
    if (test == result) {
      return count;
    }
    test = (test * DL_G) % DL_P;
    count++;
  }
  return count;
}

// ================================================
// NEW FUNCTIONS
// ================================================


Vector_Vote_ZKP ElectionClient::GenerateVectorVotesZKP(
  std::vector<Vote_Ciphertext> votes,
  CryptoPP::Integer pk, CryptoPP::Integer R) {
  initLogger();

  CryptoPP::Integer C1 = 1;
  CryptoPP::Integer C2 = 1;

  for (size_t i = 0; i < votes.size(); ++i) {
    C1 = a_times_b_mod_c(C1, votes[i].a, DL_P);
    C2 = a_times_b_mod_c(C2, votes[i].b, DL_P);
  }

  Vector_Vote_ZKP vector_vote_zkp;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer r(prng, 1, DL_Q - 1);
  CryptoPP::Integer A = a_exp_b_mod_c(DL_G, r, DL_P);
  CryptoPP::Integer B = a_exp_b_mod_c(pk, r, DL_P);

  CryptoPP::Integer sigma = hash_vector_vote_zkp(pk, C1, C2, A, B);

  CryptoPP::Integer r_prime = (r + a_times_b_mod_c(sigma, R, DL_Q)) % DL_Q;

  vector_vote_zkp.c1 = C1;
  vector_vote_zkp.c2 = C2;
  vector_vote_zkp.a = A;
  vector_vote_zkp.b = B;
  vector_vote_zkp.r = r_prime;

  return vector_vote_zkp;

}


bool ElectionClient::VerifyVectorVotesZKP(
  Vector_Vote_ZKP zkp, CryptoPP::Integer pk, int k) {
  initLogger();

  CryptoPP::Integer sigma = hash_vector_vote_zkp(pk, zkp.c1, zkp.c2, zkp.a, zkp.b);

  if (CryptoPP::ModularExponentiation(DL_G, zkp.r, DL_P) != a_times_b_mod_c(zkp.a, CryptoPP::ModularExponentiation(zkp.c1, sigma, DL_P), DL_P)) {
    return false;
  }

  CryptoPP::Integer pk_r = CryptoPP::ModularExponentiation(pk, zkp.r, DL_P);

  CryptoPP::Integer g_k = CryptoPP::ModularExponentiation(DL_G, k, DL_P);
  CryptoPP::Integer g_k_inv = CryptoPP::EuclideanMultiplicativeInverse(g_k, DL_P);
  CryptoPP::Integer C2_div_g_k = a_times_b_mod_c(zkp.c2, g_k_inv, DL_P);

  if (pk_r != a_times_b_mod_c(zkp.b, CryptoPP::ModularExponentiation(C2_div_g_k, sigma, DL_P), DL_P)) {
    return false;
  }

  return true;
}