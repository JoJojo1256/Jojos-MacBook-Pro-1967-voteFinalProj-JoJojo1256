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
std::pair<Vote_Ciphertext, VoteZKP_Struct>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  initLogger();
  // TODO: implement me!
  Vote_Ciphertext ciphertext;
  VoteZKP_Struct zkp;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::Integer r(prng, 2, DL_Q - 1);

  ciphertext.a = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
  ciphertext.b = a_times_b_mod_c(CryptoPP::ModularExponentiation(pk, r, DL_P), CryptoPP::ModularExponentiation(DL_G, vote, DL_P), DL_P);



  if (vote == CryptoPP::Integer::One()) {
    CryptoPP::Integer double_r_prime_zero(prng, 2, DL_Q - 1);
    CryptoPP::Integer sigma_zero(prng, 2, DL_Q - 1);
    CryptoPP::Integer a0 = a_times_b_mod_c(CryptoPP::ModularExponentiation(DL_G, double_r_prime_zero, DL_P), CryptoPP::EuclideanMultiplicativeInverse((CryptoPP::ModularExponentiation(ciphertext.a, sigma_zero, DL_P)), DL_P), DL_P);
    CryptoPP::Integer b0 = a_times_b_mod_c(CryptoPP::ModularExponentiation(pk, double_r_prime_zero, DL_P), CryptoPP::EuclideanMultiplicativeInverse((CryptoPP::ModularExponentiation(ciphertext.b, sigma_zero, DL_P)), DL_P), DL_P);
    zkp.a0 = a0;
    zkp.b0 = b0;
    zkp.c0 = sigma_zero;
    zkp.r0 = double_r_prime_zero;
    CryptoPP::Integer r_prime_one = CryptoPP::Integer(prng, 2, DL_Q - 1);
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
    return std::make_pair(ciphertext, zkp);
  }
  return std::make_pair(ciphertext, zkp);
}

std::pair<Vector_Vote_Ciphertext, VectorVoteZKP_Struct>
ElectionClient::GenerateVectorVote(const std::vector<CryptoPP::Integer>& votes, 
                                  CryptoPP::Integer pk,
                                  CryptoPP::Integer k) {
  initLogger();
  
  // Validate votes count equals k
  CryptoPP::Integer sum = 0;
  for (const auto& vote : votes) {
    if (vote != CryptoPP::Integer::Zero() && vote != CryptoPP::Integer::One()) {
      CUSTOM_LOG(lg, error) << "Each vote must be 0 or 1";
      throw std::runtime_error("Each vote must be 0 or 1");
    }
    sum = sum + vote;
  }
  
  if (sum != k) {
    CUSTOM_LOG(lg, error) << "Must select exactly " << k << " candidates";
    throw std::runtime_error("Must select exactly k candidates");
  }
  
  // Generate individual vote encryptions and ZKPs
  Vector_Vote_Ciphertext vector_ciphertext;
  VectorVoteZKP_Struct vector_zkp;
  
  // Track sum of randomness for sum ZKP
  CryptoPP::Integer r_sum = CryptoPP::Integer::Zero();
  CryptoPP::AutoSeededRandomPool prng;
  
  for (const auto& vote : votes) {
    // Generate random r for this encryption
    CryptoPP::Integer r(prng, 2, DL_Q - 1);
    r_sum = (r_sum + r) % DL_Q;
    
    // Encrypt the vote
    Vote_Ciphertext ciphertext;
    ciphertext.a = CryptoPP::ModularExponentiation(DL_G, r, DL_P);
    ciphertext.b = a_times_b_mod_c(
      CryptoPP::ModularExponentiation(pk, r, DL_P),
      CryptoPP::ModularExponentiation(DL_G, vote, DL_P),
      DL_P
    );
    
    // Generate ZKP for this vote
    auto result = GenerateVote(vote, pk);
    
    // Store the vote and ZKP
    vector_ciphertext.votes.push_back(ciphertext);
    vector_zkp.individual_zkps.push_back(result.second);
  }
  
  // Generate ZKP for sum constraint
  
  // 1. Homomorphically combine all votes
  Vote_Ciphertext combined;
  combined.a = CryptoPP::Integer::One();
  combined.b = CryptoPP::Integer::One();
  
  for (const auto& vote : vector_ciphertext.votes) {
    combined.a = a_times_b_mod_c(combined.a, vote.a, DL_P);
    combined.b = a_times_b_mod_c(combined.b, vote.b, DL_P);
  }
  
  // 2. Adjust for k: combined/g^k should encrypt 0 if sum equals k
  CryptoPP::Integer adjusted_b = a_times_b_mod_c(
    combined.b, 
    CryptoPP::EuclideanMultiplicativeInverse(
      CryptoPP::ModularExponentiation(DL_G, k, DL_P), 
      DL_P
    ), 
    DL_P
  );
  
  // 3. Create ZKP that adjusted_combined encrypts 0
  CryptoPP::Integer r_prime(prng, 2, DL_Q - 1);
  vector_zkp.sum_zkp.A = CryptoPP::ModularExponentiation(DL_G, r_prime, DL_P);
  vector_zkp.sum_zkp.B = CryptoPP::ModularExponentiation(pk, r_prime, DL_P);
  
  // Create challenge
  CryptoPP::Integer sigma = hash_sum_zkp(pk, combined.a, adjusted_b, 
                                         vector_zkp.sum_zkp.A, vector_zkp.sum_zkp.B) % DL_Q;
  
  vector_zkp.sum_zkp.c = sigma;
  vector_zkp.sum_zkp.r = (r_prime + a_times_b_mod_c(sigma, r_sum, DL_Q)) % DL_Q;
  
  return std::make_pair(vector_ciphertext, vector_zkp);
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

bool ElectionClient::VerifyVectorVoteZKP(
  const std::pair<Vector_Vote_Ciphertext, VectorVoteZKP_Struct>& vector_vote, 
  CryptoPP::Integer pk,
  CryptoPP::Integer k) {
initLogger();

// 1. Verify each individual vote ZKP
for (size_t i = 0; i < vector_vote.first.votes.size(); i++) {
  if (!VerifyVoteZKP(
      std::make_pair(vector_vote.first.votes[i], vector_vote.second.individual_zkps[i]), 
      pk)) {
    CUSTOM_LOG(lg, debug) << "Individual vote ZKP verification failed for index " << i;
    return false;
  }
}

// 2. Verify the sum constraint ZKP
// Homomorphically combine all votes
Vote_Ciphertext combined;
combined.a = CryptoPP::Integer::One();
combined.b = CryptoPP::Integer::One();

for (const auto& vote : vector_vote.first.votes) {
  combined.a = a_times_b_mod_c(combined.a, vote.a, DL_P);
  combined.b = a_times_b_mod_c(combined.b, vote.b, DL_P);
}

// Adjust for k: combined/g^k should encrypt 0 if sum equals k
CryptoPP::Integer adjusted_b = a_times_b_mod_c(
  combined.b, 
  CryptoPP::EuclideanMultiplicativeInverse(
    CryptoPP::ModularExponentiation(DL_G, k, DL_P), 
    DL_P
  ), 
  DL_P
);

// Verify challenge
CryptoPP::Integer expected_sigma = hash_sum_zkp(pk, combined.a, adjusted_b, 
                                       vector_vote.second.sum_zkp.A, 
                                       vector_vote.second.sum_zkp.B) % DL_Q;

if (expected_sigma != vector_vote.second.sum_zkp.c) {
  CUSTOM_LOG(lg, debug) << "Sum ZKP challenge verification failed";
  return false;
}

// Verify proof values
if (CryptoPP::ModularExponentiation(DL_G, vector_vote.second.sum_zkp.r, DL_P) != 
    a_times_b_mod_c(vector_vote.second.sum_zkp.A, 
                    CryptoPP::ModularExponentiation(combined.a, vector_vote.second.sum_zkp.c, DL_P), 
                    DL_P)) {
  CUSTOM_LOG(lg, debug) << "Sum ZKP first verification equation failed";
  return false;
}

if (CryptoPP::ModularExponentiation(pk, vector_vote.second.sum_zkp.r, DL_P) != 
    a_times_b_mod_c(vector_vote.second.sum_zkp.B, 
                    CryptoPP::ModularExponentiation(adjusted_b, vector_vote.second.sum_zkp.c, DL_P), 
                    DL_P)) {
  CUSTOM_LOG(lg, debug) << "Sum ZKP second verification equation failed";
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

std::vector<std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>>
ElectionClient::PartialDecryptVector(
    const std::vector<Vote_Ciphertext>& combined_votes,
    CryptoPP::Integer pk, 
    CryptoPP::Integer sk) {
  initLogger();
  
  std::vector<std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>> results;
  
  for (const auto& combined_vote : combined_votes) {
    results.push_back(PartialDecrypt(combined_vote, pk, sk));
  }
  
  return results;
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

std::vector<Vote_Ciphertext> ElectionClient::CombineVectorVotes(
  const std::vector<VectorVoteRow>& all_votes) {
initLogger();

if (all_votes.empty()) {
  CUSTOM_LOG(lg, warning) << "No votes to combine";
  return {};
}

// Initialize combined votes for each candidate
size_t num_candidates = all_votes[0].vote.votes.size();
std::vector<Vote_Ciphertext> combined_votes(num_candidates);

for (size_t i = 0; i < num_candidates; i++) {
  combined_votes[i].a = CryptoPP::Integer::One();
  combined_votes[i].b = CryptoPP::Integer::One();
}

// Homomorphically combine votes for each candidate position
for (const auto& voter_row : all_votes) {
  for (size_t i = 0; i < num_candidates; i++) {
    combined_votes[i].a = a_times_b_mod_c(combined_votes[i].a, voter_row.vote.votes[i].a, DL_P);
    combined_votes[i].b = a_times_b_mod_c(combined_votes[i].b, voter_row.vote.votes[i].b, DL_P);
  }
}

return combined_votes;
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

std::vector<CryptoPP::Integer> ElectionClient::CombineVectorResults(
  const std::vector<Vote_Ciphertext>& combined_votes,
  const std::vector<std::vector<PartialDecryptionRow>>& all_partial_decryptions) {
initLogger();

std::vector<CryptoPP::Integer> results;

for (size_t i = 0; i < combined_votes.size(); i++) {
  results.push_back(CombineResults(combined_votes[i], all_partial_decryptions[i]));
}

return results;
}

CryptoPP::Integer hash_sum_zkp(
  CryptoPP::Integer pk, 
  CryptoPP::Integer a, 
  CryptoPP::Integer b,
  CryptoPP::Integer A, 
  CryptoPP::Integer B) {

CryptoPP::SHA256 hash;
byte digest[CryptoPP::SHA256::DIGESTSIZE];

// Convert all integers to byte arrays
std::vector<byte> pk_bytes = integer_to_bytes(pk);
std::vector<byte> a_bytes = integer_to_bytes(a);
std::vector<byte> b_bytes = integer_to_bytes(b);
std::vector<byte> A_bytes = integer_to_bytes(A);
std::vector<byte> B_bytes = integer_to_bytes(B);

// Update hash with all values
hash.Update(pk_bytes.data(), pk_bytes.size());
hash.Update(a_bytes.data(), a_bytes.size());
hash.Update(b_bytes.data(), b_bytes.size());
hash.Update(A_bytes.data(), A_bytes.size());
hash.Update(B_bytes.data(), B_bytes.size());

hash.Final(digest);

return bytes_to_integer(digest, CryptoPP::SHA256::DIGESTSIZE);
}