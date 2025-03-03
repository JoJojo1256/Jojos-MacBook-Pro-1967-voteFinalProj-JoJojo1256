#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../include/drivers/crypto_driver.hpp"
#include "../include/drivers/network_driver.hpp"
#include "../include/pkg/election.hpp"
#include "doctest/doctest.h"


TEST_CASE("sample") {
    std::cout << "TESTING: sanity-election-vote-0" << std::endl;

    CryptoDriver bob_crypto_driver;
    std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
        bob_crypto_driver.EG_generate();

    ElectionClient alice_election;
    std::pair<Vote_Ciphertext, VoteZKP_Struct> alice_vote =
        alice_election.GenerateVote(CryptoPP::Integer::Zero(), keys.second);

    ElectionClient bob_election;
    CHECK(bob_election.VerifyVoteZKP(alice_vote, keys.second));
}
