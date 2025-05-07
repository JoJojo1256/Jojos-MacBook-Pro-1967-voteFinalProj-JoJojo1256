#pragma once

#include <iostream>
#include <string>

#include <crypto++/base64.h>
#include <crypto++/cryptlib.h>
#include <crypto++/files.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/modes.h>
#include <crypto++/osrng.h>

#include "../include-shared/messages.hpp"

void SaveRSAPrivateKey(const std::string &filename,
                       const CryptoPP::PrivateKey &key);
void LoadRSAPrivateKey(const std::string &filename, CryptoPP::PrivateKey &key);

void SaveRSAPublicKey(const std::string &filename,
                      const CryptoPP::PublicKey &key);
void LoadRSAPublicKey(const std::string &filename, CryptoPP::PublicKey &key);

void SaveVote(const std::string &filename, Vote_Ciphertext &vote);
void LoadVote(const std::string &filename, Vote_Ciphertext &vote);

void SaveVoteZKP(const std::string &filename, VoteZKP_Struct &vote_zkp);
void LoadVoteZKP(const std::string &filename, VoteZKP_Struct &vote_zkp);

void SaveInteger(const std::string &filename, const CryptoPP::Integer &i);
void LoadInteger(const std::string &filename, CryptoPP::Integer &i);

void LoadElectionPublicKey(const std::vector<std::string> &filenames,
                           CryptoPP::Integer &public_key);
