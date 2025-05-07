#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/rsa.h>

// ================================================
// MESSAGE TYPES
// ================================================

namespace MessageType {
enum T {
  HMACTagged_Wrapper = 1,
  UserToServer_DHPublicValue_Message = 2,
  ServerToUser_DHPublicValue_Message = 3,
  VoterToRegistrar_Register_Message = 4,
  RegistrarToVoter_Blind_Signature_Message = 5,
  Vote_Ciphertext = 6,
  VoteZKP_Struct = 7,
  VoterToTallyer_Vote_Message = 8,
  TallyerToWorld_Vote_Message = 9,
  PartialDecryption_Struct = 10,
  DecryptionZKP_Struct = 11,
  ArbiterToWorld_PartialDecryption_Message = 12,
  Vector_Vote_ZKP = 13,
};
};
MessageType::T get_message_type(std::vector<unsigned char> &data);

// ================================================
// SERIALIZABLE
// ================================================

struct Serializable {
  virtual void serialize(std::vector<unsigned char> &data) = 0;
  virtual int deserialize(std::vector<unsigned char> &data) = 0;
};

// serializers.
int put_bool(bool b, std::vector<unsigned char> &data);
int put_string(std::string s, std::vector<unsigned char> &data);
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data);

// deserializers
int get_bool(bool *b, std::vector<unsigned char> &data, int idx);
int get_string(std::string *s, std::vector<unsigned char> &data, int idx);
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx);

// ================================================
// WRAPPERS
// ================================================

struct HMACTagged_Wrapper : public Serializable {
  std::vector<unsigned char> payload;
  CryptoPP::SecByteBlock iv;
  std::string mac;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// Struct for a vote, v, as an
// ElGamal ciphertext (a, b) := (g^r, pk^r * g^v)
struct Vote_Ciphertext : public Serializable {
  CryptoPP::Integer a;
  CryptoPP::Integer b;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// KEY EXCHANGE
// ================================================

struct UserToServer_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock public_value;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ServerToUser_DHPublicValue_Message : public Serializable {
  CryptoPP::SecByteBlock server_public_value;
  CryptoPP::SecByteBlock user_public_value;
  std::string server_signature; // computed on server_value + user_value

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// VOTER <==> REGISTRAR
// ================================================

struct VoterToRegistrar_Register_Message : public Serializable {
  std::string id;
  CryptoPP::Integer vote;

  std::vector<CryptoPP::Integer> votes;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct RegistrarToVoter_Blind_Signature_Message : public Serializable {
  std::string id;
  CryptoPP::Integer registrar_signature;

  std::vector<CryptoPP::Integer> registrar_signatures;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// VOTER <==> TALLYER
// ================================================

// Struct for a dcp zkp of vote (a, b):
// (aβ, bβ, cβ, rβ) = (g^r, pk^r, cβ, r''β)
struct VoteZKP_Struct : public Serializable {
  CryptoPP::Integer a0;
  CryptoPP::Integer a1;
  CryptoPP::Integer b0;
  CryptoPP::Integer b1;
  CryptoPP::Integer c0;
  CryptoPP::Integer c1;
  CryptoPP::Integer r0;
  CryptoPP::Integer r1;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct VoterToTallyer_Vote_Message : public Serializable {
  Vote_Ciphertext vote;
  CryptoPP::Integer unblinded_signature;
  VoteZKP_Struct zkp;

  std::vector<Vote_Ciphertext> votes;
  std::vector<VoteZKP_Struct> zkps;
  std::vector<CryptoPP::Integer> unblinded_signatures;
  Vector_Vote_ZKP vector_vote_zkp;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct TallyerToWorld_Vote_Message : public Serializable {
  Vote_Ciphertext vote;
  VoteZKP_Struct zkp;
  CryptoPP::Integer unblinded_signature;
  std::string
      tallyer_signature; // computed on vote || zkp || unblinded_signature


  std::vector<Vote_Ciphertext> votes;
  std::vector<VoteZKP_Struct> zkps;
  std::vector<CryptoPP::Integer> unblinded_signatures;
  std::vector<std::string> tallyer_signatures;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// ARBITER <==> WORLD
// ================================================

// Struct for a pd of `aggregate_ciphertext` (d) = (g^{r sk_i})
struct PartialDecryption_Struct : public Serializable {
  CryptoPP::Integer d;
  Vote_Ciphertext aggregate_ciphertext;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// Struct for a pd zkp of vote (a, b): (u, v, s) = (a^r, g^r, s)
struct DecryptionZKP_Struct : public Serializable {
  CryptoPP::Integer u;
  CryptoPP::Integer v;
  CryptoPP::Integer s;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

struct ArbiterToWorld_PartialDecryption_Message : public Serializable {
  std::string arbiter_id;
  std::string arbiter_vk_path;
  PartialDecryption_Struct dec;
  DecryptionZKP_Struct zkp;

  size_t id;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

// ================================================
// SIGNING HELPERS
// ================================================

std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2);
std::vector<unsigned char>
concat_vote_zkp_and_signature(Vote_Ciphertext &vote, VoteZKP_Struct &zkp,
                              CryptoPP::Integer &signature);


// ================================================
// NEW STRUCTS
// ================================================         

struct Vector_Vote_ZKP : public Serializable {
  CryptoPP::Integer c1;
  CryptoPP::Integer c2;
  CryptoPP::Integer a;
  CryptoPP::Integer b;
  CryptoPP::Integer r;

  void serialize(std::vector<unsigned char> &data);
  int deserialize(std::vector<unsigned char> &data);
};

