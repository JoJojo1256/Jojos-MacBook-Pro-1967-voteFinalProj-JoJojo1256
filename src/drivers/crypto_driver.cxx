#include <iostream>
#include <stdexcept>
#include <string>

#include "crypto++/base64.h"
#include "crypto++/osrng.h"
#include "crypto++/pssr.h"
#include "crypto++/rsa.h"
#include <crypto++/cryptlib.h>
#include <crypto++/elgamal.h>
#include <crypto++/files.h>
#include <crypto++/nbtheory.h>
#include <crypto++/queue.h>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

/**
 * @brief Encrypts the given message using AES and tags the ciphertext with an
 * HMAC. Outputs an HMACTagged_Wrapper as bytes.
 */
std::vector<unsigned char>
CryptoDriver::encrypt_and_tag(SecByteBlock AES_key, SecByteBlock HMAC_key,
                              Serializable *message) {
  // Serialize given message.
  std::vector<unsigned char> plaintext;
  message->serialize(plaintext);

  // Encrypt the payload, generate iv to hmac.
  std::pair<std::string, SecByteBlock> encrypted =
      this->AES_encrypt(AES_key, chvec2str(plaintext));
  std::string to_tag = std::string((const char *)encrypted.second.data(),
                                   encrypted.second.size()) +
                       encrypted.first;

  // Generate HMAC on the payload.
  HMACTagged_Wrapper msg;
  msg.payload = str2chvec(encrypted.first);
  msg.iv = encrypted.second;
  msg.mac = this->HMAC_generate(HMAC_key, to_tag);

  // Serialize the HMAC and payload.
  std::vector<unsigned char> payload_data;
  msg.serialize(payload_data);
  return payload_data;
}

/**
 * @brief Verifies that the tagged HMAC is valid on the ciphertext and decrypts
 * the given message using AES. Takes in an HMACTagged_Wrapper as bytes.
 */
std::pair<std::vector<unsigned char>, bool>
CryptoDriver::decrypt_and_verify(SecByteBlock AES_key, SecByteBlock HMAC_key,
                                 std::vector<unsigned char> ciphertext_data) {
  // Deserialize
  HMACTagged_Wrapper ciphertext;
  ciphertext.deserialize(ciphertext_data);

  // Verify HMAC
  std::string to_verify =
      std::string((const char *)ciphertext.iv.data(), ciphertext.iv.size()) +
      chvec2str(ciphertext.payload);
  bool valid = this->HMAC_verify(HMAC_key, to_verify, ciphertext.mac);

  // Decrypt
  std::string plaintext =
      this->AES_decrypt(AES_key, ciphertext.iv, chvec2str(ciphertext.payload));
  std::vector<unsigned char> plaintext_data = str2chvec(plaintext);
  return std::make_pair(plaintext_data, valid);
}

/**
 * @brief Generate DH keypair.
 */
std::tuple<DH, SecByteBlock, SecByteBlock> CryptoDriver::DH_initialize() {
  DH DH_obj(DL_P, DL_Q, DL_G);
  AutoSeededRandomPool prng;
  SecByteBlock DH_private_key(DH_obj.PrivateKeyLength());
  SecByteBlock DH_public_key(DH_obj.PublicKeyLength());
  DH_obj.GenerateKeyPair(prng, DH_private_key, DH_public_key);
  return std::make_tuple(DH_obj, DH_private_key, DH_public_key);
}

/**
 * @brief Generates a shared secret.
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
    const DH &DH_obj, const SecByteBlock &DH_private_value,
    const SecByteBlock &DH_other_public_value) {
  SecByteBlock DH_shared_key(DH_obj.AgreedValueLength());
  if (!DH_obj.Agree(DH_shared_key, DH_private_value, DH_other_public_value)) {
    throw std::runtime_error("Error: failed to reach shared secret.");
  }
  return DH_shared_key;
}

/**
 * @brief Generates AES key using HKDF with a salt.
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key) {
  std::string aes_salt_str("salt0000");
  SecByteBlock aes_salt((const unsigned char *)(aes_salt_str.data()),
                        aes_salt_str.size());
  // Derive AES key using HKDF
  SecByteBlock AES_shared_key(AES::DEFAULT_KEYLENGTH);
  HKDF<SHA256> hkdf;
  hkdf.DeriveKey(AES_shared_key, AES_shared_key.size(), DH_shared_key,
                 DH_shared_key.size(), aes_salt, aes_salt.size(), NULL, 0);

  return AES_shared_key;
}

/**
 * @brief Encrypts the given plaintext.
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext) {
  try {
    // Create encryptor and set key
    CBC_Mode<AES>::Encryption AES_encryptor = CBC_Mode<AES>::Encryption();

    SecByteBlock iv(AES::BLOCKSIZE);
    AutoSeededRandomPool prng;
    AES_encryptor.GetNextIV(prng, iv.BytePtr());
    AES_encryptor.SetKeyWithIV(key, key.size(), iv);

    // Encrypt using a StreamTransformationFilter
    std::string ciphertext;
    StringSource ss1(plaintext, true,
                     new StreamTransformationFilter(
                         AES_encryptor, new StringSink(ciphertext)));

    return std::make_pair(ciphertext, iv);
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES encryption failed.");
  }
}

/**
 * @brief Decrypts the given ciphertext.
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext) {
  try {
    CBC_Mode<AES>::Decryption AES_decryptor = CBC_Mode<AES>::Decryption();
    AES_decryptor.SetKeyWithIV(key, key.size(), iv);

    // Decrypt using a StreamTransformationFilter
    std::string recovered;
    StringSource ss1(ciphertext, true,
                     new StreamTransformationFilter(AES_decryptor,
                                                    new StringSink(recovered)));
    return recovered;
  } catch (CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    std::cerr << "This function was likely called with an incorrect shared key."
              << std::endl;
    throw std::runtime_error("CryptoDriver AES decryption failed.");
  }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt.
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key) {
  std::string hmac_salt_str("salt0001");
  SecByteBlock hmac_salt((const unsigned char *)(hmac_salt_str.data()),
                         hmac_salt_str.size());
  // Derive 256 byte ECB key from DH shared key using KDF
  HKDF<SHA256> hkdf;
  SecByteBlock HMAC_shared_key(SHA256::BLOCKSIZE);
  hkdf.DeriveKey(HMAC_shared_key, HMAC_shared_key.size(), DH_shared_key,
                 DH_shared_key.size(), hmac_salt, hmac_salt.size(), NULL, 0);
  return HMAC_shared_key;
}

/**
 * @brief Given a ciphertext, generates an HMAC
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext) {
  try {
    std::string mac;
    HMAC<SHA256> hmac(key, key.size());
    StringSource ss2(ciphertext, true,
                     new HashFilter(hmac, new StringSink(mac)));
    return mac;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    throw std::runtime_error("CryptoDriver HMAC generation failed.");
  }
}

/**
 * @brief Given a message and MAC, checks the MAC is valid.
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac) {
  const int flags = HashVerificationFilter::THROW_EXCEPTION |
                    HashVerificationFilter::HASH_AT_END;
  try {
    HMAC<SHA256> hmac(key, key.size());
    StringSource(ciphertext + mac, true,
                 new HashVerificationFilter(hmac, NULL, flags));
    return true;
  } catch (const CryptoPP::Exception &e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

/**
 * @brief Generates a pair of El Gamal keys. This function should:
 * 1) Generate a random `a` value using an CryptoPP::AutoSeededRandomPool
      from the range (1, q-1].
 * 2) Exponentiate the base DL_G to get the public value,
 *    then return (private key, public key)
 */
std::pair<CryptoPP::Integer, CryptoPP::Integer> CryptoDriver::EG_generate() {
  // TODO: implement me!
  CryptoPP::AutoSeededRandomPool prng;
    // Generate a random number in [min, max]
    // where is q from????
  CryptoPP::Integer a = Integer(prng, 2, DL_Q - 1);
  CryptoPP::Integer A = CryptoPP::ModularExponentiation(DL_G, a, DL_P);
  return std::make_pair(a, A);
}

/**
 * @brief Generates RSA public and private keys with key size RSA_KEYSIZE.
 * Suitable for both normal RSA signatures and RSA blind signatures.
 */
std::pair<RSA::PrivateKey, RSA::PublicKey> CryptoDriver::RSA_generate_keys() {
  // TODO: implement me!
AutoSeededRandomPool rng;
  RSA::PrivateKey private_key;
  private_key.GenerateRandomWithKeySize(rng, RSA_KEYSIZE);
  RSA::PublicKey public_key(private_key);
  
  if (!private_key.Validate(rng, 3) || !public_key.Validate(rng, 3)) {
    throw std::runtime_error("CryptoDriver RSA key generation failed.");
  }
  return std::make_pair(private_key, public_key);
}

/**
 * @brief Sign the given message with the given signing key.
 */
std::string CryptoDriver::RSA_sign(const RSA::PrivateKey &signing_key,
                                   std::vector<unsigned char> message) {
  // TODO: implement me!
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(signing_key);
  std::string msg_str = chvec2str(message);

  // Sign the message
  std::string signature;
  CryptoPP::AutoSeededRandomPool rng;

  CryptoPP::StringSource(msg_str, true,
    new CryptoPP::SignerFilter(rng, signer,
      new CryptoPP::StringSink(signature)
    ) 
    ); 

  return signature;
}

/**
 * @brief Verify that signature is valid on message with the verification_key.
 */
bool CryptoDriver::RSA_verify(const RSA::PublicKey &verification_key,
                              std::vector<unsigned char> message,
                              std::string signature) {
  const int flags = SignatureVerificationFilter::PUT_RESULT |
                    SignatureVerificationFilter::SIGNATURE_AT_END;
  // TODO: implement me!
  std::string message_str = chvec2str(message);
  CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier verifier(verification_key);
  bool result = false;

    // Verify signature using SignatureVerificationFilter
    StringSource ss(message_str + signature, true,
        new SignatureVerificationFilter(
            verifier,
            new ArraySink((byte*)&result, sizeof(result)),
            flags
        ) // SignatureVerificationFilter
    ); // StringSource

    return result;
}

/**
 * @brief Blinds the given message using the given public key.
 */
std::pair<CryptoPP::Integer, CryptoPP::Integer>
CryptoDriver::RSA_BLIND_blind(const RSA::PublicKey &public_key,
                              Serializable &msg) {
  // Convenience
  CryptoPP::AutoSeededRandomPool prng;
  const CryptoPP::Integer n = public_key.GetModulus();
  const CryptoPP::Integer e = public_key.GetPublicExponent();
  const size_t SIG_SIZE = n.ByteCount();

  // Convert the msg to a secbyteblock
  std::vector<unsigned char> msg_buff;
  msg.serialize(msg_buff);
  CryptoPP::SecByteBlock msg_block =
      CryptoPP::SecByteBlock(msg_buff.data(), msg_buff.size());

  // Hash the message using a FDH
  CryptoPP::SecByteBlock msg_hash = FDH_hash(msg_block, SIG_SIZE);

  // Convert the hash to an integer modulo n
  CryptoPP::Integer hm(msg_hash.data(), msg_hash.size());
  hm = hm % n;

  // [STUDENTS] Now:
  // 1) Generate a random number r that is relatively prime to n
  // 2) Compute the blinded message mm = (hm * r^e) % n
  // 3) Return the blinded message and the blinding factor r
  // See https://www.cryptopp.com/wiki/Blind_Signature for reference
  // TODO: implement me!
  CryptoPP::Integer r;
  do {
    r.Randomize(prng, 1, n - 1);
  } while (!RelativelyPrime(r, n));


  CryptoPP::Integer mm = (hm * CryptoPP::ModularExponentiation(r, e, n)) % n;
  return std::make_pair(mm, r);
}

/**
 * @brief Signs the given blinded message using the given private key.
 */
CryptoPP::Integer
CryptoDriver::RSA_BLIND_sign(const RSA::PrivateKey &private_key,
                             CryptoPP::Integer blinded_msg) {
  // TODO: implement me!
  CryptoPP::AutoSeededRandomPool prng;
  const CryptoPP::Integer n = private_key.GetModulus();
  const CryptoPP::Integer d = private_key.GetPrivateExponent(); 
  return CryptoPP::ModularExponentiation(blinded_msg, d, n);
}

/**
 * @brief Unblinds the given signed message using the given public key.
 */
CryptoPP::Integer
CryptoDriver::RSA_BLIND_unblind(const RSA::PublicKey &public_key,
                                CryptoPP::Integer signed_blind_msg,
                                CryptoPP::Integer blind) {
  // TODO: implement me!
  const CryptoPP::Integer n = public_key.GetModulus();

  // Compute the inverse of blind mod n
  CryptoPP::Integer blind_inverse = CryptoPP::EuclideanMultiplicativeInverse(blind, n);

  // Safety check: if inverse doesn't exist, throw error
  if (blind_inverse == 0) {
    throw std::runtime_error("Blind factor has no inverse mod n!");
  }

  // Unblind the signature: s = (s' * r^-1) mod n
  CryptoPP::Integer unblinded_signature = a_times_b_mod_c(signed_blind_msg, blind_inverse, n);

  return unblinded_signature;
}

/**
 * @brief Verifies the given signature.
 */
bool CryptoDriver::RSA_BLIND_verify(const RSA::PublicKey &public_key,
                                    Serializable &msg,
                                    CryptoPP::Integer signature) {
  // Convenience
  const size_t SIG_SIZE = public_key.GetModulus().ByteCount();
  const CryptoPP::Integer n = public_key.GetModulus();
  const CryptoPP::Integer e = public_key.GetPublicExponent();

  // Convert the msg to a secbyteblock
  std::vector<unsigned char> msg_buff;
  msg.serialize(msg_buff);
  CryptoPP::SecByteBlock msg_block =
      CryptoPP::SecByteBlock(msg_buff.data(), msg_buff.size());

  // Hash the message using a FDH and convert to integer modulo n
  CryptoPP::SecByteBlock hash = FDH_hash(msg_block, SIG_SIZE);
  CryptoPP::Integer hm(hash.data(), hash.size());
  hm = hm % n;

  // [STUDENTS] Now:
  // 1) Raise the signature to the power of e modulo n.
  // You may see this referred to as "applying the trapdoor"
  // in documentation, or as the function "ApplyFunction" in the
  // CryptoPP wiki.
  // 2) Compare the result to the hash of the message (`hm`) and return
  // TODO: implement me!
  CryptoPP::Integer signed_hash = CryptoPP::ModularExponentiation(signature, e, n);
  return signed_hash == hm;
}

/**
 * @brief Uses HKDF to hash the given message to the desired domain size (in
 * bits)
 */
SecByteBlock CryptoDriver::FDH_hash(SecByteBlock input, int domain_byte_size) {
  // Account for statistical security
  domain_byte_size = domain_byte_size + LAMBDA / 8;

  // Hash and return. Note that the resulting hash, when converted
  // to an integer, may be much larger than the domain bit size and
  // will need to be reduced modulo n.
  HKDF<SHA256> hkdf;
  SecByteBlock hash(domain_byte_size);
  hkdf.DeriveKey(hash, hash.size(), input, input.size(), NULL, 0, NULL, 0);
  return hash;
}