#include "../include-shared/util.hpp"

/**
 * Convert char vec to string.
 */
std::string chvec2str(std::vector<unsigned char> data) {
  std::string s(data.begin(), data.end());
  return s;
}

/**
 * Convert string to char vec.
 */
std::vector<unsigned char> str2chvec(std::string s) {
  std::vector<unsigned char> v(s.begin(), s.end());
  return v;
}

/**
 * Convert char vec to string.
 */
std::string hex_encode(std::string s) {
  std::string res;
  CryptoPP::StringSource(
      s, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(res)));
  return res;
}

/**
 * Convert string to char vec.
 */
std::string hex_decode(std::string s) {
  std::string res;
  CryptoPP::StringSource(
      s, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(res)));
  return res;
}

/**
 * Converts a byte block into an integer.
 */
CryptoPP::Integer byteblock_to_integer(CryptoPP::SecByteBlock block) {
  return CryptoPP::Integer(block, block.size());
}

/**
 * Converts an integer into a byte block.
 */
CryptoPP::SecByteBlock integer_to_byteblock(CryptoPP::Integer x) {
  size_t encodedSize = x.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
  CryptoPP::SecByteBlock bytes(encodedSize);
  x.Encode(bytes.BytePtr(), encodedSize, CryptoPP::Integer::UNSIGNED);
  return bytes;
}

/**
 * Converts a byte block into a string.
 */
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block) {
  return std::string(block.begin(), block.end());
}

/**
 * Converts a string into a byte block.
 */
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s) {
  CryptoPP::SecByteBlock block(reinterpret_cast<const unsigned char *>(&s[0]), s.size());
  return block;
}

/**
 * Converts an integer to a string
 * Example: 123 -> "123"
 */
std::string integer_to_string(CryptoPP::Integer x) {
  return CryptoPP::IntToString(x);
}

/**
 * Converts a string to an integer
 * Example: "123" -> 123
 */
CryptoPP::Integer string_to_integer(const std::string &s) {
  return CryptoPP::Integer(s.c_str());
}

/**
 * Given a string, it prints its hex representation of the raw bytes it
 * contains. Used for debugging.
 */
void print_string_as_hex(std::string str) {
  for (int i = 0; i < str.length(); i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(str[i]) << " ";
  }
  std::cout << std::endl;
}

/**
 * Prints contents as integer
 */
void print_key_as_int(CryptoPP::SecByteBlock block) {
  std::cout << byteblock_to_integer(block) << std::endl;
}

/**
 * Prints contents as hex.
 */
void print_key_as_hex(CryptoPP::SecByteBlock block) {
  std::string result;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));

  encoder.Put(block, block.size());
  encoder.MessageEnd();

  std::cout << result << std::endl;
}

/**
 * Split a string.
 */
std::vector<std::string> string_split(std::string str, char delimiter) {
  std::vector<std::string> result;
  // construct a stream from the string
  std::stringstream ss(str);
  std::string s;
  while (std::getline(ss, s, delimiter)) {
    result.push_back(s);
  }
  return result;
}

/**
 * Hash vote zkp
 */
CryptoPP::Integer hash_vote_zkp(CryptoPP::Integer pk, CryptoPP::Integer a,
                                CryptoPP::Integer b, CryptoPP::Integer a0_p,
                                CryptoPP::Integer b0_p, CryptoPP::Integer a1_p,
                                CryptoPP::Integer b1_p) {
  std::string res;
  res += CryptoPP::IntToString(pk);
  res += CryptoPP::IntToString(a);
  res += CryptoPP::IntToString(b);
  res += CryptoPP::IntToString(a0_p);
  res += CryptoPP::IntToString(b0_p);
  res += CryptoPP::IntToString(a1_p);
  res += CryptoPP::IntToString(b1_p);

  CryptoPP::SHA256 hash;
  std::string encodedHex;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encodedHex));
  CryptoPP::StringSource(
      res, true,
      new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(encodedHex)));
  return CryptoPP::Integer(("0x" + encodedHex).c_str());
}

/**
 * Hash partial decryption zkp
 */
CryptoPP::Integer hash_dec_zkp(CryptoPP::Integer pk, CryptoPP::Integer a,
                               CryptoPP::Integer b, CryptoPP::Integer u,
                               CryptoPP::Integer v) {
  std::string res;
  res += CryptoPP::IntToString(pk);
  res += CryptoPP::IntToString(a);
  res += CryptoPP::IntToString(b);
  res += CryptoPP::IntToString(u);
  res += CryptoPP::IntToString(v);

  CryptoPP::SHA256 hash;
  std::string encodedHex;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encodedHex));
  CryptoPP::StringSource(
      res, true,
      new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(encodedHex)));
  return CryptoPP::Integer(("0x" + encodedHex).c_str());
}