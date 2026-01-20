#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>
#include <span>
#include <vector>

#include "common/crypto/crypto_engine.h"
#include "common/crypto/random.h"

namespace veil::tests {

TEST(CryptoEngineTests, HkdfProducesDifferentOutputsForDifferentInfo) {
  std::array<std::uint8_t, crypto::kHmacSha256Len> prk{};
  prk.fill(0x11);
  const std::array<std::uint8_t, 1> info_a{0x61};
  const std::array<std::uint8_t, 1> info_b{0x62};
  const auto first = crypto::hkdf_expand(prk, std::span(info_a), 32);
  const auto second = crypto::hkdf_expand(prk, std::span(info_b), 32);
  ASSERT_EQ(first.size(), second.size());
  EXPECT_NE(first, second);
}

TEST(CryptoEngineTests, AeadRoundTrip) {
  const auto key_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  const auto base_nonce_vec = crypto::random_bytes(crypto::kNonceLen);

  std::array<std::uint8_t, crypto::kAeadKeyLen> key{};
  std::copy(key_vec.begin(), key_vec.end(), key.begin());
  std::array<std::uint8_t, crypto::kNonceLen> base_nonce{};
  std::copy(base_nonce_vec.begin(), base_nonce_vec.end(), base_nonce.begin());

  const auto nonce = crypto::derive_nonce(base_nonce, 1);
  const std::vector<std::uint8_t> aad = {'m', 'e', 't', 'a'};
  const std::vector<std::uint8_t> message = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
  const auto ciphertext = crypto::aead_encrypt(key, nonce, aad, message);
  const auto decrypted =
      crypto::aead_decrypt(key, nonce, aad, ciphertext);
  ASSERT_TRUE(decrypted.has_value());
  const auto& plain = decrypted.value();
  EXPECT_EQ(plain, message);
}

TEST(CryptoEngineTests, SessionKeysAlignBetweenPeers) {
  const auto a = crypto::generate_x25519_keypair();
  const auto b = crypto::generate_x25519_keypair();
  const auto salt = crypto::random_bytes(16);
  const std::array<std::uint8_t, crypto::kSharedSecretSize> shared_a =
      crypto::compute_shared_secret(a.secret_key, b.public_key);
  const std::array<std::uint8_t, crypto::kSharedSecretSize> shared_b =
      crypto::compute_shared_secret(b.secret_key, a.public_key);
  ASSERT_EQ(shared_a, shared_b);

  const std::array<std::uint8_t, 8> info_bytes{0, 1, 2, 3, 4, 5, 6, 7};

  const auto initiator_keys =
      crypto::derive_session_keys(shared_a, salt, info_bytes, true);
  const auto responder_keys =
      crypto::derive_session_keys(shared_b, salt, info_bytes, false);

  EXPECT_EQ(initiator_keys.send_key, responder_keys.recv_key);
  EXPECT_EQ(initiator_keys.recv_key, responder_keys.send_key);
  EXPECT_EQ(initiator_keys.send_nonce, responder_keys.recv_nonce);
  EXPECT_EQ(initiator_keys.recv_nonce, responder_keys.send_nonce);
}

TEST(CryptoEngineTests, DecryptFailureOnTamper) {
  const auto key_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  const auto base_nonce_vec = crypto::random_bytes(crypto::kNonceLen);

  std::array<std::uint8_t, crypto::kAeadKeyLen> key{};
  std::copy(key_vec.begin(), key_vec.end(), key.begin());
  std::array<std::uint8_t, crypto::kNonceLen> base_nonce{};
  std::copy(base_nonce_vec.begin(), base_nonce_vec.end(), base_nonce.begin());

  const auto nonce = crypto::derive_nonce(base_nonce, 5);
  const std::vector<std::uint8_t> aad = {'m', 'e', 't', 'a'};
  const std::vector<std::uint8_t> message = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
  auto ciphertext = crypto::aead_encrypt(key, nonce, aad, message);
  ciphertext[0] ^= 0x01;
  const auto decrypted =
      crypto::aead_decrypt(key, nonce, aad, ciphertext);
  EXPECT_FALSE(decrypted.has_value());
}

// Issue #21: Sequence number obfuscation tests for DPI resistance
TEST(CryptoEngineTests, SequenceObfuscationRoundTrip) {
  const auto key_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  std::array<std::uint8_t, crypto::kAeadKeyLen> key{};
  std::copy(key_vec.begin(), key_vec.end(), key.begin());

  // Test various sequence values
  const std::vector<std::uint64_t> test_sequences = {
      0, 1, 42, 0x1234567890ABCDEF, std::numeric_limits<std::uint64_t>::max()
  };

  for (const auto original_seq : test_sequences) {
    const auto obfuscated = crypto::obfuscate_sequence(original_seq, key);
    const auto deobfuscated = crypto::deobfuscate_sequence(obfuscated, key);
    EXPECT_EQ(original_seq, deobfuscated)
        << "Failed round-trip for sequence " << original_seq;
  }
}

TEST(CryptoEngineTests, SequenceObfuscationProducesRandomLookingOutput) {
  const auto key_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  std::array<std::uint8_t, crypto::kAeadKeyLen> key{};
  std::copy(key_vec.begin(), key_vec.end(), key.begin());

  // Consecutive sequences should not produce consecutive obfuscated values
  // (which would be detectable by DPI)
  const std::uint64_t seq1 = 1000;
  const std::uint64_t seq2 = 1001;
  const std::uint64_t seq3 = 1002;

  const auto obf1 = crypto::obfuscate_sequence(seq1, key);
  const auto obf2 = crypto::obfuscate_sequence(seq2, key);
  const auto obf3 = crypto::obfuscate_sequence(seq3, key);

  // Obfuscated values should be very different despite small input differences
  EXPECT_NE(obf1, obf2);
  EXPECT_NE(obf2, obf3);
  EXPECT_NE(obf1, obf3);

  // The differences should be large (not just +1)
  EXPECT_GT(std::abs(static_cast<std::int64_t>(obf2 - obf1)), 1000);
  EXPECT_GT(std::abs(static_cast<std::int64_t>(obf3 - obf2)), 1000);
}

TEST(CryptoEngineTests, SequenceObfuscationDiffersByKey) {
  const auto key1_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  const auto key2_vec = crypto::random_bytes(crypto::kAeadKeyLen);

  std::array<std::uint8_t, crypto::kAeadKeyLen> key1{};
  std::array<std::uint8_t, crypto::kAeadKeyLen> key2{};
  std::copy(key1_vec.begin(), key1_vec.end(), key1.begin());
  std::copy(key2_vec.begin(), key2_vec.end(), key2.begin());

  const std::uint64_t sequence = 12345;

  const auto obf1 = crypto::obfuscate_sequence(sequence, key1);
  const auto obf2 = crypto::obfuscate_sequence(sequence, key2);

  // Same sequence with different keys should produce different obfuscated values
  EXPECT_NE(obf1, obf2);
}

TEST(CryptoEngineTests, DeriveSequenceObfuscationKeyProducesDifferentKeys) {
  const auto send_key1_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  const auto send_key2_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  const auto nonce_vec = crypto::random_bytes(crypto::kNonceLen);

  std::array<std::uint8_t, crypto::kAeadKeyLen> send_key1{};
  std::array<std::uint8_t, crypto::kAeadKeyLen> send_key2{};
  std::array<std::uint8_t, crypto::kNonceLen> nonce{};
  std::copy(send_key1_vec.begin(), send_key1_vec.end(), send_key1.begin());
  std::copy(send_key2_vec.begin(), send_key2_vec.end(), send_key2.begin());
  std::copy(nonce_vec.begin(), nonce_vec.end(), nonce.begin());

  const auto obf_key1 = crypto::derive_sequence_obfuscation_key(send_key1, nonce);
  const auto obf_key2 = crypto::derive_sequence_obfuscation_key(send_key2, nonce);

  // Different session keys should produce different obfuscation keys
  EXPECT_NE(obf_key1, obf_key2);
}

TEST(CryptoEngineTests, DeriveSequenceObfuscationKeyIsDeterministic) {
  const auto send_key_vec = crypto::random_bytes(crypto::kAeadKeyLen);
  const auto nonce_vec = crypto::random_bytes(crypto::kNonceLen);

  std::array<std::uint8_t, crypto::kAeadKeyLen> send_key{};
  std::array<std::uint8_t, crypto::kNonceLen> nonce{};
  std::copy(send_key_vec.begin(), send_key_vec.end(), send_key.begin());
  std::copy(nonce_vec.begin(), nonce_vec.end(), nonce.begin());

  const auto obf_key1 = crypto::derive_sequence_obfuscation_key(send_key, nonce);
  const auto obf_key2 = crypto::derive_sequence_obfuscation_key(send_key, nonce);

  // Same inputs should produce the same obfuscation key
  EXPECT_EQ(obf_key1, obf_key2);
}

}  // namespace veil::tests
