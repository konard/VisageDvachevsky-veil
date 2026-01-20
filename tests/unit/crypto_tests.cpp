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

}  // namespace veil::tests
