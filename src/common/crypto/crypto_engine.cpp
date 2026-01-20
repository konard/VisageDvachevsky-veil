#include "common/crypto/crypto_engine.h"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "common/crypto/random.h"
#include "common/crypto/secure_buffer.h"

namespace {
void ensure_sodium_ready() {
  static const bool ready = [] { return sodium_init() >= 0; }();
  if (!ready) {
    throw std::runtime_error("libsodium initialization failed");
  }
}

std::array<std::uint8_t, veil::crypto::kHmacSha256Len> hmac_sha256_array(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
  std::array<std::uint8_t, veil::crypto::kHmacSha256Len> out{};
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init(&state, key.data(), key.size());
  crypto_auth_hmacsha256_update(&state, data.data(), data.size());
  crypto_auth_hmacsha256_final(&state, out.data());
  // SECURITY: Clear HMAC state containing key material
  sodium_memzero(&state, sizeof(state));
  return out;
}

void shift_block(std::array<std::uint8_t, veil::crypto::kNonceLen>& nonce, std::uint64_t counter) {
  for (std::size_t i = 0; i < 8; ++i) {
    nonce[veil::crypto::kNonceLen - 1 - i] ^= static_cast<std::uint8_t>((counter >> (8 * i)) & 0xFF);
  }
}
}  // namespace

namespace veil::crypto {

KeyPair generate_x25519_keypair() {
  ensure_sodium_ready();
  KeyPair kp{};
  randombytes_buf(kp.secret_key.data(), kp.secret_key.size());
  crypto_scalarmult_curve25519_base(kp.public_key.data(), kp.secret_key.data());
  return kp;
}

std::array<std::uint8_t, kSharedSecretSize> compute_shared_secret(
    std::span<const std::uint8_t, kX25519SecretKeySize> secret_key,
    std::span<const std::uint8_t, kX25519PublicKeySize> peer_public) {
  ensure_sodium_ready();
  std::array<std::uint8_t, kSharedSecretSize> shared{};
  if (crypto_scalarmult_curve25519(shared.data(), secret_key.data(), peer_public.data()) != 0) {
    throw std::runtime_error("shared secret derivation failed");
  }
  return shared;
}

std::vector<std::uint8_t> hmac_sha256(std::span<const std::uint8_t> key,
                                      std::span<const std::uint8_t> data) {
  ensure_sodium_ready();
  const auto out = hmac_sha256_array(key, data);
  return std::vector<std::uint8_t>(out.begin(), out.end());
}

std::array<std::uint8_t, kHmacSha256Len> hkdf_extract(std::span<const std::uint8_t> salt,
                                                      std::span<const std::uint8_t> ikm) {
  ensure_sodium_ready();
  if (salt.empty()) {
    std::array<std::uint8_t, kHmacSha256Len> zero_salt{};
    return hmac_sha256_array(zero_salt, ikm);
  }
  return hmac_sha256_array(salt, ikm);
}

std::vector<std::uint8_t> hkdf_expand(std::span<const std::uint8_t, kHmacSha256Len> prk,
                                      std::span<const std::uint8_t> info, std::size_t length) {
  ensure_sodium_ready();
  if (length > kHmacSha256Len * 255) {
    throw std::invalid_argument("hkdf_expand length too large");
  }
  std::vector<std::uint8_t> okm(length);
  std::vector<std::uint8_t> previous;
  std::size_t generated = 0;
  std::uint8_t counter = 1;
  while (generated < length) {
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, prk.data(), prk.size());
    if (!previous.empty()) {
      crypto_auth_hmacsha256_update(&state, previous.data(), previous.size());
    }
    if (!info.empty()) {
      crypto_auth_hmacsha256_update(&state, info.data(), info.size());
    }
    crypto_auth_hmacsha256_update(&state, &counter, 1);

    std::array<std::uint8_t, kHmacSha256Len> block{};
    crypto_auth_hmacsha256_final(&state, block.data());
    // SECURITY: Clear HMAC state containing key material
    sodium_memzero(&state, sizeof(state));

    const std::size_t to_copy = std::min<std::size_t>(block.size(), length - generated);
    std::copy_n(block.begin(), to_copy, okm.begin() + static_cast<std::ptrdiff_t>(generated));

    // SECURITY: Clear previous block before reassignment
    if (!previous.empty()) {
      sodium_memzero(previous.data(), previous.size());
    }
    previous.assign(block.begin(), block.end());

    // SECURITY: Clear the block after copying
    sodium_memzero(block.data(), block.size());

    generated += to_copy;
    ++counter;
  }

  // SECURITY: Clear final previous buffer
  if (!previous.empty()) {
    sodium_memzero(previous.data(), previous.size());
  }

  return okm;
}

SessionKeys derive_session_keys(std::span<const std::uint8_t, kSharedSecretSize> shared_secret,
                                std::span<const std::uint8_t> salt, std::span<const std::uint8_t> info,
                                bool initiator) {
  auto prk = hkdf_extract(salt, shared_secret);
  auto material = hkdf_expand(prk, info, 2 * kAeadKeyLen + 2 * kNonceLen);

  // SECURITY: Clear PRK immediately after use
  sodium_memzero(prk.data(), prk.size());

  SessionKeys keys{};
  std::size_t offset = 0;
  auto load_block = [&](auto& dest) {
    std::copy_n(material.begin() + static_cast<std::ptrdiff_t>(offset), dest.size(), dest.begin());
    offset += dest.size();
  };

  std::array<std::uint8_t, kAeadKeyLen> first_key{};
  std::array<std::uint8_t, kAeadKeyLen> second_key{};
  std::array<std::uint8_t, kNonceLen> first_nonce{};
  std::array<std::uint8_t, kNonceLen> second_nonce{};

  load_block(first_key);
  load_block(second_key);
  load_block(first_nonce);
  load_block(second_nonce);

  // SECURITY: Clear raw key material after extracting individual keys
  sodium_memzero(material.data(), material.size());

  if (initiator) {
    keys.send_key = first_key;
    keys.recv_key = second_key;
    keys.send_nonce = first_nonce;
    keys.recv_nonce = second_nonce;
  } else {
    keys.send_key = second_key;
    keys.recv_key = first_key;
    keys.send_nonce = second_nonce;
    keys.recv_nonce = first_nonce;
  }

  // SECURITY: Clear temporary key arrays
  sodium_memzero(first_key.data(), first_key.size());
  sodium_memzero(second_key.data(), second_key.size());
  sodium_memzero(first_nonce.data(), first_nonce.size());
  sodium_memzero(second_nonce.data(), second_nonce.size());

  return keys;
}

std::array<std::uint8_t, kNonceLen> derive_nonce(
    std::span<const std::uint8_t, kNonceLen> base_nonce, std::uint64_t counter) {
  std::array<std::uint8_t, kNonceLen> nonce{};
  std::copy(base_nonce.begin(), base_nonce.end(), nonce.begin());
  shift_block(nonce, counter);
  return nonce;
}

std::array<std::uint8_t, kAeadKeyLen> derive_sequence_obfuscation_key(
    std::span<const std::uint8_t, kAeadKeyLen> send_key,
    std::span<const std::uint8_t, kNonceLen> send_nonce) {
  ensure_sodium_ready();

  // Use HKDF to derive a separate key for sequence obfuscation.
  // We use send_key as the input key material (IKM) and a constant info string.
  // The send_nonce is included in the info to ensure uniqueness per session.
  constexpr const char* info_prefix = "veil-sequence-obfuscation-v1";

  // Create info = info_prefix || send_nonce
  std::vector<std::uint8_t> info;
  info.reserve(std::strlen(info_prefix) + send_nonce.size());
  info.insert(info.end(), info_prefix, info_prefix + std::strlen(info_prefix));
  info.insert(info.end(), send_nonce.begin(), send_nonce.end());

  // Extract phase with zero salt
  auto prk = hkdf_extract({}, send_key);

  // Expand to get obfuscation key
  auto expanded = hkdf_expand(prk, info, kAeadKeyLen);

  // SECURITY: Clear PRK immediately after use
  sodium_memzero(prk.data(), prk.size());

  std::array<std::uint8_t, kAeadKeyLen> obfuscation_key{};
  std::copy_n(expanded.begin(), kAeadKeyLen, obfuscation_key.begin());

  // SECURITY: Clear expanded material
  sodium_memzero(expanded.data(), expanded.size());

  return obfuscation_key;
}

std::uint64_t obfuscate_sequence(std::uint64_t sequence,
                                  std::span<const std::uint8_t, kAeadKeyLen> obfuscation_key) {
  ensure_sodium_ready();

  // Use a simplified 3-round Feistel network to create a pseudorandom permutation.
  // This is invertible and provides good obfuscation for DPI resistance.
  // Split the 64-bit sequence into two 32-bit halves and apply Feistel rounds.

  std::uint32_t left = static_cast<std::uint32_t>(sequence >> 32);
  std::uint32_t right = static_cast<std::uint32_t>(sequence & 0xFFFFFFFF);

  // Round 1
  std::array<std::uint8_t, 4 + 1> round1_input{};
  round1_input[0] = 1;  // Round number
  for (std::size_t i = 0; i < 4; ++i) {
    round1_input[1 + i] = static_cast<std::uint8_t>((right >> (8 * (3 - i))) & 0xFF);
  }
  std::array<std::uint8_t, 4> round1_output{};
  crypto_generichash(round1_output.data(), round1_output.size(),
                     round1_input.data(), round1_input.size(),
                     obfuscation_key.data(), obfuscation_key.size());
  std::uint32_t f1 = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    f1 = (f1 << 8) | round1_output[i];
  }
  left ^= f1;

  // Round 2
  std::array<std::uint8_t, 4 + 1> round2_input{};
  round2_input[0] = 2;
  for (std::size_t i = 0; i < 4; ++i) {
    round2_input[1 + i] = static_cast<std::uint8_t>((left >> (8 * (3 - i))) & 0xFF);
  }
  std::array<std::uint8_t, 4> round2_output{};
  crypto_generichash(round2_output.data(), round2_output.size(),
                     round2_input.data(), round2_input.size(),
                     obfuscation_key.data(), obfuscation_key.size());
  std::uint32_t f2 = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    f2 = (f2 << 8) | round2_output[i];
  }
  right ^= f2;

  // Round 3
  std::array<std::uint8_t, 4 + 1> round3_input{};
  round3_input[0] = 3;
  for (std::size_t i = 0; i < 4; ++i) {
    round3_input[1 + i] = static_cast<std::uint8_t>((right >> (8 * (3 - i))) & 0xFF);
  }
  std::array<std::uint8_t, 4> round3_output{};
  crypto_generichash(round3_output.data(), round3_output.size(),
                     round3_input.data(), round3_input.size(),
                     obfuscation_key.data(), obfuscation_key.size());
  std::uint32_t f3 = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    f3 = (f3 << 8) | round3_output[i];
  }
  left ^= f3;

  // Combine halves
  return (static_cast<std::uint64_t>(left) << 32) | right;
}

std::uint64_t deobfuscate_sequence(std::uint64_t obfuscated_sequence,
                                    std::span<const std::uint8_t, kAeadKeyLen> obfuscation_key) {
  ensure_sodium_ready();

  // Inverse Feistel network - apply rounds in reverse order
  std::uint32_t left = static_cast<std::uint32_t>(obfuscated_sequence >> 32);
  std::uint32_t right = static_cast<std::uint32_t>(obfuscated_sequence & 0xFFFFFFFF);

  // Inverse Round 3
  std::array<std::uint8_t, 4 + 1> round3_input{};
  round3_input[0] = 3;
  for (std::size_t i = 0; i < 4; ++i) {
    round3_input[1 + i] = static_cast<std::uint8_t>((right >> (8 * (3 - i))) & 0xFF);
  }
  std::array<std::uint8_t, 4> round3_output{};
  crypto_generichash(round3_output.data(), round3_output.size(),
                     round3_input.data(), round3_input.size(),
                     obfuscation_key.data(), obfuscation_key.size());
  std::uint32_t f3 = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    f3 = (f3 << 8) | round3_output[i];
  }
  left ^= f3;

  // Inverse Round 2
  std::array<std::uint8_t, 4 + 1> round2_input{};
  round2_input[0] = 2;
  for (std::size_t i = 0; i < 4; ++i) {
    round2_input[1 + i] = static_cast<std::uint8_t>((left >> (8 * (3 - i))) & 0xFF);
  }
  std::array<std::uint8_t, 4> round2_output{};
  crypto_generichash(round2_output.data(), round2_output.size(),
                     round2_input.data(), round2_input.size(),
                     obfuscation_key.data(), obfuscation_key.size());
  std::uint32_t f2 = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    f2 = (f2 << 8) | round2_output[i];
  }
  right ^= f2;

  // Inverse Round 1
  std::array<std::uint8_t, 4 + 1> round1_input{};
  round1_input[0] = 1;
  for (std::size_t i = 0; i < 4; ++i) {
    round1_input[1 + i] = static_cast<std::uint8_t>((right >> (8 * (3 - i))) & 0xFF);
  }
  std::array<std::uint8_t, 4> round1_output{};
  crypto_generichash(round1_output.data(), round1_output.size(),
                     round1_input.data(), round1_input.size(),
                     obfuscation_key.data(), obfuscation_key.size());
  std::uint32_t f1 = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    f1 = (f1 << 8) | round1_output[i];
  }
  left ^= f1;

  // Combine halves
  return (static_cast<std::uint64_t>(left) << 32) | right;
}

std::vector<std::uint8_t> aead_encrypt(std::span<const std::uint8_t, kAeadKeyLen> key,
                                       std::span<const std::uint8_t, kNonceLen> nonce,
                                       std::span<const std::uint8_t> aad,
                                       std::span<const std::uint8_t> plaintext) {
  ensure_sodium_ready();
  std::vector<std::uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long out_len = 0;
  const auto rc = crypto_aead_chacha20poly1305_ietf_encrypt(
      ciphertext.data(), &out_len, plaintext.data(), plaintext.size(), aad.data(), aad.size(),
      nullptr, nonce.data(), key.data());
  if (rc != 0) {
    throw std::runtime_error("encryption failed");
  }
  ciphertext.resize(out_len);
  return ciphertext;
}

std::optional<std::vector<std::uint8_t>> aead_decrypt(
    std::span<const std::uint8_t, kAeadKeyLen> key, std::span<const std::uint8_t, kNonceLen> nonce,
    std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext) {
  ensure_sodium_ready();
  if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> plaintext(ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
  unsigned long long out_len = 0;
  const auto rc = crypto_aead_chacha20poly1305_ietf_decrypt(
      plaintext.data(), &out_len, nullptr, ciphertext.data(), ciphertext.size(), aad.data(),
      aad.size(), nonce.data(), key.data());
  if (rc != 0) {
    return std::nullopt;
  }
  plaintext.resize(out_len);
  return plaintext;
}

}  // namespace veil::crypto
