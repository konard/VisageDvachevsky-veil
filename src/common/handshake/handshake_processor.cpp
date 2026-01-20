#include "common/handshake/handshake_processor.h"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

#include "common/crypto/random.h"
namespace {
// Internal magic bytes used inside encrypted payload (not visible to DPI)
constexpr std::array<std::uint8_t, 2> kMagic{'H', 'S'};
constexpr std::uint8_t kVersion = 1;

// AEAD tag size for ChaCha20-Poly1305
constexpr std::size_t kAeadTagLen = crypto_aead_chacha20poly1305_ietf_ABYTES;  // 16 bytes

// Label for deriving handshake encryption key from PSK
constexpr std::array<std::uint8_t, 24> kHandshakeKeyLabel{
    'V', 'E', 'I', 'L', '-', 'H', 'A', 'N', 'D', 'S', 'H', 'A',
    'K', 'E', '-', 'O', 'B', 'F', 'U', 'S', 'C', 'A', 'T', 'E'};

// Handshake padding configuration (DPI resistance)
constexpr std::uint16_t kMinPaddingSize = 32;   // Minimum padding bytes
constexpr std::uint16_t kMaxPaddingSize = 400;  // Maximum padding bytes

// Derive a key for handshake packet obfuscation from PSK
std::array<std::uint8_t, veil::crypto::kAeadKeyLen> derive_handshake_key(
    std::span<const std::uint8_t> psk) {
  // Use HKDF to derive handshake encryption key
  auto prk = veil::crypto::hkdf_extract({}, psk);  // empty salt
  auto key_material = veil::crypto::hkdf_expand(prk, kHandshakeKeyLabel, veil::crypto::kAeadKeyLen);

  // SECURITY: Clear PRK after use
  sodium_memzero(prk.data(), prk.size());

  std::array<std::uint8_t, veil::crypto::kAeadKeyLen> key{};
  std::copy_n(key_material.begin(), key.size(), key.begin());

  // SECURITY: Clear key material
  sodium_memzero(key_material.data(), key_material.size());

  return key;
}

// Encrypt a handshake packet using AEAD (nonce prepended to output)
std::vector<std::uint8_t> encrypt_handshake_packet(
    std::span<const std::uint8_t, veil::crypto::kAeadKeyLen> key,
    std::span<const std::uint8_t> plaintext) {
  // Generate random nonce
  auto nonce_bytes = veil::crypto::random_bytes(veil::crypto::kNonceLen);
  std::array<std::uint8_t, veil::crypto::kNonceLen> nonce{};
  std::copy_n(nonce_bytes.begin(), nonce.size(), nonce.begin());

  // Encrypt with empty AAD
  auto ciphertext = veil::crypto::aead_encrypt(key, nonce, {}, plaintext);

  // Prepend nonce to ciphertext
  std::vector<std::uint8_t> result;
  result.reserve(nonce.size() + ciphertext.size());
  result.insert(result.end(), nonce.begin(), nonce.end());
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());

  return result;
}

// Decrypt a handshake packet (nonce is at the beginning)
std::optional<std::vector<std::uint8_t>> decrypt_handshake_packet(
    std::span<const std::uint8_t, veil::crypto::kAeadKeyLen> key,
    std::span<const std::uint8_t> encrypted) {
  if (encrypted.size() < veil::crypto::kNonceLen + kAeadTagLen) {
    return std::nullopt;
  }

  // Extract nonce
  std::array<std::uint8_t, veil::crypto::kNonceLen> nonce{};
  std::copy_n(encrypted.begin(), nonce.size(), nonce.begin());

  // Extract ciphertext
  auto ciphertext = encrypted.subspan(veil::crypto::kNonceLen);

  // Decrypt with empty AAD
  return veil::crypto::aead_decrypt(key, nonce, {}, ciphertext);
}

// Compute random padding size for handshake packets (DPI resistance)
std::uint16_t compute_random_padding_size() {
  if (kMinPaddingSize >= kMaxPaddingSize) {
    return kMinPaddingSize;
  }
  const auto random_val = veil::crypto::random_uint64();
  const auto range = static_cast<std::uint64_t>(kMaxPaddingSize) -
                     static_cast<std::uint64_t>(kMinPaddingSize) + 1U;
  return static_cast<std::uint16_t>(kMinPaddingSize + (random_val % range));
}

std::uint64_t to_millis(std::chrono::system_clock::time_point tp) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count());
}

void write_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

std::uint64_t read_u64(std::span<const std::uint8_t> data, std::size_t offset) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | data[offset + static_cast<std::size_t>(i)];
  }
  return value;
}

std::vector<std::uint8_t> build_hmac_payload(std::uint8_t type, std::uint64_t init_ts,
                                             std::uint64_t resp_ts, std::uint64_t session_id,
                                             std::span<const std::uint8_t, 32> init_pub,
                                             std::span<const std::uint8_t, 32> resp_pub) {
  std::vector<std::uint8_t> payload;
  payload.reserve(1 + 1 + 8 + 8 + 8 + init_pub.size() + resp_pub.size());
  payload.insert(payload.end(), kMagic.begin(), kMagic.end());
  payload.push_back(kVersion);
  payload.push_back(type);
  write_u64(payload, init_ts);
  write_u64(payload, resp_ts);
  write_u64(payload, session_id);
  payload.insert(payload.end(), init_pub.begin(), init_pub.end());
  payload.insert(payload.end(), resp_pub.begin(), resp_pub.end());
  return payload;
}

std::vector<std::uint8_t> build_init_hmac_payload(std::uint64_t ts,
                                                  std::span<const std::uint8_t, 32> pub) {
  std::vector<std::uint8_t> payload;
  payload.reserve(1 + 1 + 8 + pub.size());
  payload.insert(payload.end(), kMagic.begin(), kMagic.end());
  payload.push_back(kVersion);
  payload.push_back(static_cast<std::uint8_t>(veil::handshake::MessageType::kInit));
  write_u64(payload, ts);
  payload.insert(payload.end(), pub.begin(), pub.end());
  return payload;
}

std::vector<std::uint8_t> derive_info(std::span<const std::uint8_t, 32> init_pub,
                                      std::span<const std::uint8_t, 32> resp_pub) {
  std::vector<std::uint8_t> info;
  const std::array<std::uint8_t, 8> label{'V', 'E', 'I', 'L', 'H', 'S', '1', 0};
  info.insert(info.end(), label.begin(), label.end());
  info.insert(info.end(), init_pub.begin(), init_pub.end());
  info.insert(info.end(), resp_pub.begin(), resp_pub.end());
  return info;
}

bool timestamp_valid(std::uint64_t remote_ts, std::chrono::milliseconds skew,
                     const std::function<std::chrono::system_clock::time_point()>& now_fn) {
  const auto now_ms = to_millis(now_fn());
  const auto diff = (remote_ts > now_ms) ? (remote_ts - now_ms) : (now_ms - remote_ts);
  return diff <= static_cast<std::uint64_t>(skew.count());
}

}  // namespace

namespace veil::handshake {

HandshakeInitiator::HandshakeInitiator(std::vector<std::uint8_t> psk,
                                       std::chrono::milliseconds skew_tolerance,
                                       std::function<Clock::time_point()> now_fn)
    : psk_(std::move(psk)), skew_tolerance_(skew_tolerance), now_fn_(std::move(now_fn)) {
  if (psk_.empty()) {
    throw std::invalid_argument("psk required");
  }
}

HandshakeInitiator::~HandshakeInitiator() {
  // SECURITY: Clear all sensitive key material on destruction
  if (!psk_.empty()) {
    sodium_memzero(psk_.data(), psk_.size());
  }
  sodium_memzero(ephemeral_.secret_key.data(), ephemeral_.secret_key.size());
  sodium_memzero(ephemeral_.public_key.data(), ephemeral_.public_key.size());
}

std::vector<std::uint8_t> HandshakeInitiator::create_init() {
  ephemeral_ = crypto::generate_x25519_keypair();
  init_timestamp_ms_ = to_millis(now_fn_());
  init_sent_ = true;

  auto hmac_payload = build_init_hmac_payload(init_timestamp_ms_, ephemeral_.public_key);
  const auto mac = crypto::hmac_sha256(psk_, hmac_payload);

  // Generate random padding for DPI resistance
  const auto padding_size = compute_random_padding_size();
  const auto padding = veil::crypto::random_bytes(padding_size);

  // Build plaintext handshake packet (internal format with magic bytes + padding)
  std::vector<std::uint8_t> plaintext;
  plaintext.reserve(kMagic.size() + 1 + 1 + 8 + ephemeral_.public_key.size() + mac.size() + 2 + padding_size);
  plaintext.insert(plaintext.end(), kMagic.begin(), kMagic.end());
  plaintext.push_back(kVersion);
  plaintext.push_back(static_cast<std::uint8_t>(MessageType::kInit));
  write_u64(plaintext, init_timestamp_ms_);
  plaintext.insert(plaintext.end(), ephemeral_.public_key.begin(), ephemeral_.public_key.end());
  plaintext.insert(plaintext.end(), mac.begin(), mac.end());

  // Append padding length (2 bytes, big-endian)
  plaintext.push_back(static_cast<std::uint8_t>((padding_size >> 8) & 0xFF));
  plaintext.push_back(static_cast<std::uint8_t>(padding_size & 0xFF));

  // Append random padding
  plaintext.insert(plaintext.end(), padding.begin(), padding.end());

  // Derive handshake encryption key and encrypt the packet
  // Result: [12-byte nonce][encrypted payload + 16-byte AEAD tag]
  // This eliminates plaintext magic bytes - first bytes are random nonce
  auto handshake_key = derive_handshake_key(psk_);
  auto encrypted = encrypt_handshake_packet(handshake_key, plaintext);

  // SECURITY: Clear handshake key after use
  sodium_memzero(handshake_key.data(), handshake_key.size());

  return encrypted;
}

std::optional<HandshakeSession> HandshakeInitiator::consume_response(
    std::span<const std::uint8_t> response) {
  if (!init_sent_) {
    return std::nullopt;
  }

  // Decrypt the response first
  auto handshake_key = derive_handshake_key(psk_);
  auto decrypted = decrypt_handshake_packet(handshake_key, response);

  // SECURITY: Clear handshake key after use
  sodium_memzero(handshake_key.data(), handshake_key.size());

  if (!decrypted.has_value()) {
    return std::nullopt;
  }

  const auto& plaintext = *decrypted;

  // Minimum size: header + fields + padding_length (2 bytes)
  const std::size_t min_size = kMagic.size() + 1 + 1 + 8 + 8 + 8 + 32 + 32 + 2;
  if (plaintext.size() < min_size) {
    return std::nullopt;
  }
  // Maximum size with maximum padding
  const std::size_t max_size = min_size + kMaxPaddingSize;
  if (plaintext.size() > max_size) {
    return std::nullopt;
  }
  if (!std::equal(kMagic.begin(), kMagic.end(), plaintext.begin())) {
    return std::nullopt;
  }
  if (plaintext[2] != kVersion || plaintext[3] != static_cast<std::uint8_t>(MessageType::kResponse)) {
    return std::nullopt;
  }
  const auto init_ts = read_u64(plaintext, 4);
  const auto resp_ts = read_u64(plaintext, 12);
  const auto session_id = read_u64(plaintext, 20);
  std::array<std::uint8_t, crypto::kX25519PublicKeySize> responder_pub{};
  std::copy_n(plaintext.begin() + 28, responder_pub.size(), responder_pub.begin());
  std::array<std::uint8_t, crypto::kX25519PublicKeySize> init_pub{};
  std::copy(ephemeral_.public_key.begin(), ephemeral_.public_key.end(), init_pub.begin());

  if (init_ts != init_timestamp_ms_) {
    return std::nullopt;
  }
  if (!timestamp_valid(resp_ts, skew_tolerance_, now_fn_)) {
    return std::nullopt;
  }

  const auto hmac_offset = 28 + responder_pub.size();
  std::array<std::uint8_t, crypto::kHmacSha256Len> provided_mac{};
  std::copy_n(plaintext.begin() + static_cast<std::ptrdiff_t>(hmac_offset), crypto::kHmacSha256Len, provided_mac.begin());

  const auto hmac_payload =
      build_hmac_payload(static_cast<std::uint8_t>(MessageType::kResponse), init_ts, resp_ts,
                         session_id, init_pub, responder_pub);
  const auto expected_mac = crypto::hmac_sha256(psk_, hmac_payload);
  if (!std::equal(expected_mac.begin(), expected_mac.end(), provided_mac.begin())) {
    return std::nullopt;
  }

  // Validate padding length field (after HMAC)
  const auto padding_len_offset = hmac_offset + crypto::kHmacSha256Len;
  if (plaintext.size() < padding_len_offset + 2) {
    return std::nullopt;
  }
  const auto padding_len = static_cast<std::uint16_t>(
      (plaintext[padding_len_offset] << 8) | plaintext[padding_len_offset + 1]);

  // Validate padding length is within allowed range
  if (padding_len < kMinPaddingSize || padding_len > kMaxPaddingSize) {
    return std::nullopt;
  }

  // Validate total packet size matches expected size with padding
  const std::size_t expected_total_size = padding_len_offset + 2 + padding_len;
  if (plaintext.size() != expected_total_size) {
    return std::nullopt;
  }

  auto shared = crypto::compute_shared_secret(ephemeral_.secret_key, responder_pub);
  const auto info = derive_info(init_pub, responder_pub);
  const auto keys = crypto::derive_session_keys(shared, psk_, info, true);

  // SECURITY: Clear shared secret immediately after key derivation
  sodium_memzero(shared.data(), shared.size());

  // SECURITY: Clear ephemeral private key after ECDH computation
  sodium_memzero(ephemeral_.secret_key.data(), ephemeral_.secret_key.size());

  HandshakeSession session{
      .session_id = session_id,
      .keys = keys,
      .initiator_ephemeral = init_pub,
      .responder_ephemeral = responder_pub,
  };
  return session;
}

HandshakeResponder::HandshakeResponder(std::vector<std::uint8_t> psk,
                                       std::chrono::milliseconds skew_tolerance,
                                       utils::TokenBucket rate_limiter,
                                       std::function<Clock::time_point()> now_fn)
    : psk_(std::move(psk)),
      skew_tolerance_(skew_tolerance),
      rate_limiter_(std::move(rate_limiter)),
      now_fn_(std::move(now_fn)) {
  if (psk_.empty()) {
    throw std::invalid_argument("psk required");
  }
}

HandshakeResponder::~HandshakeResponder() {
  // SECURITY: Clear PSK on destruction
  if (!psk_.empty()) {
    sodium_memzero(psk_.data(), psk_.size());
  }
}

std::optional<HandshakeResponder::Result> HandshakeResponder::handle_init(
    std::span<const std::uint8_t> init_bytes) {
  // Rate limit before attempting decryption (prevents DoS via decrypt operations)
  if (!rate_limiter_.allow()) {
    return std::nullopt;
  }

  // Derive handshake key and attempt decryption
  auto handshake_key = derive_handshake_key(psk_);
  auto decrypted = decrypt_handshake_packet(handshake_key, init_bytes);

  if (!decrypted.has_value()) {
    // SECURITY: Clear handshake key even on failure
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }

  const auto& plaintext = *decrypted;

  // Minimum size: header + fields + HMAC + padding_length (2 bytes)
  constexpr std::size_t min_init_size =
      kMagic.size() + 1 + 1 + 8 + crypto::kX25519PublicKeySize + crypto::kHmacSha256Len + 2;
  if (plaintext.size() < min_init_size) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }
  // Maximum size with maximum padding
  const std::size_t max_init_size = min_init_size + kMaxPaddingSize;
  if (plaintext.size() > max_init_size) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }
  if (!std::equal(kMagic.begin(), kMagic.end(), plaintext.begin())) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }
  if (plaintext[2] != kVersion || plaintext[3] != static_cast<std::uint8_t>(MessageType::kInit)) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }
  const auto init_ts = read_u64(plaintext, 4);
  if (!timestamp_valid(init_ts, skew_tolerance_, now_fn_)) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }
  std::array<std::uint8_t, crypto::kX25519PublicKeySize> init_pub{};
  std::copy_n(plaintext.begin() + 12, init_pub.size(), init_pub.begin());

  // Check replay cache BEFORE validating HMAC (anti-probing requirement)
  // If this (timestamp, ephemeral_key) pair was seen before, silently drop
  if (replay_cache_.mark_and_check(init_ts, init_pub)) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;  // Replay detected - silently ignore
  }

  // Extract HMAC (32 bytes after the ephemeral public key)
  const auto mac_offset = 12 + init_pub.size();
  std::array<std::uint8_t, crypto::kHmacSha256Len> provided_mac{};
  std::copy_n(plaintext.begin() + static_cast<std::ptrdiff_t>(mac_offset), crypto::kHmacSha256Len, provided_mac.begin());

  const auto hmac_payload = build_init_hmac_payload(init_ts, init_pub);
  const auto expected_mac = crypto::hmac_sha256(psk_, hmac_payload);
  if (!std::equal(expected_mac.begin(), expected_mac.end(), provided_mac.begin())) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }

  // Validate padding length field (after HMAC)
  const auto padding_len_offset = mac_offset + crypto::kHmacSha256Len;
  if (plaintext.size() < padding_len_offset + 2) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }
  const auto padding_len = static_cast<std::uint16_t>(
      (plaintext[padding_len_offset] << 8) | plaintext[padding_len_offset + 1]);

  // Validate padding length is within allowed range
  if (padding_len < kMinPaddingSize || padding_len > kMaxPaddingSize) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }

  // Validate total packet size matches expected size with padding
  const std::size_t expected_total_size = padding_len_offset + 2 + padding_len;
  if (plaintext.size() != expected_total_size) {
    sodium_memzero(handshake_key.data(), handshake_key.size());
    return std::nullopt;
  }

  auto responder_keys = crypto::generate_x25519_keypair();
  auto shared = crypto::compute_shared_secret(responder_keys.secret_key, init_pub);
  const auto info = derive_info(init_pub, responder_keys.public_key);
  const auto session_keys = crypto::derive_session_keys(shared, psk_, info, false);

  // SECURITY: Clear shared secret immediately after key derivation
  sodium_memzero(shared.data(), shared.size());

  // SECURITY: Clear responder's ephemeral private key after ECDH computation
  sodium_memzero(responder_keys.secret_key.data(), responder_keys.secret_key.size());

  const auto session_id = veil::crypto::random_uint64();
  const auto resp_ts = to_millis(now_fn_());

  auto hmac_payload_resp = build_hmac_payload(static_cast<std::uint8_t>(MessageType::kResponse),
                                              init_ts, resp_ts, session_id, init_pub,
                                              responder_keys.public_key);
  const auto mac = crypto::hmac_sha256(psk_, hmac_payload_resp);

  // Generate random padding for DPI resistance
  const auto padding_size = compute_random_padding_size();
  const auto padding = veil::crypto::random_bytes(padding_size);

  // Build plaintext response
  std::vector<std::uint8_t> response_plaintext;
  response_plaintext.reserve(kMagic.size() + 1 + 1 + 8 + 8 + 8 + responder_keys.public_key.size() + mac.size() + 2 + padding_size);
  response_plaintext.insert(response_plaintext.end(), kMagic.begin(), kMagic.end());
  response_plaintext.push_back(kVersion);
  response_plaintext.push_back(static_cast<std::uint8_t>(MessageType::kResponse));
  write_u64(response_plaintext, init_ts);
  write_u64(response_plaintext, resp_ts);
  write_u64(response_plaintext, session_id);
  response_plaintext.insert(response_plaintext.end(), responder_keys.public_key.begin(),
                            responder_keys.public_key.end());
  response_plaintext.insert(response_plaintext.end(), mac.begin(), mac.end());

  // Append padding length (2 bytes, big-endian)
  response_plaintext.push_back(static_cast<std::uint8_t>((padding_size >> 8) & 0xFF));
  response_plaintext.push_back(static_cast<std::uint8_t>(padding_size & 0xFF));

  // Append random padding
  response_plaintext.insert(response_plaintext.end(), padding.begin(), padding.end());

  // Encrypt the response to hide magic bytes from DPI
  auto encrypted_response = encrypt_handshake_packet(handshake_key, response_plaintext);

  // SECURITY: Clear handshake key after use
  sodium_memzero(handshake_key.data(), handshake_key.size());

  HandshakeSession session{
      .session_id = session_id,
      .keys = session_keys,
      .initiator_ephemeral = init_pub,
      .responder_ephemeral = responder_keys.public_key,
  };

  return Result{.response = std::move(encrypted_response), .session = session};
}

}  // namespace veil::handshake
