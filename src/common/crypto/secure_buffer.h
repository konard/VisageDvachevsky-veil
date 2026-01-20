#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "common/crypto/random.h"

namespace veil::crypto {

/**
 * @brief RAII wrapper for fixed-size sensitive data that automatically zeros memory on destruction.
 *
 * SecureArray provides automatic secure memory clearing using sodium_memzero()
 * when the object goes out of scope. This prevents sensitive data (like keys,
 * shared secrets, etc.) from remaining in memory after use.
 *
 * @tparam N Size of the array in bytes
 */
template <std::size_t N>
class SecureArray {
 public:
  SecureArray() = default;

  /// Copy constructor - performs deep copy
  SecureArray(const SecureArray& other) : data_(other.data_) {}

  /// Move constructor - takes ownership and clears source
  SecureArray(SecureArray&& other) noexcept : data_(other.data_) { other.clear(); }

  /// Copy assignment
  SecureArray& operator=(const SecureArray& other) {
    if (this != &other) {
      clear();
      data_ = other.data_;
    }
    return *this;
  }

  /// Move assignment
  SecureArray& operator=(SecureArray&& other) noexcept {
    if (this != &other) {
      clear();
      data_ = other.data_;
      other.clear();
    }
    return *this;
  }

  /// Destructor - automatically clears sensitive data
  ~SecureArray() { clear(); }

  /// Construct from std::array
  explicit SecureArray(const std::array<std::uint8_t, N>& arr) : data_(arr) {}

  /// Construct from std::array (move)
  explicit SecureArray(std::array<std::uint8_t, N>&& arr) noexcept : data_(std::move(arr)) {}

  /// Assignment from std::array
  SecureArray& operator=(const std::array<std::uint8_t, N>& arr) {
    clear();
    data_ = arr;
    return *this;
  }

  /// Securely clear the buffer contents using sodium_memzero
  void clear() { secure_zero(std::span<std::uint8_t>(data_.data(), data_.size())); }

  /// Get pointer to underlying data
  std::uint8_t* data() { return data_.data(); }
  const std::uint8_t* data() const { return data_.data(); }

  /// Get size
  constexpr std::size_t size() const { return N; }

  /// Iterator access
  auto begin() { return data_.begin(); }
  auto end() { return data_.end(); }
  auto begin() const { return data_.begin(); }
  auto end() const { return data_.end(); }

  /// Array subscript access
  std::uint8_t& operator[](std::size_t idx) { return data_[idx]; }
  const std::uint8_t& operator[](std::size_t idx) const { return data_[idx]; }

  /// Get reference to underlying array
  std::array<std::uint8_t, N>& array() { return data_; }
  const std::array<std::uint8_t, N>& array() const { return data_; }

  /// Convert to span for use with crypto functions
  std::span<std::uint8_t, N> span() { return std::span<std::uint8_t, N>(data_); }
  std::span<const std::uint8_t, N> span() const { return std::span<const std::uint8_t, N>(data_); }

 private:
  std::array<std::uint8_t, N> data_{};
};

/**
 * @brief RAII wrapper for variable-size sensitive data that automatically zeros memory on destruction.
 *
 * SecureVector provides automatic secure memory clearing using sodium_memzero()
 * when the object goes out of scope or is resized.
 */
class SecureVector {
 public:
  SecureVector() = default;

  /// Construct with specified size (zero-initialized)
  explicit SecureVector(std::size_t size) : data_(size, 0) {}

  /// Copy constructor
  SecureVector(const SecureVector& other) = default;

  /// Move constructor
  SecureVector(SecureVector&& other) noexcept : data_(std::move(other.data_)) {
    // other.data_ is now in valid but unspecified state; it's empty after move
  }

  /// Copy assignment
  SecureVector& operator=(const SecureVector& other) {
    if (this != &other) {
      clear();
      data_ = other.data_;
    }
    return *this;
  }

  /// Move assignment
  SecureVector& operator=(SecureVector&& other) noexcept {
    if (this != &other) {
      clear();
      data_ = std::move(other.data_);
    }
    return *this;
  }

  /// Destructor - automatically clears sensitive data
  ~SecureVector() { clear(); }

  /// Construct from std::vector
  explicit SecureVector(const std::vector<std::uint8_t>& vec) : data_(vec) {}

  /// Construct from std::vector (move)
  explicit SecureVector(std::vector<std::uint8_t>&& vec) noexcept : data_(std::move(vec)) {}

  /// Assignment from std::vector
  SecureVector& operator=(const std::vector<std::uint8_t>& vec) {
    clear();
    data_ = vec;
    return *this;
  }

  /// Securely clear the buffer contents using sodium_memzero
  void clear() {
    if (!data_.empty()) {
      secure_zero(std::span<std::uint8_t>(data_.data(), data_.size()));
    }
    data_.clear();
  }

  /// Resize with secure clearing of old data if shrinking
  void resize(std::size_t new_size) {
    if (new_size < data_.size()) {
      // Clear the bytes we're about to lose
      secure_zero(std::span<std::uint8_t>(data_.data() + new_size, data_.size() - new_size));
    }
    data_.resize(new_size);
  }

  /// Reserve capacity
  void reserve(std::size_t new_cap) { data_.reserve(new_cap); }

  /// Get pointer to underlying data
  std::uint8_t* data() { return data_.data(); }
  const std::uint8_t* data() const { return data_.data(); }

  /// Get size
  std::size_t size() const { return data_.size(); }

  /// Check if empty
  bool empty() const { return data_.empty(); }

  /// Iterator access
  auto begin() { return data_.begin(); }
  auto end() { return data_.end(); }
  auto begin() const { return data_.begin(); }
  auto end() const { return data_.end(); }

  /// Array subscript access
  std::uint8_t& operator[](std::size_t idx) { return data_[idx]; }
  const std::uint8_t& operator[](std::size_t idx) const { return data_[idx]; }

  /// Append data
  void push_back(std::uint8_t byte) { data_.push_back(byte); }

  /// Get reference to underlying vector
  std::vector<std::uint8_t>& vector() { return data_; }
  const std::vector<std::uint8_t>& vector() const { return data_; }

  /// Convert to span for use with crypto functions
  std::span<std::uint8_t> span() { return std::span<std::uint8_t>(data_); }
  std::span<const std::uint8_t> span() const { return std::span<const std::uint8_t>(data_); }

  /// Assign from span
  void assign(std::span<const std::uint8_t> src) {
    clear();
    data_.assign(src.begin(), src.end());
  }

 private:
  std::vector<std::uint8_t> data_;
};

// Convenient type aliases for common key sizes
using SecureKey32 = SecureArray<32>;   // 256-bit keys (X25519, ChaCha20)
using SecureKey16 = SecureArray<16>;   // 128-bit values
using SecureNonce12 = SecureArray<12>; // 96-bit nonces

/**
 * @brief Secure key pair with automatic memory clearing.
 *
 * Wraps both public and secret keys, ensuring the secret key
 * is securely cleared on destruction.
 */
struct SecureKeyPair {
  std::array<std::uint8_t, kX25519PublicKeySize> public_key{};
  SecureKey32 secret_key;

  SecureKeyPair() = default;

  /// Copy constructor
  SecureKeyPair(const SecureKeyPair& other) = default;

  /// Move constructor
  SecureKeyPair(SecureKeyPair&& other) noexcept
      : public_key(other.public_key), secret_key(std::move(other.secret_key)) {
    // Clear the public key in source (not strictly necessary but consistent)
    std::fill(other.public_key.begin(), other.public_key.end(), 0);
  }

  /// Copy assignment
  SecureKeyPair& operator=(const SecureKeyPair& other) {
    if (this != &other) {
      public_key = other.public_key;
      secret_key = other.secret_key;
    }
    return *this;
  }

  /// Move assignment
  SecureKeyPair& operator=(SecureKeyPair&& other) noexcept {
    if (this != &other) {
      public_key = other.public_key;
      secret_key = std::move(other.secret_key);
      std::fill(other.public_key.begin(), other.public_key.end(), 0);
    }
    return *this;
  }

  /// Construct from regular KeyPair (for migration)
  explicit SecureKeyPair(const KeyPair& kp) : public_key(kp.public_key) {
    secret_key = kp.secret_key;
  }

  /// Convert to KeyPair (for compatibility)
  KeyPair to_keypair() const {
    KeyPair kp;
    kp.public_key = public_key;
    kp.secret_key = secret_key.array();
    return kp;
  }

  /// Clear all key material
  void clear() {
    secret_key.clear();
    std::fill(public_key.begin(), public_key.end(), 0);
  }
};

/**
 * @brief Secure session keys with automatic memory clearing.
 *
 * Wraps all session key material, ensuring everything is
 * securely cleared on destruction.
 */
struct SecureSessionKeys {
  SecureKey32 send_key;
  SecureKey32 recv_key;
  SecureNonce12 send_nonce;
  SecureNonce12 recv_nonce;

  SecureSessionKeys() = default;

  /// Construct from regular SessionKeys (for migration)
  explicit SecureSessionKeys(const SessionKeys& keys) {
    send_key = keys.send_key;
    recv_key = keys.recv_key;
    send_nonce = keys.send_nonce;
    recv_nonce = keys.recv_nonce;
  }

  /// Convert to SessionKeys (for compatibility)
  SessionKeys to_session_keys() const {
    SessionKeys keys;
    keys.send_key = send_key.array();
    keys.recv_key = recv_key.array();
    keys.send_nonce = send_nonce.array();
    keys.recv_nonce = recv_nonce.array();
    return keys;
  }

  /// Clear all key material
  void clear() {
    send_key.clear();
    recv_key.clear();
    send_nonce.clear();
    recv_nonce.clear();
  }
};

}  // namespace veil::crypto
