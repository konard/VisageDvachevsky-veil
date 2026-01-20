#include "common/crypto/random.h"

#include <sodium.h>

#include <stdexcept>

namespace {
void ensure_sodium_ready() {
  static const bool ready = [] { return sodium_init() >= 0; }();
  if (!ready) {
    throw std::runtime_error("libsodium initialization failed");
  }
}
}  // namespace

namespace veil::crypto {

std::vector<std::uint8_t> random_bytes(std::size_t length) {
  ensure_sodium_ready();
  std::vector<std::uint8_t> output(length);
  if (!output.empty()) {
    randombytes_buf(output.data(), output.size());
  }
  return output;
}

std::uint64_t random_uint64() {
  ensure_sodium_ready();
  std::uint64_t value{};
  randombytes_buf(&value, sizeof(value));
  return value;
}

void secure_zero(std::span<std::uint8_t> buffer) {
  if (!buffer.empty()) {
    sodium_memzero(buffer.data(), buffer.size());
  }
}

}  // namespace veil::crypto
