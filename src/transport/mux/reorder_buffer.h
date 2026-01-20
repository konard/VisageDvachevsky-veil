#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace veil::mux {

class ReorderBuffer {
 public:
  explicit ReorderBuffer(std::uint64_t initial = 0, std::size_t max_bytes = 1 << 20);

  bool push(std::uint64_t seq, std::vector<std::uint8_t> payload);
  std::optional<std::vector<std::uint8_t>> pop_next();
  std::uint64_t next_expected() const { return next_; }

 private:
  std::uint64_t next_;
  std::size_t max_bytes_;
  std::size_t buffered_bytes_{0};
  std::map<std::uint64_t, std::vector<std::uint8_t>> buffer_;
};

}  // namespace veil::mux
