#include "transport/mux/reorder_buffer.h"

#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace veil::mux {

ReorderBuffer::ReorderBuffer(std::uint64_t initial, std::size_t max_bytes)
    : next_(initial), max_bytes_(max_bytes) {}

bool ReorderBuffer::push(std::uint64_t seq, std::vector<std::uint8_t> payload) {
  if (seq < next_) {
    return false;
  }
  if (buffered_bytes_ + payload.size() > max_bytes_) {
    return false;
  }
  auto [it, inserted] = buffer_.emplace(seq, std::move(payload));
  if (inserted) {
    buffered_bytes_ += it->second.size();
  }
  return inserted;
}

std::optional<std::vector<std::uint8_t>> ReorderBuffer::pop_next() {
  auto it = buffer_.find(next_);
  if (it == buffer_.end()) {
    return std::nullopt;
  }
  auto payload = std::move(it->second);
  buffered_bytes_ -= payload.size();
  buffer_.erase(it);
  ++next_;
  return payload;
}

}  // namespace veil::mux
