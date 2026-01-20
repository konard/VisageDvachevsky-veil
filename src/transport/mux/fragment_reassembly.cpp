#include "transport/mux/fragment_reassembly.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace veil::mux {

FragmentReassembly::FragmentReassembly(std::size_t max_bytes,
                                       std::chrono::milliseconds fragment_timeout)
    : max_bytes_(max_bytes), fragment_timeout_(fragment_timeout) {}

bool FragmentReassembly::push(std::uint64_t message_id, Fragment fragment, TimePoint now) {
  auto& entry = state_[message_id];

  // Record timestamp of first fragment for this message
  if (entry.fragments.empty()) {
    entry.first_fragment_time = now;
  }

  if (entry.total_bytes + fragment.data.size() > max_bytes_) {
    return false;
  }

  entry.total_bytes += fragment.data.size();
  entry.has_last = entry.has_last || fragment.last;
  entry.fragments.push_back(std::move(fragment));
  return true;
}

std::optional<std::vector<std::uint8_t>> FragmentReassembly::try_reassemble(
    std::uint64_t message_id) {
  auto it = state_.find(message_id);
  if (it == state_.end()) {
    return std::nullopt;
  }
  auto& entry = it->second;
  if (!entry.has_last) {
    return std::nullopt;
  }

  std::sort(entry.fragments.begin(), entry.fragments.end(),
            [](const Fragment& a, const Fragment& b) { return a.offset < b.offset; });

  std::size_t assembled = 0;
  std::size_t expected_offset = 0;
  for (const auto& frag : entry.fragments) {
    if (frag.offset != expected_offset) {
      return std::nullopt;
    }
    assembled += frag.data.size();
    expected_offset += frag.data.size();
  }

  std::vector<std::uint8_t> output;
  output.reserve(assembled);
  for (const auto& frag : entry.fragments) {
    output.insert(output.end(), frag.data.begin(), frag.data.end());
  }
  state_.erase(it);
  return output;
}

std::size_t FragmentReassembly::cleanup_expired(TimePoint now) {
  std::size_t removed = 0;

  for (auto it = state_.begin(); it != state_.end();) {
    const auto age = now - it->second.first_fragment_time;
    if (age > fragment_timeout_) {
      it = state_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }

  return removed;
}

std::size_t FragmentReassembly::memory_usage() const {
  std::size_t total = 0;
  for (const auto& [_, state] : state_) {
    total += state.total_bytes;
  }
  return total;
}

}  // namespace veil::mux
