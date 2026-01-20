#include "common/session/replay_window.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace veil::session {

namespace {
constexpr std::size_t kBitsPerWord = std::numeric_limits<std::uint64_t>::digits;
}

ReplayWindow::ReplayWindow(std::size_t window_size)
    : window_size_(window_size),
      bits_((window_size + kBitsPerWord - 1) / kBitsPerWord) {}

bool ReplayWindow::mark_and_check(std::uint64_t sequence) {
  if (!initialized_) {
    highest_ = sequence;
    initialized_ = true;
    set_bit(0);
    return true;
  }

  if (sequence > highest_) {
    const std::size_t delta = static_cast<std::size_t>(sequence - highest_);
    if (delta >= window_size_) {
      std::fill(bits_.begin(), bits_.end(), 0);
    } else {
      shift(delta);
    }
    highest_ = sequence;
    set_bit(0);
    return true;
  }

  const std::uint64_t diff = highest_ - sequence;
  if (diff >= window_size_) {
    return false;
  }

  const std::size_t index = static_cast<std::size_t>(diff);
  if (get_bit(index)) {
    return false;
  }
  set_bit(index);
  return true;
}

void ReplayWindow::shift(std::size_t delta) {
  const auto word_shift = delta / kBitsPerWord;
  const auto bit_shift = delta % kBitsPerWord;

  if (word_shift >= bits_.size()) {
    std::fill(bits_.begin(), bits_.end(), 0);
    return;
  }

  for (std::size_t i = bits_.size(); i-- > 0;) {
    std::uint64_t value = 0;
    if (i >= word_shift) {
      value = bits_[i - word_shift];
      if (bit_shift != 0) {
        value <<= bit_shift;
        if (i > word_shift) {
          value |= bits_[i - word_shift - 1] >> (kBitsPerWord - bit_shift);
        }
      }
    }
    bits_[i] = value;
  }
  mask_tail();
}

bool ReplayWindow::get_bit(std::size_t index) const {
  const auto word = index / kBitsPerWord;
  const auto bit = index % kBitsPerWord;
  return ((bits_[word] >> bit) & 1U) != 0U;
}

void ReplayWindow::set_bit(std::size_t index) {
  const auto word = index / kBitsPerWord;
  const auto bit = index % kBitsPerWord;
  bits_[word] |= (std::uint64_t(1) << bit);
}

void ReplayWindow::mask_tail() {
  const auto remainder = window_size_ % kBitsPerWord;
  if (remainder == 0) {
    return;
  }
  const std::uint64_t mask = (std::uint64_t(1) << remainder) - 1;
  bits_.back() &= mask;
}

}  // namespace veil::session
