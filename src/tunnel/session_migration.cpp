#include "tunnel/session_migration.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

namespace veil::tunnel {

const char* migration_result_to_string(MigrationResult result) {
  switch (result) {
    case MigrationResult::kSuccess:
      return "success";
    case MigrationResult::kInvalidToken:
      return "invalid_token";
    case MigrationResult::kTokenExpired:
      return "token_expired";
    case MigrationResult::kSessionNotFound:
      return "session_not_found";
    case MigrationResult::kSessionInactive:
      return "session_inactive";
    case MigrationResult::kMigrationDisabled:
      return "migration_disabled";
    case MigrationResult::kRateLimited:
      return "rate_limited";
    case MigrationResult::kInternalError:
      return "internal_error";
    default:
      return "unknown";
  }
}

// MigrationTokenManager implementation.

MigrationTokenManager::MigrationTokenManager(SessionMigrationConfig config,
                                              std::function<TimePoint()> now_fn)
    : config_(std::move(config)), now_fn_(std::move(now_fn)) {}

MigrationToken MigrationTokenManager::generate_token(std::uint64_t session_id,
                                                      const MigrationState& state) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto token = generate_random_token();
  auto now = now_fn_();

  // Convert token to string key.
  std::ostringstream oss;
  for (auto byte : token) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  std::string key = oss.str();

  TokenEntry entry;
  entry.session_id = session_id;
  entry.state = state;
  entry.created_at = now;
  entry.expires_at = now + config_.token_ttl;

  tokens_[key] = std::move(entry);
  session_tokens_[session_id].push_back(key);

  // Enforce max pending limit.
  while (tokens_.size() > config_.max_pending_migrations) {
    // Remove oldest token.
    auto oldest = tokens_.begin();
    for (auto it = tokens_.begin(); it != tokens_.end(); ++it) {
      if (it->second.created_at < oldest->second.created_at) {
        oldest = it;
      }
    }
    if (oldest != tokens_.end()) {
      auto& session_keys = session_tokens_[oldest->second.session_id];
      session_keys.erase(std::remove(session_keys.begin(), session_keys.end(), oldest->first),
                         session_keys.end());
      tokens_.erase(oldest);
    }
  }

  return token;
}

std::optional<std::uint64_t> MigrationTokenManager::validate_token(const MigrationToken& token) {
  std::lock_guard<std::mutex> lock(mutex_);

  std::ostringstream oss;
  for (auto byte : token) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  std::string key = oss.str();

  auto it = tokens_.find(key);
  if (it == tokens_.end()) {
    return std::nullopt;
  }

  auto now = now_fn_();
  if (now > it->second.expires_at) {
    return std::nullopt;
  }

  return it->second.session_id;
}

std::optional<MigrationState> MigrationTokenManager::consume_token(const MigrationToken& token) {
  std::lock_guard<std::mutex> lock(mutex_);

  std::ostringstream oss;
  for (auto byte : token) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  std::string key = oss.str();

  auto it = tokens_.find(key);
  if (it == tokens_.end()) {
    return std::nullopt;
  }

  auto now = now_fn_();
  if (now > it->second.expires_at) {
    tokens_.erase(it);
    return std::nullopt;
  }

  auto state = std::move(it->second.state);
  auto session_id = it->second.session_id;

  // Remove from session tokens.
  auto& session_keys = session_tokens_[session_id];
  session_keys.erase(std::remove(session_keys.begin(), session_keys.end(), key), session_keys.end());

  tokens_.erase(it);

  return state;
}

void MigrationTokenManager::invalidate_session_tokens(std::uint64_t session_id) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = session_tokens_.find(session_id);
  if (it == session_tokens_.end()) {
    return;
  }

  for (const auto& key : it->second) {
    tokens_.erase(key);
  }
  session_tokens_.erase(it);
}

std::size_t MigrationTokenManager::cleanup_expired() {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = now_fn_();
  std::size_t removed = 0;

  for (auto it = tokens_.begin(); it != tokens_.end();) {
    if (now > it->second.expires_at) {
      auto& session_keys = session_tokens_[it->second.session_id];
      session_keys.erase(std::remove(session_keys.begin(), session_keys.end(), it->first),
                         session_keys.end());
      it = tokens_.erase(it);
      removed++;
    } else {
      ++it;
    }
  }

  // Clean up empty session entries.
  for (auto it = session_tokens_.begin(); it != session_tokens_.end();) {
    if (it->second.empty()) {
      it = session_tokens_.erase(it);
    } else {
      ++it;
    }
  }

  return removed;
}

bool MigrationTokenManager::is_token_expired(const MigrationToken& token) const {
  std::lock_guard<std::mutex> lock(mutex_);

  std::ostringstream oss;
  for (auto byte : token) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  std::string key = oss.str();

  auto it = tokens_.find(key);
  if (it == tokens_.end()) {
    return false;  // Token doesn't exist, not "expired".
  }

  auto now = now_fn_();
  return now > it->second.expires_at;
}

std::size_t MigrationTokenManager::token_count() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return tokens_.size();
}

MigrationToken MigrationTokenManager::generate_random_token() {
  MigrationToken token;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 255);

  for (auto& byte : token) {
    byte = static_cast<std::uint8_t>(dis(gen));
  }

  return token;
}

// SessionMigrationHandler implementation.

SessionMigrationHandler::SessionMigrationHandler(SessionMigrationConfig config,
                                                  std::function<TimePoint()> now_fn)
    : config_(std::move(config)), now_fn_(std::move(now_fn)), token_manager_(config_, now_fn_) {}

void SessionMigrationHandler::set_get_state_callback(GetSessionStateCallback callback) {
  get_state_callback_ = std::move(callback);
}

void SessionMigrationHandler::set_restore_callback(RestoreSessionCallback callback) {
  restore_callback_ = std::move(callback);
}

void SessionMigrationHandler::set_migration_callback(OnMigrationCallback callback) {
  migration_callback_ = std::move(callback);
}

std::optional<MigrationToken> SessionMigrationHandler::request_token(std::uint64_t session_id) {
  if (!config_.enabled) {
    return std::nullopt;
  }

  if (!can_migrate(session_id)) {
    return std::nullopt;
  }

  if (!get_state_callback_) {
    return std::nullopt;
  }

  auto state = get_state_callback_(session_id);
  if (!state) {
    return std::nullopt;
  }

  auto token = token_manager_.generate_token(session_id, *state);
  tokens_generated_.fetch_add(1, std::memory_order_relaxed);

  return token;
}

MigrationResult SessionMigrationHandler::process_migration(const MigrationRequest& request) {
  migrations_attempted_.fetch_add(1, std::memory_order_relaxed);

  if (!config_.enabled) {
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kMigrationDisabled;
  }

  // Check if token is expired first (before validate consumes it implicitly).
  if (token_manager_.is_token_expired(request.token)) {
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    tokens_expired_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kTokenExpired;
  }

  // Validate token.
  auto session_id = token_manager_.validate_token(request.token);
  if (!session_id) {
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kInvalidToken;
  }

  if (*session_id != request.old_session_id) {
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kInvalidToken;
  }

  // Check cooldown.
  if (!check_cooldown(*session_id)) {
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kRateLimited;
  }

  // Consume token and get state.
  auto state = token_manager_.consume_token(request.token);
  if (!state) {
    // Token existed but was consumed/expired between validate and consume.
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    tokens_expired_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kTokenExpired;
  }

  // Restore session.
  if (!restore_callback_) {
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kInternalError;
  }

  if (!restore_callback_(*session_id, *state, request.new_endpoint)) {
    migrations_failed_.fetch_add(1, std::memory_order_relaxed);
    return MigrationResult::kInternalError;
  }

  // Record migration.
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& record = migration_records_[*session_id];
    auto old_endpoint = record.last_endpoint;
    record.count++;
    record.last_migration = now_fn_();
    record.last_endpoint = request.new_endpoint;

    if (migration_callback_) {
      migration_callback_(*session_id, old_endpoint, request.new_endpoint);
    }
  }

  migrations_successful_.fetch_add(1, std::memory_order_relaxed);
  return MigrationResult::kSuccess;
}

bool SessionMigrationHandler::can_migrate(std::uint64_t session_id) const {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = migration_records_.find(session_id);
  if (it == migration_records_.end()) {
    return true;
  }

  // Check max migrations.
  if (it->second.count >= config_.max_migrations_per_session) {
    return false;
  }

  // Check cooldown.
  return check_cooldown(session_id);
}

std::uint32_t SessionMigrationHandler::migration_count(std::uint64_t session_id) const {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = migration_records_.find(session_id);
  if (it == migration_records_.end()) {
    return 0;
  }

  return it->second.count;
}

void SessionMigrationHandler::record_migration(std::uint64_t session_id,
                                                const std::string& old_endpoint,
                                                const std::string& new_endpoint) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto& record = migration_records_[session_id];
  record.count++;
  record.last_migration = now_fn_();
  record.last_endpoint = new_endpoint;

  if (migration_callback_) {
    migration_callback_(session_id, old_endpoint, new_endpoint);
  }
}

std::size_t SessionMigrationHandler::cleanup() {
  std::size_t cleaned = token_manager_.cleanup_expired();

  // Clean up old migration records (optional).
  // For now, we keep records for the lifetime of the server.

  return cleaned;
}

SessionMigrationHandler::Stats SessionMigrationHandler::get_stats() const {
  Stats stats;
  stats.tokens_generated = tokens_generated_.load(std::memory_order_relaxed);
  stats.migrations_attempted = migrations_attempted_.load(std::memory_order_relaxed);
  stats.migrations_successful = migrations_successful_.load(std::memory_order_relaxed);
  stats.migrations_failed = migrations_failed_.load(std::memory_order_relaxed);
  stats.tokens_expired = tokens_expired_.load(std::memory_order_relaxed);
  return stats;
}

bool SessionMigrationHandler::check_cooldown(std::uint64_t session_id) const {
  auto it = migration_records_.find(session_id);
  if (it == migration_records_.end()) {
    return true;
  }

  auto now = now_fn_();
  auto since_last =
      std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_migration);
  return since_last >= config_.migration_cooldown;
}

// MigrationFrame implementation.

std::vector<std::uint8_t> MigrationFrame::serialize() const {
  std::vector<std::uint8_t> data;
  data.reserve(1 + 8 + kMigrationTokenSize + 1);

  // Frame type.
  data.push_back(frame_type);

  // Session ID (big-endian).
  for (int i = 7; i >= 0; --i) {
    data.push_back(static_cast<std::uint8_t>((session_id >> (i * 8)) & 0xFF));
  }

  // Token.
  data.insert(data.end(), token.begin(), token.end());

  // Result (for ACK/NACK).
  if (frame_type == kFrameTypeMigrateAck || frame_type == kFrameTypeMigrateNack) {
    data.push_back(result);
  }

  return data;
}

std::optional<MigrationFrame> MigrationFrame::deserialize(const std::vector<std::uint8_t>& data) {
  if (data.size() < 1 + 8 + kMigrationTokenSize) {
    return std::nullopt;
  }

  MigrationFrame frame;
  std::size_t offset = 0;

  // Frame type.
  frame.frame_type = data[offset++];

  // Session ID.
  frame.session_id = 0;
  for (int i = 0; i < 8; ++i) {
    frame.session_id = (frame.session_id << 8) | data[offset++];
  }

  // Token.
  std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
            data.begin() + static_cast<std::ptrdiff_t>(offset + kMigrationTokenSize), frame.token.begin());
  offset += kMigrationTokenSize;

  // Result (for ACK/NACK).
  if ((frame.frame_type == kFrameTypeMigrateAck || frame.frame_type == kFrameTypeMigrateNack) &&
      data.size() > offset) {
    frame.result = data[offset];
  }

  return frame;
}

}  // namespace veil::tunnel
