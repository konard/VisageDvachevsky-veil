#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace veil::tunnel {

// Migration token size (256 bits).
constexpr std::size_t kMigrationTokenSize = 32;

// Migration token type.
using MigrationToken = std::array<std::uint8_t, kMigrationTokenSize>;

// Migration request from client.
struct MigrationRequest {
  std::uint64_t old_session_id{0};
  MigrationToken token;
  std::string new_endpoint;  // "ip:port"
  std::uint64_t timestamp{0};
};

// Migration result.
enum class MigrationResult : std::uint8_t {
  kSuccess = 0,
  kInvalidToken = 1,
  kTokenExpired = 2,
  kSessionNotFound = 3,
  kSessionInactive = 4,
  kMigrationDisabled = 5,
  kRateLimited = 6,
  kInternalError = 7
};

// Convert migration result to string.
const char* migration_result_to_string(MigrationResult result);

// Configuration for session migration.
struct SessionMigrationConfig {
  // Enable session migration.
  bool enabled{true};
  // Migration token time-to-live.
  std::chrono::seconds token_ttl{300};
  // Maximum migrations per session.
  std::uint32_t max_migrations_per_session{5};
  // Minimum time between migrations.
  std::chrono::seconds migration_cooldown{10};
  // Whether to migrate replay window state.
  bool migrate_replay_window{true};
  // Whether to migrate retransmit buffer.
  bool migrate_retransmit_buffer{true};
  // Maximum pending migrations.
  std::size_t max_pending_migrations{1000};
};

// State saved for session migration.
struct MigrationState {
  std::uint64_t session_id{0};
  std::uint64_t send_sequence{0};
  std::uint64_t recv_sequence{0};
  std::vector<std::uint8_t> replay_window_state;
  std::vector<std::vector<std::uint8_t>> pending_retransmits;
  std::chrono::steady_clock::time_point created_at;
  std::chrono::steady_clock::time_point last_activity;
  std::uint32_t migration_count{0};
};

// Session migration token manager.
class MigrationTokenManager {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  explicit MigrationTokenManager(SessionMigrationConfig config = {},
                                  std::function<TimePoint()> now_fn = Clock::now);

  // Generate a migration token for a session.
  // Returns token and stores association internally.
  MigrationToken generate_token(std::uint64_t session_id, const MigrationState& state);

  // Validate a migration token.
  // Returns the session ID if valid, nullopt otherwise.
  std::optional<std::uint64_t> validate_token(const MigrationToken& token);

  // Consume a token (invalidates it after use).
  // Returns the migration state if valid.
  std::optional<MigrationState> consume_token(const MigrationToken& token);

  // Invalidate all tokens for a session.
  void invalidate_session_tokens(std::uint64_t session_id);

  // Clean up expired tokens.
  std::size_t cleanup_expired();

  // Check if a token exists but is expired.
  bool is_token_expired(const MigrationToken& token) const;

  // Get number of active tokens.
  std::size_t token_count() const;

  // Get configuration.
  const SessionMigrationConfig& config() const { return config_; }

 private:
  MigrationToken generate_random_token();

  SessionMigrationConfig config_;
  std::function<TimePoint()> now_fn_;

  struct TokenEntry {
    std::uint64_t session_id;
    MigrationState state;
    TimePoint created_at;
    TimePoint expires_at;
  };

  std::unordered_map<std::string, TokenEntry> tokens_;
  std::unordered_map<std::uint64_t, std::vector<std::string>> session_tokens_;
  mutable std::mutex mutex_;
};

// Migration handler for server-side processing.
class SessionMigrationHandler {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  // Callback to get session state for migration.
  using GetSessionStateCallback = std::function<std::optional<MigrationState>(std::uint64_t session_id)>;
  // Callback to restore session after migration.
  using RestoreSessionCallback =
      std::function<bool(std::uint64_t session_id, const MigrationState& state, const std::string& new_endpoint)>;
  // Callback to notify session of successful migration.
  using OnMigrationCallback = std::function<void(std::uint64_t session_id, const std::string& old_endpoint,
                                                   const std::string& new_endpoint)>;

  explicit SessionMigrationHandler(SessionMigrationConfig config = {},
                                    std::function<TimePoint()> now_fn = Clock::now);

  // Set callbacks.
  void set_get_state_callback(GetSessionStateCallback callback);
  void set_restore_callback(RestoreSessionCallback callback);
  void set_migration_callback(OnMigrationCallback callback);

  // Request a migration token for a session.
  std::optional<MigrationToken> request_token(std::uint64_t session_id);

  // Process a migration request.
  MigrationResult process_migration(const MigrationRequest& request);

  // Check if a session can migrate.
  bool can_migrate(std::uint64_t session_id) const;

  // Get migration count for a session.
  std::uint32_t migration_count(std::uint64_t session_id) const;

  // Record a successful migration.
  void record_migration(std::uint64_t session_id, const std::string& old_endpoint,
                        const std::string& new_endpoint);

  // Clean up expired state.
  std::size_t cleanup();

  // Statistics.
  struct Stats {
    std::uint64_t tokens_generated{0};
    std::uint64_t migrations_attempted{0};
    std::uint64_t migrations_successful{0};
    std::uint64_t migrations_failed{0};
    std::uint64_t tokens_expired{0};
  };
  Stats get_stats() const;

  // Get configuration.
  const SessionMigrationConfig& config() const { return config_; }

 private:
  bool check_cooldown(std::uint64_t session_id) const;

  SessionMigrationConfig config_;
  std::function<TimePoint()> now_fn_;
  MigrationTokenManager token_manager_;

  GetSessionStateCallback get_state_callback_;
  RestoreSessionCallback restore_callback_;
  OnMigrationCallback migration_callback_;

  // Track migrations per session.
  struct MigrationRecord {
    std::uint32_t count{0};
    TimePoint last_migration;
    std::string last_endpoint;
  };
  std::unordered_map<std::uint64_t, MigrationRecord> migration_records_;

  // Stats.
  std::atomic<std::uint64_t> tokens_generated_{0};
  std::atomic<std::uint64_t> migrations_attempted_{0};
  std::atomic<std::uint64_t> migrations_successful_{0};
  std::atomic<std::uint64_t> migrations_failed_{0};
  std::atomic<std::uint64_t> tokens_expired_{0};

  mutable std::mutex mutex_;
};

// Migration frame for the wire protocol.
struct MigrationFrame {
  static constexpr std::uint8_t kFrameTypeMigrate = 0x10;
  static constexpr std::uint8_t kFrameTypeMigrateAck = 0x11;
  static constexpr std::uint8_t kFrameTypeMigrateNack = 0x12;

  std::uint8_t frame_type{0};
  std::uint64_t session_id{0};
  MigrationToken token;
  std::uint8_t result{0};  // For ACK/NACK frames.

  // Serialize to bytes.
  std::vector<std::uint8_t> serialize() const;

  // Deserialize from bytes.
  static std::optional<MigrationFrame> deserialize(const std::vector<std::uint8_t>& data);
};

}  // namespace veil::tunnel
