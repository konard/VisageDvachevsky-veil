#include <gtest/gtest.h>

#include <chrono>

#include "tunnel/session_migration.h"

namespace veil::tunnel::test {

class SessionMigrationTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override { current_time_ = Clock::now(); }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::seconds sec) { current_time_ += sec; }

  TimePoint current_time_;
};

TEST_F(SessionMigrationTest, MigrationResultToString) {
  EXPECT_STREQ(migration_result_to_string(MigrationResult::kSuccess), "success");
  EXPECT_STREQ(migration_result_to_string(MigrationResult::kInvalidToken), "invalid_token");
  EXPECT_STREQ(migration_result_to_string(MigrationResult::kTokenExpired), "token_expired");
  EXPECT_STREQ(migration_result_to_string(MigrationResult::kSessionNotFound), "session_not_found");
  EXPECT_STREQ(migration_result_to_string(MigrationResult::kMigrationDisabled), "migration_disabled");
}

// MigrationTokenManager tests.

TEST_F(SessionMigrationTest, TokenManager_GenerateToken) {
  SessionMigrationConfig config;
  MigrationTokenManager manager(config, [this]() { return now(); });

  MigrationState state;
  state.session_id = 12345;
  state.send_sequence = 100;
  state.recv_sequence = 50;

  auto token = manager.generate_token(12345, state);

  EXPECT_EQ(manager.token_count(), 1u);

  // Token should be valid.
  auto session_id = manager.validate_token(token);
  ASSERT_TRUE(session_id.has_value());
  EXPECT_EQ(*session_id, 12345u);
}

TEST_F(SessionMigrationTest, TokenManager_ConsumeToken) {
  SessionMigrationConfig config;
  MigrationTokenManager manager(config, [this]() { return now(); });

  MigrationState state;
  state.session_id = 12345;
  state.send_sequence = 100;

  auto token = manager.generate_token(12345, state);

  auto consumed_state = manager.consume_token(token);
  ASSERT_TRUE(consumed_state.has_value());
  EXPECT_EQ(consumed_state->session_id, 12345u);
  EXPECT_EQ(consumed_state->send_sequence, 100u);

  // Token should no longer be valid.
  EXPECT_FALSE(manager.validate_token(token).has_value());
  EXPECT_EQ(manager.token_count(), 0u);
}

TEST_F(SessionMigrationTest, TokenManager_TokenExpiry) {
  SessionMigrationConfig config;
  config.token_ttl = std::chrono::seconds(60);

  MigrationTokenManager manager(config, [this]() { return now(); });

  MigrationState state;
  state.session_id = 12345;

  auto token = manager.generate_token(12345, state);
  EXPECT_TRUE(manager.validate_token(token).has_value());

  // Advance past TTL.
  advance_time(std::chrono::seconds(61));

  EXPECT_FALSE(manager.validate_token(token).has_value());
  EXPECT_FALSE(manager.consume_token(token).has_value());
}

TEST_F(SessionMigrationTest, TokenManager_InvalidateSessionTokens) {
  SessionMigrationConfig config;
  MigrationTokenManager manager(config, [this]() { return now(); });

  MigrationState state;
  state.session_id = 12345;

  auto token1 = manager.generate_token(12345, state);
  auto token2 = manager.generate_token(12345, state);

  EXPECT_EQ(manager.token_count(), 2u);

  manager.invalidate_session_tokens(12345);

  EXPECT_EQ(manager.token_count(), 0u);
  EXPECT_FALSE(manager.validate_token(token1).has_value());
  EXPECT_FALSE(manager.validate_token(token2).has_value());
}

TEST_F(SessionMigrationTest, TokenManager_CleanupExpired) {
  SessionMigrationConfig config;
  config.token_ttl = std::chrono::seconds(60);

  MigrationTokenManager manager(config, [this]() { return now(); });

  MigrationState state;
  manager.generate_token(1, state);
  manager.generate_token(2, state);

  advance_time(std::chrono::seconds(61));

  manager.generate_token(3, state);  // This one is fresh.

  auto cleaned = manager.cleanup_expired();
  EXPECT_EQ(cleaned, 2u);
  EXPECT_EQ(manager.token_count(), 1u);
}

// SessionMigrationHandler tests.

TEST_F(SessionMigrationTest, Handler_RequestToken) {
  SessionMigrationConfig config;
  SessionMigrationHandler handler(config, [this]() { return now(); });

  // Set up callback to provide state.
  handler.set_get_state_callback([](std::uint64_t session_id) -> std::optional<MigrationState> {
    MigrationState state;
    state.session_id = session_id;
    state.send_sequence = 100;
    return state;
  });

  auto token = handler.request_token(12345);
  ASSERT_TRUE(token.has_value());
}

TEST_F(SessionMigrationTest, Handler_RequestToken_DisabledMigration) {
  SessionMigrationConfig config;
  config.enabled = false;

  SessionMigrationHandler handler(config, [this]() { return now(); });

  auto token = handler.request_token(12345);
  EXPECT_FALSE(token.has_value());
}

TEST_F(SessionMigrationTest, Handler_ProcessMigration_Success) {
  SessionMigrationConfig config;
  SessionMigrationHandler handler(config, [this]() { return now(); });

  MigrationState saved_state;

  handler.set_get_state_callback([&saved_state](std::uint64_t session_id) -> std::optional<MigrationState> {
    saved_state.session_id = session_id;
    saved_state.send_sequence = 100;
    return saved_state;
  });

  handler.set_restore_callback([]([[maybe_unused]] std::uint64_t session_id,
                                   [[maybe_unused]] const MigrationState& state,
                                   [[maybe_unused]] const std::string& new_endpoint) { return true; });

  auto token = handler.request_token(12345);
  ASSERT_TRUE(token.has_value());

  MigrationRequest request;
  request.old_session_id = 12345;
  request.token = *token;
  request.new_endpoint = "192.168.1.100:5000";

  auto result = handler.process_migration(request);
  EXPECT_EQ(result, MigrationResult::kSuccess);
}

TEST_F(SessionMigrationTest, Handler_ProcessMigration_InvalidToken) {
  SessionMigrationConfig config;
  SessionMigrationHandler handler(config, [this]() { return now(); });

  MigrationRequest request;
  request.old_session_id = 12345;
  request.token = {};  // Invalid token.
  request.new_endpoint = "192.168.1.100:5000";

  auto result = handler.process_migration(request);
  EXPECT_EQ(result, MigrationResult::kInvalidToken);
}

TEST_F(SessionMigrationTest, Handler_ProcessMigration_TokenExpired) {
  SessionMigrationConfig config;
  config.token_ttl = std::chrono::seconds(60);

  SessionMigrationHandler handler(config, [this]() { return now(); });

  handler.set_get_state_callback([](std::uint64_t session_id) -> std::optional<MigrationState> {
    MigrationState state;
    state.session_id = session_id;
    return state;
  });

  auto token = handler.request_token(12345);
  ASSERT_TRUE(token.has_value());

  // Advance past TTL.
  advance_time(std::chrono::seconds(61));

  MigrationRequest request;
  request.old_session_id = 12345;
  request.token = *token;
  request.new_endpoint = "192.168.1.100:5000";

  auto result = handler.process_migration(request);
  EXPECT_EQ(result, MigrationResult::kTokenExpired);
}

TEST_F(SessionMigrationTest, Handler_MigrationCooldown) {
  SessionMigrationConfig config;
  config.migration_cooldown = std::chrono::seconds(30);

  SessionMigrationHandler handler(config, [this]() { return now(); });

  handler.set_get_state_callback([](std::uint64_t session_id) -> std::optional<MigrationState> {
    MigrationState state;
    state.session_id = session_id;
    return state;
  });

  handler.set_restore_callback([](std::uint64_t, const MigrationState&, const std::string&) {
    return true;
  });

  // First migration.
  auto token1 = handler.request_token(12345);
  ASSERT_TRUE(token1.has_value());

  MigrationRequest request1;
  request1.old_session_id = 12345;
  request1.token = *token1;
  request1.new_endpoint = "192.168.1.100:5000";

  EXPECT_EQ(handler.process_migration(request1), MigrationResult::kSuccess);

  // Second migration immediately should be rate limited.
  advance_time(std::chrono::seconds(5));
  EXPECT_FALSE(handler.can_migrate(12345));

  // After cooldown, should be allowed.
  advance_time(std::chrono::seconds(30));
  EXPECT_TRUE(handler.can_migrate(12345));
}

TEST_F(SessionMigrationTest, Handler_MaxMigrations) {
  SessionMigrationConfig config;
  config.max_migrations_per_session = 2;
  config.migration_cooldown = std::chrono::seconds(1);

  SessionMigrationHandler handler(config, [this]() { return now(); });

  handler.set_get_state_callback([](std::uint64_t session_id) -> std::optional<MigrationState> {
    MigrationState state;
    state.session_id = session_id;
    return state;
  });

  handler.set_restore_callback([](std::uint64_t, const MigrationState&, const std::string&) {
    return true;
  });

  // First migration.
  auto token1 = handler.request_token(12345);
  MigrationRequest req1{12345, *token1, "ep1"};
  EXPECT_EQ(handler.process_migration(req1), MigrationResult::kSuccess);

  advance_time(std::chrono::seconds(2));

  // Second migration.
  auto token2 = handler.request_token(12345);
  MigrationRequest req2{12345, *token2, "ep2"};
  EXPECT_EQ(handler.process_migration(req2), MigrationResult::kSuccess);

  advance_time(std::chrono::seconds(2));

  // Third migration should be denied (max reached).
  EXPECT_FALSE(handler.can_migrate(12345));
}

TEST_F(SessionMigrationTest, Handler_Stats) {
  SessionMigrationConfig config;
  SessionMigrationHandler handler(config, [this]() { return now(); });

  handler.set_get_state_callback([](std::uint64_t session_id) -> std::optional<MigrationState> {
    MigrationState state;
    state.session_id = session_id;
    return state;
  });

  handler.set_restore_callback([](std::uint64_t, const MigrationState&, const std::string&) {
    return true;
  });

  auto token = handler.request_token(12345);
  MigrationRequest request{12345, *token, "ep1"};
  handler.process_migration(request);

  auto stats = handler.get_stats();
  EXPECT_EQ(stats.tokens_generated, 1u);
  EXPECT_EQ(stats.migrations_attempted, 1u);
  EXPECT_EQ(stats.migrations_successful, 1u);
}

// MigrationFrame tests.

TEST_F(SessionMigrationTest, MigrationFrame_Serialize) {
  MigrationFrame frame;
  frame.frame_type = MigrationFrame::kFrameTypeMigrate;
  frame.session_id = 0x123456789ABCDEF0;
  for (std::size_t i = 0; i < kMigrationTokenSize; i++) {
    frame.token[i] = static_cast<std::uint8_t>(i);
  }

  auto data = frame.serialize();
  EXPECT_EQ(data.size(), 1 + 8 + kMigrationTokenSize);
  EXPECT_EQ(data[0], MigrationFrame::kFrameTypeMigrate);
}

TEST_F(SessionMigrationTest, MigrationFrame_Deserialize) {
  MigrationFrame original;
  original.frame_type = MigrationFrame::kFrameTypeMigrate;
  original.session_id = 0x123456789ABCDEF0;
  for (std::size_t i = 0; i < kMigrationTokenSize; i++) {
    original.token[i] = static_cast<std::uint8_t>(i);
  }

  auto data = original.serialize();
  auto parsed = MigrationFrame::deserialize(data);

  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->frame_type, original.frame_type);
  EXPECT_EQ(parsed->session_id, original.session_id);
  EXPECT_EQ(parsed->token, original.token);
}

TEST_F(SessionMigrationTest, MigrationFrame_DeserializeAck) {
  MigrationFrame original;
  original.frame_type = MigrationFrame::kFrameTypeMigrateAck;
  original.session_id = 12345;
  original.result = static_cast<std::uint8_t>(MigrationResult::kSuccess);

  auto data = original.serialize();
  auto parsed = MigrationFrame::deserialize(data);

  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->frame_type, MigrationFrame::kFrameTypeMigrateAck);
  EXPECT_EQ(parsed->result, 0u);  // Success.
}

TEST_F(SessionMigrationTest, MigrationFrame_DeserializeInvalid) {
  std::vector<std::uint8_t> short_data{0x10, 0x00};  // Too short.
  auto parsed = MigrationFrame::deserialize(short_data);
  EXPECT_FALSE(parsed.has_value());
}

}  // namespace veil::tunnel::test
