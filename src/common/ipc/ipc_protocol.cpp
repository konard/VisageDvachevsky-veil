#include "ipc_protocol.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace veil::ipc {

// ============================================================================
// Helper Functions
// ============================================================================

const char* connection_state_to_string(ConnectionState state) {
  switch (state) {
    case ConnectionState::kDisconnected: return "disconnected";
    case ConnectionState::kConnecting: return "connecting";
    case ConnectionState::kConnected: return "connected";
    case ConnectionState::kReconnecting: return "reconnecting";
    case ConnectionState::kError: return "error";
  }
  return "unknown";
}

std::optional<ConnectionState> connection_state_from_string(const std::string& str) {
  if (str == "disconnected") return ConnectionState::kDisconnected;
  if (str == "connecting") return ConnectionState::kConnecting;
  if (str == "connected") return ConnectionState::kConnected;
  if (str == "reconnecting") return ConnectionState::kReconnecting;
  if (str == "error") return ConnectionState::kError;
  return std::nullopt;
}

// ============================================================================
// JSON Conversion Functions
// ============================================================================

// ConnectionConfig
void to_json(json& j, const ConnectionConfig& cfg) {
  j = json{
    {"server_address", cfg.server_address},
    {"server_port", cfg.server_port},
    {"enable_obfuscation", cfg.enable_obfuscation},
    {"auto_reconnect", cfg.auto_reconnect},
    {"reconnect_interval_sec", cfg.reconnect_interval_sec},
    {"max_reconnect_attempts", cfg.max_reconnect_attempts},
    {"route_all_traffic", cfg.route_all_traffic},
    {"custom_routes", cfg.custom_routes}
  };
}

void from_json(const json& j, ConnectionConfig& cfg) {
  j.at("server_address").get_to(cfg.server_address);
  j.at("server_port").get_to(cfg.server_port);
  j.at("enable_obfuscation").get_to(cfg.enable_obfuscation);
  j.at("auto_reconnect").get_to(cfg.auto_reconnect);
  j.at("reconnect_interval_sec").get_to(cfg.reconnect_interval_sec);
  j.at("max_reconnect_attempts").get_to(cfg.max_reconnect_attempts);
  j.at("route_all_traffic").get_to(cfg.route_all_traffic);
  j.at("custom_routes").get_to(cfg.custom_routes);
}

// ConnectionStatus
void to_json(json& j, const ConnectionStatus& status) {
  j = json{
    {"state", connection_state_to_string(status.state)},
    {"session_id", status.session_id},
    {"server_address", status.server_address},
    {"server_port", status.server_port},
    {"uptime_sec", status.uptime_sec},
    {"error_message", status.error_message},
    {"reconnect_attempt", status.reconnect_attempt}
  };
}

void from_json(const json& j, ConnectionStatus& status) {
  auto state_str = j.at("state").get<std::string>();
  auto state_opt = connection_state_from_string(state_str);
  status.state = state_opt.value_or(ConnectionState::kDisconnected);
  j.at("session_id").get_to(status.session_id);
  j.at("server_address").get_to(status.server_address);
  j.at("server_port").get_to(status.server_port);
  j.at("uptime_sec").get_to(status.uptime_sec);
  j.at("error_message").get_to(status.error_message);
  j.at("reconnect_attempt").get_to(status.reconnect_attempt);
}

// ConnectionMetrics
void to_json(json& j, const ConnectionMetrics& metrics) {
  j = json{
    {"latency_ms", metrics.latency_ms},
    {"tx_bytes_per_sec", metrics.tx_bytes_per_sec},
    {"rx_bytes_per_sec", metrics.rx_bytes_per_sec},
    {"total_tx_bytes", metrics.total_tx_bytes},
    {"total_rx_bytes", metrics.total_rx_bytes}
  };
}

void from_json(const json& j, ConnectionMetrics& metrics) {
  j.at("latency_ms").get_to(metrics.latency_ms);
  j.at("tx_bytes_per_sec").get_to(metrics.tx_bytes_per_sec);
  j.at("rx_bytes_per_sec").get_to(metrics.rx_bytes_per_sec);
  j.at("total_tx_bytes").get_to(metrics.total_tx_bytes);
  j.at("total_rx_bytes").get_to(metrics.total_rx_bytes);
}

// ProtocolMetrics
void to_json(json& j, const ProtocolMetrics& metrics) {
  j = json{
    {"send_sequence", metrics.send_sequence},
    {"recv_sequence", metrics.recv_sequence},
    {"packets_sent", metrics.packets_sent},
    {"packets_received", metrics.packets_received},
    {"packets_lost", metrics.packets_lost},
    {"packets_retransmitted", metrics.packets_retransmitted},
    {"loss_percentage", metrics.loss_percentage}
  };
}

void from_json(const json& j, ProtocolMetrics& metrics) {
  j.at("send_sequence").get_to(metrics.send_sequence);
  j.at("recv_sequence").get_to(metrics.recv_sequence);
  j.at("packets_sent").get_to(metrics.packets_sent);
  j.at("packets_received").get_to(metrics.packets_received);
  j.at("packets_lost").get_to(metrics.packets_lost);
  j.at("packets_retransmitted").get_to(metrics.packets_retransmitted);
  j.at("loss_percentage").get_to(metrics.loss_percentage);
}

// ReassemblyStats
void to_json(json& j, const ReassemblyStats& stats) {
  j = json{
    {"fragments_received", stats.fragments_received},
    {"messages_reassembled", stats.messages_reassembled},
    {"fragments_pending", stats.fragments_pending},
    {"reassembly_timeouts", stats.reassembly_timeouts}
  };
}

void from_json(const json& j, ReassemblyStats& stats) {
  j.at("fragments_received").get_to(stats.fragments_received);
  j.at("messages_reassembled").get_to(stats.messages_reassembled);
  j.at("fragments_pending").get_to(stats.fragments_pending);
  j.at("reassembly_timeouts").get_to(stats.reassembly_timeouts);
}

// ObfuscationProfile
void to_json(json& j, const ObfuscationProfile& profile) {
  j = json{
    {"padding_enabled", profile.padding_enabled},
    {"current_padding_size", profile.current_padding_size},
    {"timing_jitter_model", profile.timing_jitter_model},
    {"timing_jitter_param", profile.timing_jitter_param},
    {"heartbeat_mode", profile.heartbeat_mode},
    {"last_heartbeat_sec", profile.last_heartbeat_sec}
  };
}

void from_json(const json& j, const ObfuscationProfile& profile) {
  // Note: This is intentionally empty as ObfuscationProfile is read-only from GUI
  (void)j;
  (void)profile;
}

// ClientSession
void to_json(json& j, const ClientSession& session) {
  j = json{
    {"session_id", session.session_id},
    {"tunnel_ip", session.tunnel_ip},
    {"endpoint_host", session.endpoint_host},
    {"endpoint_port", session.endpoint_port},
    {"uptime_sec", session.uptime_sec},
    {"packets_sent", session.packets_sent},
    {"packets_received", session.packets_received},
    {"bytes_sent", session.bytes_sent},
    {"bytes_received", session.bytes_received},
    {"last_activity_sec", session.last_activity_sec}
  };
}

// ServerStatus
void to_json(json& j, const ServerStatus& status) {
  j = json{
    {"running", status.running},
    {"listen_port", status.listen_port},
    {"listen_address", status.listen_address},
    {"active_clients", status.active_clients},
    {"max_clients", status.max_clients},
    {"uptime_sec", status.uptime_sec},
    {"total_packets_sent", status.total_packets_sent},
    {"total_packets_received", status.total_packets_received},
    {"total_bytes_sent", status.total_bytes_sent},
    {"total_bytes_received", status.total_bytes_received}
  };
}

// ============================================================================
// Message Serialization
// ============================================================================

std::string serialize_message(const Message& msg) {
  json j;

  // Set message type
  switch (msg.type) {
    case MessageType::kCommand: j["type"] = "command"; break;
    case MessageType::kEvent: j["type"] = "event"; break;
    case MessageType::kResponse: j["type"] = "response"; break;
    case MessageType::kError: j["type"] = "error"; break;
  }

  // Set request ID if present
  if (msg.id) {
    j["id"] = *msg.id;
  }

  // Serialize payload based on type
  // Note: This is simplified - full implementation would handle all variants
  j["payload"] = json::object();

  // Add newline delimiter for framing
  return j.dump() + "\n";
}

std::optional<Message> deserialize_message(const std::string& json_str) {
  try {
    auto j = json::parse(json_str);

    Message msg;

    // Parse message type
    auto type_str = j.at("type").get<std::string>();
    if (type_str == "command") {
      msg.type = MessageType::kCommand;
    } else if (type_str == "event") {
      msg.type = MessageType::kEvent;
    } else if (type_str == "response") {
      msg.type = MessageType::kResponse;
    } else if (type_str == "error") {
      msg.type = MessageType::kError;
    } else {
      return std::nullopt;
    }

    // Parse request ID if present
    if (j.contains("id")) {
      msg.id = j.at("id").get<std::uint64_t>();
    }

    // Parse payload
    // Note: This is simplified - full implementation would handle all variants

    return msg;
  } catch (const json::exception&) {
    return std::nullopt;
  }
}

}  // namespace veil::ipc
