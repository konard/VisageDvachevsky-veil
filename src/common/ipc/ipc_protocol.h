#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// Forward declaration for DPI bypass mode
namespace veil::obfuscation {
enum class DPIBypassMode : std::uint8_t;
}

namespace veil::ipc {

// ============================================================================
// IPC Protocol - JSON over Unix Domain Socket
// ============================================================================
// This protocol is used for communication between GUI applications and daemons.
//
// Message Format:
// {
//   "type": "command" | "event" | "response" | "error",
//   "id": <optional request ID for request-response correlation>,
//   "payload": { ... type-specific data ... }
// }

// Connection states (matches client_ui_design.md specification)
enum class ConnectionState {
  kDisconnected,
  kConnecting,
  kConnected,
  kReconnecting,
  kError
};

// Command types from GUI to Daemon
enum class CommandType {
  kConnect,
  kDisconnect,
  kGetStatus,
  kGetMetrics,
  kGetDiagnostics,
  kUpdateConfig,
  kExportDiagnostics
};

// Event types from Daemon to GUI
enum class EventType {
  kStatusUpdate,
  kMetricsUpdate,
  kConnectionStateChange,
  kError,
  kLogEvent
};

// ============================================================================
// Data Structures
// ============================================================================

// Connection configuration
struct ConnectionConfig {
  std::string server_address;
  std::uint16_t server_port{4433};
  bool enable_obfuscation{true};
  bool auto_reconnect{true};
  std::uint32_t reconnect_interval_sec{5};
  std::uint32_t max_reconnect_attempts{0};  // 0 = unlimited
  bool route_all_traffic{true};
  std::vector<std::string> custom_routes;
  std::uint8_t dpi_bypass_mode{0};  // DPI bypass mode (0=IoT, 1=QUIC, 2=Noise, 3=Trickle)
};

// Current connection status
struct ConnectionStatus {
  ConnectionState state{ConnectionState::kDisconnected};
  std::string session_id;
  std::string server_address;
  std::uint16_t server_port{0};
  std::uint64_t uptime_sec{0};
  std::string error_message;
  std::uint32_t reconnect_attempt{0};
};

// Real-time metrics
struct ConnectionMetrics {
  std::uint32_t latency_ms{0};
  std::uint64_t tx_bytes_per_sec{0};
  std::uint64_t rx_bytes_per_sec{0};
  std::uint64_t total_tx_bytes{0};
  std::uint64_t total_rx_bytes{0};
};

// Protocol-level diagnostics
struct ProtocolMetrics {
  std::uint64_t send_sequence{0};
  std::uint64_t recv_sequence{0};
  std::uint64_t packets_sent{0};
  std::uint64_t packets_received{0};
  std::uint64_t packets_lost{0};
  std::uint64_t packets_retransmitted{0};
  double loss_percentage{0.0};
};

// Reassembly statistics
struct ReassemblyStats {
  std::uint64_t fragments_received{0};
  std::uint64_t messages_reassembled{0};
  std::uint64_t fragments_pending{0};
  std::uint64_t reassembly_timeouts{0};
};

// Obfuscation profile information
struct ObfuscationProfile {
  bool padding_enabled{false};
  std::uint32_t current_padding_size{0};
  std::string timing_jitter_model;
  double timing_jitter_param{0.0};
  std::string heartbeat_mode;
  double last_heartbeat_sec{0.0};
  std::string active_dpi_mode;  // Active DPI bypass mode name
};

// Log event for diagnostics screen
struct LogEvent {
  std::uint64_t timestamp_ms{0};
  std::string level;  // "info", "success", "warning", "error"
  std::string message;
};

// Complete diagnostics data
struct DiagnosticsData {
  ProtocolMetrics protocol;
  ReassemblyStats reassembly;
  ObfuscationProfile obfuscation;
  std::vector<LogEvent> recent_events;  // Last N events
};

// Server-specific: Client session info
struct ClientSession {
  std::uint64_t session_id{0};
  std::string tunnel_ip;
  std::string endpoint_host;
  std::uint16_t endpoint_port{0};
  std::uint64_t uptime_sec{0};
  std::uint64_t packets_sent{0};
  std::uint64_t packets_received{0};
  std::uint64_t bytes_sent{0};
  std::uint64_t bytes_received{0};
  std::uint64_t last_activity_sec{0};
};

// Server-specific: Overall server status
struct ServerStatus {
  bool running{false};
  std::uint16_t listen_port{0};
  std::string listen_address;
  std::uint32_t active_clients{0};
  std::uint32_t max_clients{0};
  std::uint64_t uptime_sec{0};
  std::uint64_t total_packets_sent{0};
  std::uint64_t total_packets_received{0};
  std::uint64_t total_bytes_sent{0};
  std::uint64_t total_bytes_received{0};
};

// ============================================================================
// Commands (GUI -> Daemon)
// ============================================================================

struct ConnectCommand {
  ConnectionConfig config;
};

struct DisconnectCommand {};

struct GetStatusCommand {};

struct GetMetricsCommand {};

struct GetDiagnosticsCommand {};

struct UpdateConfigCommand {
  ConnectionConfig config;
};

struct ExportDiagnosticsCommand {
  std::string export_path;
};

// Server-specific: Get list of active clients
struct GetClientListCommand {};

// Command variant
using Command = std::variant<
  ConnectCommand,
  DisconnectCommand,
  GetStatusCommand,
  GetMetricsCommand,
  GetDiagnosticsCommand,
  UpdateConfigCommand,
  ExportDiagnosticsCommand,
  GetClientListCommand
>;

// ============================================================================
// Events (Daemon -> GUI)
// ============================================================================

struct StatusUpdateEvent {
  ConnectionStatus status;
};

struct MetricsUpdateEvent {
  ConnectionMetrics metrics;
};

struct ConnectionStateChangeEvent {
  ConnectionState old_state;
  ConnectionState new_state;
  std::string message;
};

struct ErrorEvent {
  std::string error_message;
  std::string details;
};

struct LogEventData {
  LogEvent event;
};

// Server-specific: Client list update
struct ClientListUpdateEvent {
  std::vector<ClientSession> clients;
};

// Server-specific: Server status update
struct ServerStatusUpdateEvent {
  ServerStatus status;
};

// Event variant
using Event = std::variant<
  StatusUpdateEvent,
  MetricsUpdateEvent,
  ConnectionStateChangeEvent,
  ErrorEvent,
  LogEventData,
  ClientListUpdateEvent,
  ServerStatusUpdateEvent
>;

// ============================================================================
// Responses (Daemon -> GUI, in response to commands)
// ============================================================================

struct StatusResponse {
  ConnectionStatus status;
};

struct MetricsResponse {
  ConnectionMetrics metrics;
};

struct DiagnosticsResponse {
  DiagnosticsData diagnostics;
};

struct ClientListResponse {
  std::vector<ClientSession> clients;
};

struct SuccessResponse {
  std::string message;
};

struct ErrorResponse {
  std::string error_message;
  std::string details;
};

// Response variant
using Response = std::variant<
  StatusResponse,
  MetricsResponse,
  DiagnosticsResponse,
  ClientListResponse,
  SuccessResponse,
  ErrorResponse
>;

// ============================================================================
// Message envelope
// ============================================================================

enum class MessageType {
  kCommand,
  kEvent,
  kResponse,
  kError
};

struct Message {
  MessageType type;
  std::optional<std::uint64_t> id;  // For request-response correlation
  std::variant<Command, Event, Response> payload;
};

// ============================================================================
// Serialization/Deserialization
// ============================================================================
// These functions convert between Message structures and JSON strings.

// Serialize a message to JSON string
std::string serialize_message(const Message& msg);

// Deserialize JSON string to message
std::optional<Message> deserialize_message(const std::string& json);

// Helper: Get connection state as string
const char* connection_state_to_string(ConnectionState state);

// Helper: Parse connection state from string
std::optional<ConnectionState> connection_state_from_string(const std::string& str);

}  // namespace veil::ipc
