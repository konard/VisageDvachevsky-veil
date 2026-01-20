#pragma once

#include <sys/un.h>

#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include "ipc_protocol.h"

namespace veil::ipc {

// ============================================================================
// Unix Domain Socket IPC Implementation
// ============================================================================

// Default socket paths
constexpr const char* kDefaultClientSocketPath = "/tmp/veil-client.sock";
constexpr const char* kDefaultServerSocketPath = "/tmp/veil-server.sock";

// ============================================================================
// IPC Server (runs in daemon)
// ============================================================================

class IpcServer {
 public:
  using MessageHandler = std::function<void(const Message& msg, int client_fd)>;

  explicit IpcServer(std::string socket_path = kDefaultClientSocketPath);
  ~IpcServer();

  // Non-copyable
  IpcServer(const IpcServer&) = delete;
  IpcServer& operator=(const IpcServer&) = delete;

  // Start listening for connections
  bool start(std::error_code& ec);

  // Stop the server and close all connections
  void stop();

  // Set handler for incoming messages
  void on_message(MessageHandler handler);

  // Send a message to a specific client
  bool send_message(int client_fd, const Message& msg, std::error_code& ec);

  // Send a message to all connected clients (for events/broadcasts)
  void broadcast_message(const Message& msg);

  // Process pending connections and messages (non-blocking)
  // Call this regularly from the main event loop
  void poll(std::error_code& ec);

  // Check if server is running
  [[nodiscard]] bool is_running() const { return running_; }

 private:
  struct ClientConnection {
    int fd{-1};
    std::string receive_buffer;
  };

  void accept_connection(std::error_code& ec);
  void handle_client_data(ClientConnection& conn, std::error_code& ec);
  void remove_client(int client_fd);
  bool send_raw(int fd, const std::string& data, std::error_code& ec);

  std::string socket_path_;
  int server_fd_{-1};
  bool running_{false};
  MessageHandler message_handler_;
  std::vector<ClientConnection> clients_;
};

// ============================================================================
// IPC Client (runs in GUI application)
// ============================================================================

class IpcClient {
 public:
  using MessageHandler = std::function<void(const Message& msg)>;
  using ConnectionHandler = std::function<void(bool connected)>;

  explicit IpcClient(std::string socket_path = kDefaultClientSocketPath);
  ~IpcClient();

  // Non-copyable
  IpcClient(const IpcClient&) = delete;
  IpcClient& operator=(const IpcClient&) = delete;

  // Connect to the daemon
  bool connect(std::error_code& ec);

  // Disconnect from the daemon
  void disconnect();

  // Send a command and optionally wait for response
  bool send_command(const Command& cmd, std::error_code& ec);

  // Send a command with request ID for tracking response
  bool send_command(const Command& cmd, std::uint64_t request_id, std::error_code& ec);

  // Set handler for incoming messages (events, responses)
  void on_message(MessageHandler handler);

  // Set handler for connection status changes
  void on_connection_change(ConnectionHandler handler);

  // Process pending messages (non-blocking)
  // Call this regularly from GUI event loop or in a separate thread
  void poll(std::error_code& ec);

  // Check if connected
  [[nodiscard]] bool is_connected() const { return connected_; }

 private:
  bool send_message(const Message& msg, std::error_code& ec);
  bool send_raw(const std::string& data, std::error_code& ec);
  void handle_incoming_data(std::error_code& ec);

  std::string socket_path_;
  int socket_fd_{-1};
  bool connected_{false};
  MessageHandler message_handler_;
  ConnectionHandler connection_handler_;
  std::string receive_buffer_;
};

}  // namespace veil::ipc
