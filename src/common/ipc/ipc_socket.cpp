#include "ipc_socket.h"

#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace veil::ipc {

namespace {
constexpr int kMaxPendingConnections = 5;
constexpr std::size_t kBufferSize = 4096;

bool set_nonblocking(int fd, std::error_code& ec) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    ec = std::error_code(errno, std::generic_category());
    return false;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    ec = std::error_code(errno, std::generic_category());
    return false;
  }
  return true;
}
}  // namespace

// ============================================================================
// IPC Server Implementation
// ============================================================================

IpcServer::IpcServer(std::string socket_path) : socket_path_(std::move(socket_path)) {}

IpcServer::~IpcServer() {
  stop();
}

bool IpcServer::start(std::error_code& ec) {
  if (running_) {
    ec = std::make_error_code(std::errc::already_connected);
    return false;
  }

  // Create socket
  server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd_ == -1) {
    ec = std::error_code(errno, std::generic_category());
    return false;
  }

  // Set non-blocking
  if (!set_nonblocking(server_fd_, ec)) {
    close(server_fd_);
    server_fd_ = -1;
    return false;
  }

  // Remove old socket file if exists
  unlink(socket_path_.c_str());

  // Bind to socket
  struct sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

  if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
    ec = std::error_code(errno, std::generic_category());
    close(server_fd_);
    server_fd_ = -1;
    return false;
  }

  // Listen
  if (listen(server_fd_, kMaxPendingConnections) == -1) {
    ec = std::error_code(errno, std::generic_category());
    close(server_fd_);
    server_fd_ = -1;
    unlink(socket_path_.c_str());
    return false;
  }

  running_ = true;
  return true;
}

void IpcServer::stop() {
  if (!running_) {
    return;
  }

  running_ = false;

  // Close all client connections
  for (auto& client : clients_) {
    if (client.fd != -1) {
      close(client.fd);
    }
  }
  clients_.clear();

  // Close server socket
  if (server_fd_ != -1) {
    close(server_fd_);
    server_fd_ = -1;
  }

  // Remove socket file
  unlink(socket_path_.c_str());
}

void IpcServer::on_message(MessageHandler handler) {
  message_handler_ = std::move(handler);
}

bool IpcServer::send_message(int client_fd, const Message& msg, std::error_code& ec) {
  std::string data = serialize_message(msg);
  return send_raw(client_fd, data, ec);
}

void IpcServer::broadcast_message(const Message& msg) {
  std::error_code ec;
  std::string data = serialize_message(msg);

  for (const auto& client : clients_) {
    if (client.fd != -1) {
      send_raw(client.fd, data, ec);
      // Ignore errors for broadcast
    }
  }
}

void IpcServer::poll(std::error_code& ec) {
  if (!running_) {
    ec = std::make_error_code(std::errc::not_connected);
    return;
  }

  // Accept new connections
  accept_connection(ec);

  // Handle data from existing clients
  for (auto& client : clients_) {
    if (client.fd != -1) {
      handle_client_data(client, ec);
    }
  }

  // Remove disconnected clients
  clients_.erase(
    std::remove_if(clients_.begin(), clients_.end(),
      [](const ClientConnection& c) { return c.fd == -1; }),
    clients_.end()
  );
}

void IpcServer::accept_connection(std::error_code& ec) {
  struct sockaddr_un client_addr {};
  socklen_t client_len = sizeof(client_addr);

  int client_fd = accept(server_fd_, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
  if (client_fd == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // No pending connections
      return;
    }
    ec = std::error_code(errno, std::generic_category());
    return;
  }

  // Set non-blocking
  if (!set_nonblocking(client_fd, ec)) {
    close(client_fd);
    return;
  }

  // Add to clients list
  ClientConnection conn;
  conn.fd = client_fd;
  clients_.push_back(std::move(conn));
}

void IpcServer::handle_client_data(ClientConnection& conn, std::error_code& ec) {
  char buffer[kBufferSize];
  ssize_t n = recv(conn.fd, buffer, sizeof(buffer), 0);

  if (n == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return;  // No data available
    }
    ec = std::error_code(errno, std::generic_category());
    remove_client(conn.fd);
    return;
  }

  if (n == 0) {
    // Client disconnected
    remove_client(conn.fd);
    return;
  }

  // Append to receive buffer
  conn.receive_buffer.append(buffer, static_cast<std::size_t>(n));

  // Process complete messages (newline-delimited)
  std::size_t pos = 0;
  while ((pos = conn.receive_buffer.find('\n')) != std::string::npos) {
    std::string message_str = conn.receive_buffer.substr(0, pos);
    conn.receive_buffer.erase(0, pos + 1);

    // Deserialize and handle message
    auto msg = deserialize_message(message_str);
    if (msg && message_handler_) {
      message_handler_(*msg, conn.fd);
    }
  }
}

void IpcServer::remove_client(int client_fd) {
  close(client_fd);
  for (auto& client : clients_) {
    if (client.fd == client_fd) {
      client.fd = -1;
      break;
    }
  }
}

bool IpcServer::send_raw(int fd, const std::string& data, std::error_code& ec) {
  ssize_t sent = send(fd, data.c_str(), data.size(), MSG_NOSIGNAL);
  if (sent == -1) {
    ec = std::error_code(errno, std::generic_category());
    return false;
  }
  return true;
}

// ============================================================================
// IPC Client Implementation
// ============================================================================

IpcClient::IpcClient(std::string socket_path) : socket_path_(std::move(socket_path)) {}

IpcClient::~IpcClient() {
  disconnect();
}

bool IpcClient::connect(std::error_code& ec) {
  if (connected_) {
    ec = std::make_error_code(std::errc::already_connected);
    return false;
  }

  // Create socket
  socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
  if (socket_fd_ == -1) {
    ec = std::error_code(errno, std::generic_category());
    return false;
  }

  // Set non-blocking
  if (!set_nonblocking(socket_fd_, ec)) {
    close(socket_fd_);
    socket_fd_ = -1;
    return false;
  }

  // Connect to server
  struct sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

  if (::connect(socket_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
    if (errno != EINPROGRESS) {
      ec = std::error_code(errno, std::generic_category());
      close(socket_fd_);
      socket_fd_ = -1;
      return false;
    }
  }

  connected_ = true;
  if (connection_handler_) {
    connection_handler_(true);
  }
  return true;
}

void IpcClient::disconnect() {
  if (!connected_) {
    return;
  }

  connected_ = false;
  if (socket_fd_ != -1) {
    close(socket_fd_);
    socket_fd_ = -1;
  }

  if (connection_handler_) {
    connection_handler_(false);
  }
}

bool IpcClient::send_command(const Command& cmd, std::error_code& ec) {
  Message msg;
  msg.type = MessageType::kCommand;
  msg.payload = cmd;
  return send_message(msg, ec);
}

bool IpcClient::send_command(const Command& cmd, std::uint64_t request_id, std::error_code& ec) {
  Message msg;
  msg.type = MessageType::kCommand;
  msg.id = request_id;
  msg.payload = cmd;
  return send_message(msg, ec);
}

void IpcClient::on_message(MessageHandler handler) {
  message_handler_ = std::move(handler);
}

void IpcClient::on_connection_change(ConnectionHandler handler) {
  connection_handler_ = std::move(handler);
}

void IpcClient::poll(std::error_code& ec) {
  if (!connected_) {
    ec = std::make_error_code(std::errc::not_connected);
    return;
  }

  handle_incoming_data(ec);
}

bool IpcClient::send_message(const Message& msg, std::error_code& ec) {
  if (!connected_) {
    ec = std::make_error_code(std::errc::not_connected);
    return false;
  }

  std::string data = serialize_message(msg);
  return send_raw(data, ec);
}

bool IpcClient::send_raw(const std::string& data, std::error_code& ec) {
  ssize_t sent = send(socket_fd_, data.c_str(), data.size(), MSG_NOSIGNAL);
  if (sent == -1) {
    ec = std::error_code(errno, std::generic_category());
    if (errno == EPIPE || errno == ECONNRESET) {
      disconnect();
    }
    return false;
  }
  return true;
}

void IpcClient::handle_incoming_data(std::error_code& ec) {
  char buffer[kBufferSize];
  ssize_t n = recv(socket_fd_, buffer, sizeof(buffer), 0);

  if (n == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return;  // No data available
    }
    ec = std::error_code(errno, std::generic_category());
    disconnect();
    return;
  }

  if (n == 0) {
    // Server disconnected
    disconnect();
    return;
  }

  // Append to receive buffer
  receive_buffer_.append(buffer, static_cast<std::size_t>(n));

  // Process complete messages (newline-delimited)
  std::size_t pos = 0;
  while ((pos = receive_buffer_.find('\n')) != std::string::npos) {
    std::string message_str = receive_buffer_.substr(0, pos);
    receive_buffer_.erase(0, pos + 1);

    // Deserialize and handle message
    auto msg = deserialize_message(message_str);
    if (msg && message_handler_) {
      message_handler_(*msg);
    }
  }
}

}  // namespace veil::ipc
