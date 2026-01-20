#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace veil::transport {

struct UdpEndpoint {
  std::string host;
  std::uint16_t port{0};
};

struct UdpPacket {
  std::vector<std::uint8_t> data;
  UdpEndpoint remote;
};

class UdpSocket {
 public:
  using ReceiveHandler = std::function<void(const UdpPacket&)>;

  UdpSocket();
  ~UdpSocket();

  bool open(std::uint16_t bind_port, bool reuse_port, std::error_code& ec);
  bool connect(const UdpEndpoint& remote, std::error_code& ec);
  bool send(std::span<const std::uint8_t> data, const UdpEndpoint& remote, std::error_code& ec);
  bool send_batch(std::span<const UdpPacket> packets, std::error_code& ec);
  bool poll(const ReceiveHandler& handler, int timeout_ms, std::error_code& ec);
  void close();

  int fd() const { return fd_; }

 private:
  int fd_{-1};
  UdpEndpoint connected_;

  bool configure_socket(bool reuse_port, std::error_code& ec);
};

}  // namespace veil::transport
