#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <system_error>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "transport/udp_socket/udp_socket.h"

namespace veil::tests {

TEST(UdpSocketTests, SendAndReceiveLoopback) {
  transport::UdpSocket server;
  std::error_code ec;
  if (!server.open(0, false, ec)) {
    if (ec == std::errc::operation_not_permitted) {
      GTEST_SKIP() << "UDP sockets not permitted in this environment";
    }
    FAIL() << ec.message();
  }

  sockaddr_in addr{};
  socklen_t len = sizeof(addr);
  ASSERT_EQ(::getsockname(server.fd(), reinterpret_cast<sockaddr*>(&addr), &len), 0);
  const auto port = ntohs(addr.sin_port);

  transport::UdpSocket client;
  if (!client.open(0, false, ec)) {
    if (ec == std::errc::operation_not_permitted) {
      GTEST_SKIP() << "UDP sockets not permitted in this environment";
    }
    FAIL() << ec.message();
  }

  transport::UdpEndpoint server_ep{"127.0.0.1", port};
  std::vector<std::uint8_t> payload{1, 2, 3};
  ASSERT_TRUE(client.send(payload, server_ep, ec)) << ec.message();

  bool received = false;
  server.poll(
      [&](const transport::UdpPacket& pkt) {
        received = true;
        EXPECT_EQ(pkt.data, payload);
      },
      100, ec);
  EXPECT_TRUE(received);
}

}  // namespace veil::tests
