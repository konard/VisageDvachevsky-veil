#include "transport/udp_socket/udp_socket.h"

#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring>
#include <system_error>
#include <vector>

#include "common/logging/logger.h"

// Check for sendmmsg availability (Linux 3.0+, glibc 2.14+).
// On systems without sendmmsg, we fall back to multiple sendto calls.
#if defined(__linux__) && defined(__GLIBC__) && \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 14))
#define VEIL_HAS_SENDMMSG 1
#else
#define VEIL_HAS_SENDMMSG 0
#endif

namespace {
std::error_code last_error() { return std::error_code(errno, std::generic_category()); }

bool resolve(const veil::transport::UdpEndpoint& endpoint, sockaddr_in& addr) {
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(endpoint.port);
  if (inet_pton(AF_INET, endpoint.host.c_str(), &addr.sin_addr) != 1) {
    return false;
  }
  return true;
}

void fill_endpoint(const sockaddr_in& addr, veil::transport::UdpEndpoint& endpoint) {
  std::array<char, INET_ADDRSTRLEN> buffer{};
  const char* res = inet_ntop(AF_INET, &addr.sin_addr, buffer.data(), buffer.size());
  endpoint.host = (res != nullptr) ? buffer.data() : "";
  endpoint.port = ntohs(addr.sin_port);
}
}  // namespace

namespace veil::transport {

UdpSocket::UdpSocket() = default;
UdpSocket::~UdpSocket() { close(); }

bool UdpSocket::configure_socket(bool reuse_port, std::error_code& ec) {
  const int enable = 1;
  if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
    ec = last_error();
    return false;
  }
#ifdef SO_REUSEPORT
  if (reuse_port) {
    if (setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) != 0) {
      ec = last_error();
      return false;
    }
  }
#endif
  return true;
}

bool UdpSocket::open(std::uint16_t bind_port, bool reuse_port, std::error_code& ec) {
  fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (fd_ < 0) {
    ec = last_error();
    return false;
  }
  if (!configure_socket(reuse_port, ec)) {
    close();
    return false;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(bind_port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ec = last_error();
    close();
    return false;
  }
  return true;
}

bool UdpSocket::connect(const UdpEndpoint& remote, std::error_code& ec) {
  sockaddr_in addr{};
  if (!resolve(remote, addr)) {
    ec = std::make_error_code(std::errc::invalid_argument);
    return false;
  }
  if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ec = last_error();
    return false;
  }
  connected_ = remote;
  return true;
}

bool UdpSocket::send(std::span<const std::uint8_t> data, const UdpEndpoint& remote,
                     std::error_code& ec) {
  sockaddr_in addr{};
  if (!resolve(remote, addr)) {
    ec = std::make_error_code(std::errc::invalid_argument);
    return false;
  }
  const auto sent =
      ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (sent < 0 || static_cast<std::size_t>(sent) != data.size()) {
    ec = last_error();
    return false;
  }
  return true;
}

bool UdpSocket::send_batch(std::span<const UdpPacket> packets, std::error_code& ec) {
  if (packets.empty()) {
    return true;
  }

#if VEIL_HAS_SENDMMSG
  // Use sendmmsg for better performance when available.
  std::vector<mmsghdr> messages(packets.size());
  std::vector<sockaddr_in> addrs(packets.size());
  std::vector<iovec> iovecs(packets.size());
  for (std::size_t i = 0; i < packets.size(); ++i) {
    if (!resolve(packets[i].remote, addrs[i])) {
      ec = std::make_error_code(std::errc::invalid_argument);
      return false;
    }
    iovecs[i].iov_base = const_cast<std::uint8_t*>(packets[i].data.data());
    iovecs[i].iov_len = packets[i].data.size();
    messages[i].msg_hdr.msg_name = &addrs[i];
    messages[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
    messages[i].msg_hdr.msg_iov = &iovecs[i];
    messages[i].msg_hdr.msg_iovlen = 1;
    messages[i].msg_hdr.msg_control = nullptr;
    messages[i].msg_hdr.msg_controllen = 0;
    messages[i].msg_hdr.msg_flags = 0;
    messages[i].msg_len = 0;
  }
  const auto sent =
      ::sendmmsg(fd_, messages.data(), static_cast<unsigned int>(messages.size()), 0);
  if (sent < 0) {
    // If sendmmsg fails with EPERM (sandbox/container), fall back to sendto.
    if (errno == EPERM || errno == ENOSYS) {
      LOG_DEBUG("sendmmsg failed with {}, falling back to sendto", errno);
      goto fallback;
    }
    ec = last_error();
    return false;
  }
  if (static_cast<std::size_t>(sent) != packets.size()) {
    ec = last_error();
    return false;
  }
  return true;

fallback:
#endif
  // Fallback: send each packet individually with sendto.
  for (const auto& pkt : packets) {
    if (!send(pkt.data, pkt.remote, ec)) {
      return false;
    }
  }
  return true;
}

bool UdpSocket::poll(const ReceiveHandler& handler, int timeout_ms, std::error_code& ec) {
  int ep = epoll_create1(0);
  if (ep < 0) {
    ec = last_error();
    return false;
  }
  epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = fd_;
  if (epoll_ctl(ep, EPOLL_CTL_ADD, fd_, &ev) != 0) {
    ec = last_error();
    ::close(ep);
    return false;
  }

  std::array<epoll_event, 4> events{};
  const int n = epoll_wait(ep, events.data(), static_cast<int>(events.size()), timeout_ms);
  if (n < 0) {
    ec = last_error();
    ::close(ep);
    return false;
  }

  if (n == 0) {
    ::close(ep);
    return true;
  }

  std::array<std::uint8_t, 65535> buffer{};
  for (int i = 0; i < n; ++i) {
    if ((events[static_cast<std::size_t>(i)].events & EPOLLIN) == 0U) {
      continue;
    }
    sockaddr_in src{};
    socklen_t src_len = sizeof(src);
    const auto read =
        ::recvfrom(fd_, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&src), &src_len);
    if (read <= 0) {
      continue;
    }
    UdpEndpoint remote{};
    fill_endpoint(src, remote);
    handler(UdpPacket{std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + read), remote});
  }

  ::close(ep);
  return true;
}

void UdpSocket::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

}  // namespace veil::transport
