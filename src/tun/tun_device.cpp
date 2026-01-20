#include "tun/tun_device.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <system_error>

#include "common/logging/logger.h"

namespace {
std::error_code last_error() { return std::error_code(errno, std::generic_category()); }

// Maximum packet size for TUN devices.
constexpr std::size_t kMaxPacketSize = 65535;

// TUN packet info header size (4 bytes: flags + proto).
constexpr std::size_t kTunPiSize = 4;
}  // namespace

namespace veil::tun {

TunDevice::TunDevice() = default;

TunDevice::~TunDevice() { close(); }

TunDevice::TunDevice(TunDevice&& other) noexcept
    : fd_(other.fd_),
      device_name_(std::move(other.device_name_)),
      stats_(other.stats_),
      packet_info_(other.packet_info_) {
  other.fd_ = -1;
}

TunDevice& TunDevice::operator=(TunDevice&& other) noexcept {
  if (this != &other) {
    close();
    fd_ = other.fd_;
    device_name_ = std::move(other.device_name_);
    stats_ = other.stats_;
    packet_info_ = other.packet_info_;
    other.fd_ = -1;
  }
  return *this;
}

bool TunDevice::open(const TunConfig& config, std::error_code& ec) {
  // Open the TUN clone device.
  fd_ = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
  if (fd_ < 0) {
    ec = last_error();
    LOG_ERROR("Failed to open /dev/net/tun: {}", ec.message());
    return false;
  }

  // Configure the TUN device.
  ifreq ifr{};
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (config.packet_info) {
    ifr.ifr_flags = IFF_TUN;
    packet_info_ = true;
  }

  // Set device name if provided.
  if (!config.device_name.empty()) {
    // IFNAMSIZ is typically 16, so we use size()-1 to leave room for null terminator.
    std::strncpy(ifr.ifr_name, config.device_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
  }

  // Create the TUN device.
  if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
    ec = last_error();
    LOG_ERROR("Failed to create TUN device: {}", ec.message());
    close();
    return false;
  }

  device_name_ = ifr.ifr_name;
  LOG_INFO("Created TUN device: {}", device_name_);

  // Configure IP address if provided.
  if (!config.ip_address.empty()) {
    if (!configure_address(config, ec)) {
      close();
      return false;
    }
  }

  // Set MTU.
  if (config.mtu > 0) {
    if (!configure_mtu(config.mtu, ec)) {
      close();
      return false;
    }
  }

  // Bring interface up.
  if (config.bring_up) {
    if (!bring_interface_up(ec)) {
      close();
      return false;
    }
  }

  return true;
}

void TunDevice::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
    LOG_INFO("Closed TUN device: {}", device_name_);
  }
}

bool TunDevice::configure_address(const TunConfig& config, std::error_code& ec) {
  // Need a socket for ioctl operations.
  const int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    ec = last_error();
    LOG_ERROR("Failed to create socket for TUN configuration: {}", ec.message());
    return false;
  }

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, device_name_.c_str(), IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';

  // Set IP address.
  auto* addr = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
  addr->sin_family = AF_INET;
  if (inet_pton(AF_INET, config.ip_address.c_str(), &addr->sin_addr) != 1) {
    ec = std::make_error_code(std::errc::invalid_argument);
    LOG_ERROR("Invalid IP address: {}", config.ip_address);
    ::close(sock);
    return false;
  }

  if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
    ec = last_error();
    LOG_ERROR("Failed to set IP address: {}", ec.message());
    ::close(sock);
    return false;
  }

  LOG_INFO("Set IP address {} on {}", config.ip_address, device_name_);

  // Set netmask.
  auto* mask = reinterpret_cast<sockaddr_in*>(&ifr.ifr_netmask);
  mask->sin_family = AF_INET;
  if (inet_pton(AF_INET, config.netmask.c_str(), &mask->sin_addr) != 1) {
    ec = std::make_error_code(std::errc::invalid_argument);
    LOG_ERROR("Invalid netmask: {}", config.netmask);
    ::close(sock);
    return false;
  }

  if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
    ec = last_error();
    LOG_ERROR("Failed to set netmask: {}", ec.message());
    ::close(sock);
    return false;
  }

  LOG_INFO("Set netmask {} on {}", config.netmask, device_name_);

  ::close(sock);
  return true;
}

bool TunDevice::configure_mtu(int mtu, std::error_code& ec) {
  const int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    ec = last_error();
    return false;
  }

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, device_name_.c_str(), IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';
  ifr.ifr_mtu = mtu;

  if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
    ec = last_error();
    LOG_ERROR("Failed to set MTU to {}: {}", mtu, ec.message());
    ::close(sock);
    return false;
  }

  LOG_INFO("Set MTU {} on {}", mtu, device_name_);
  ::close(sock);
  return true;
}

bool TunDevice::bring_interface_up(std::error_code& ec) {
  const int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    ec = last_error();
    return false;
  }

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, device_name_.c_str(), IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';

  // Get current flags.
  if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
    ec = last_error();
    LOG_ERROR("Failed to get interface flags: {}", ec.message());
    ::close(sock);
    return false;
  }

  // Set IFF_UP flag.
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

  if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
    ec = last_error();
    LOG_ERROR("Failed to bring interface up: {}", ec.message());
    ::close(sock);
    return false;
  }

  LOG_INFO("Brought interface {} up", device_name_);
  ::close(sock);
  return true;
}

bool TunDevice::set_mtu(int mtu, std::error_code& ec) { return configure_mtu(mtu, ec); }

bool TunDevice::set_up(bool up, std::error_code& ec) {
  const int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    ec = last_error();
    return false;
  }

  ifreq ifr{};
  std::strncpy(ifr.ifr_name, device_name_.c_str(), IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';

  if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
    ec = last_error();
    ::close(sock);
    return false;
  }

  if (up) {
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  } else {
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
  }

  if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
    ec = last_error();
    ::close(sock);
    return false;
  }

  LOG_INFO("Set interface {} {}", device_name_, up ? "up" : "down");
  ::close(sock);
  return true;
}

std::optional<std::vector<std::uint8_t>> TunDevice::read(std::error_code& ec) {
  std::array<std::uint8_t, kMaxPacketSize> buffer{};
  const auto n = read_into(buffer, ec);
  if (n <= 0) {
    return std::nullopt;
  }
  return std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + n);
}

std::ptrdiff_t TunDevice::read_into(std::span<std::uint8_t> buffer, std::error_code& ec) {
  const auto n = ::read(fd_, buffer.data(), buffer.size());
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;  // No data available.
    }
    ec = last_error();
    stats_.read_errors++;
    return -1;
  }

  stats_.packets_read++;
  stats_.bytes_read += static_cast<std::uint64_t>(n);

  // If packet_info is enabled, strip the 4-byte header.
  if (packet_info_ && n >= static_cast<std::ptrdiff_t>(kTunPiSize)) {
    // Move data to beginning, skipping the header.
    std::memmove(buffer.data(), buffer.data() + kTunPiSize, static_cast<std::size_t>(n) - kTunPiSize);
    return n - static_cast<std::ptrdiff_t>(kTunPiSize);
  }

  return n;
}

bool TunDevice::write(std::span<const std::uint8_t> packet, std::error_code& ec) {
  std::ptrdiff_t n = 0;

  if (packet_info_) {
    // Prepend 4-byte packet info header.
    std::vector<std::uint8_t> buffer(kTunPiSize + packet.size());
    // Flags = 0, Protocol = ETH_P_IP (0x0800) in network byte order.
    buffer[0] = 0;
    buffer[1] = 0;
    buffer[2] = 0x08;
    buffer[3] = 0x00;
    std::memcpy(buffer.data() + kTunPiSize, packet.data(), packet.size());
    n = ::write(fd_, buffer.data(), buffer.size());
    if (n < 0 || static_cast<std::size_t>(n) != buffer.size()) {
      ec = last_error();
      stats_.write_errors++;
      return false;
    }
  } else {
    n = ::write(fd_, packet.data(), packet.size());
    if (n < 0 || static_cast<std::size_t>(n) != packet.size()) {
      ec = last_error();
      stats_.write_errors++;
      return false;
    }
  }

  stats_.packets_written++;
  stats_.bytes_written += packet.size();
  return true;
}

bool TunDevice::poll(const ReadHandler& handler, int timeout_ms, std::error_code& ec) {
  const int ep = epoll_create1(0);
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
    return true;  // Timeout, no data.
  }

  for (int i = 0; i < n; ++i) {
    if ((events[static_cast<std::size_t>(i)].events & EPOLLIN) == 0U) {
      continue;
    }
    auto packet = read(ec);
    if (packet && !packet->empty()) {
      handler(*packet);
    }
  }

  ::close(ep);
  return true;
}

}  // namespace veil::tun
