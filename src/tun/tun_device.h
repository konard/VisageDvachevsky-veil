#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace veil::tun {

// Configuration for TUN device.
struct TunConfig {
  // Device name (e.g., "veil0"). Empty for system-assigned name.
  std::string device_name;
  // IP address in CIDR notation or dotted-decimal.
  std::string ip_address;
  // Netmask (e.g., "255.255.255.0").
  std::string netmask{"255.255.255.0"};
  // MTU size.
  int mtu{1400};
  // Enable packet information header (struct tun_pi).
  bool packet_info{false};
  // Bring interface up automatically.
  bool bring_up{true};
};

// Statistics for TUN device operations.
struct TunStats {
  std::uint64_t packets_read{0};
  std::uint64_t packets_written{0};
  std::uint64_t bytes_read{0};
  std::uint64_t bytes_written{0};
  std::uint64_t read_errors{0};
  std::uint64_t write_errors{0};
};

// RAII wrapper for Linux TUN device.
// Provides interface for reading/writing IP packets.
class TunDevice {
 public:
  using ReadHandler = std::function<void(std::span<const std::uint8_t>)>;

  TunDevice();
  ~TunDevice();

  // Non-copyable, movable.
  TunDevice(const TunDevice&) = delete;
  TunDevice& operator=(const TunDevice&) = delete;
  TunDevice(TunDevice&& other) noexcept;
  TunDevice& operator=(TunDevice&& other) noexcept;

  // Open and configure the TUN device.
  // Returns true on success, sets ec on failure.
  bool open(const TunConfig& config, std::error_code& ec);

  // Close the TUN device.
  void close();

  // Check if device is open.
  bool is_open() const { return fd_ >= 0; }

  // Get file descriptor for event loop integration.
  int fd() const { return fd_; }

  // Get the actual device name (may differ from requested if empty).
  const std::string& device_name() const { return device_name_; }

  // Read a packet from the TUN device.
  // Returns empty optional on EAGAIN/EWOULDBLOCK, nullopt with ec set on error.
  std::optional<std::vector<std::uint8_t>> read(std::error_code& ec);

  // Read into a provided buffer.
  // Returns number of bytes read, or -1 on error.
  std::ptrdiff_t read_into(std::span<std::uint8_t> buffer, std::error_code& ec);

  // Write a packet to the TUN device.
  // Returns true on success.
  bool write(std::span<const std::uint8_t> packet, std::error_code& ec);

  // Poll for incoming packets with timeout.
  bool poll(const ReadHandler& handler, int timeout_ms, std::error_code& ec);

  // Get statistics.
  const TunStats& stats() const { return stats_; }

  // Set MTU dynamically.
  bool set_mtu(int mtu, std::error_code& ec);

  // Set interface up/down.
  bool set_up(bool up, std::error_code& ec);

 private:
  // Configure IP address and netmask using ioctl.
  bool configure_address(const TunConfig& config, std::error_code& ec);

  // Set MTU using ioctl.
  bool configure_mtu(int mtu, std::error_code& ec);

  // Bring interface up.
  bool bring_interface_up(std::error_code& ec);

  int fd_{-1};
  std::string device_name_;
  TunStats stats_;
  bool packet_info_{false};
};

}  // namespace veil::tun
