#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>

namespace veil::tun {

// Constants for MTU discovery.
constexpr int kDefaultMtu = 1500;
constexpr int kMinMtu = 576;         // Minimum IPv4 MTU.
constexpr int kMaxMtu = 65535;
constexpr int kVeilOverhead = 100;   // Encryption + headers overhead.
constexpr int kDefaultVeilMtu = 1400;

// Result of a path MTU probe.
struct PmtuProbeResult {
  int mtu{0};
  bool success{false};
  std::chrono::steady_clock::time_point timestamp;
};

// Configuration for PMTU discovery.
struct PmtuConfig {
  // Initial MTU to try.
  int initial_mtu{kDefaultVeilMtu};
  // Minimum MTU to accept.
  int min_mtu{kMinMtu};
  // Maximum MTU to try.
  int max_mtu{kDefaultMtu};
  // Probe interval for periodic discovery.
  std::chrono::seconds probe_interval{300};
  // Number of probes before giving up at a size.
  int max_probes{3};
  // Timeout for probe response.
  std::chrono::milliseconds probe_timeout{1000};
  // Enable DF (Don't Fragment) bit on probes.
  bool set_df_bit{true};
};

// Path MTU discovery manager.
// Implements RFC 1191 (PMTU Discovery) and RFC 4821 (Packetization Layer PMTUD).
class PmtuDiscovery {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using MtuChangeCallback = std::function<void(const std::string& peer, int old_mtu, int new_mtu)>;

  explicit PmtuDiscovery(PmtuConfig config = {}, std::function<TimePoint()> now_fn = Clock::now);

  // Get current path MTU for a peer.
  int get_mtu(const std::string& peer) const;

  // Set MTU for a peer (e.g., from ICMP Fragmentation Needed).
  void set_mtu(const std::string& peer, int mtu);

  // Handle ICMP Fragmentation Needed message.
  // next_hop_mtu is the MTU reported by the ICMP message (0 if not provided).
  void handle_fragmentation_needed(const std::string& peer, int next_hop_mtu);

  // Handle successful transmission at a given size.
  void handle_probe_success(const std::string& peer, int size);

  // Handle probe failure (timeout or rejection).
  void handle_probe_failure(const std::string& peer, int size);

  // Check if we should probe for a larger MTU.
  bool should_probe_increase(const std::string& peer) const;

  // Get the next probe size to try.
  int get_next_probe_size(const std::string& peer) const;

  // Register callback for MTU changes.
  void set_mtu_change_callback(MtuChangeCallback callback);

  // Get effective payload size (MTU minus overhead).
  int get_payload_size(const std::string& peer) const;

  // Reset MTU discovery state for a peer.
  void reset(const std::string& peer);

  // Remove peer from tracking.
  void remove_peer(const std::string& peer);

  // Get configuration.
  const PmtuConfig& config() const { return config_; }

 private:
  struct PeerState {
    int current_mtu{kDefaultVeilMtu};
    int probe_mtu{0};
    int probe_count{0};
    TimePoint last_probe;
    TimePoint last_decrease;
    bool probing{false};
  };

  PeerState& get_or_create_state(const std::string& peer);
  const PeerState* get_state(const std::string& peer) const;
  void notify_mtu_change(const std::string& peer, int old_mtu, int new_mtu);

  PmtuConfig config_;
  std::function<TimePoint()> now_fn_;
  std::unordered_map<std::string, PeerState> peers_;
  MtuChangeCallback mtu_change_callback_;
};

}  // namespace veil::tun
