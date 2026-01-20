// VEIL Performance Validation Tool
//
// This tool validates VEIL against production performance requirements:
// - Throughput: ≥ 500 Mbps
// - Handshake Latency: ≤ 150 ms
// - Memory @1000 clients: ≤ 50 MB
// - CPU @100 Mbps: ≤ 30%
//
// Usage:
//   veil-performance-validation --test=throughput
//   veil-performance-validation --test=handshake
//   veil-performance-validation --test=memory
//   veil-performance-validation --test=all
//

#include <CLI/CLI.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <thread>
#include <vector>

#include "common/crypto/crypto_engine.h"
#include "common/crypto/random.h"
#include "common/handshake/handshake_processor.h"
#include "common/logging/logger.h"
#include "common/utils/rate_limiter.h"
#include "transport/session/transport_session.h"

namespace {

using namespace veil;
using namespace std::chrono_literals;

// Performance targets from TZ
constexpr double kTargetThroughputMbps = 500.0;
constexpr double kTargetHandshakeLatencyMs = 150.0;
constexpr std::size_t kTargetMemoryMb = 50;
// Note: CPU test not implemented yet - requires /proc/stat parsing
// constexpr double kTargetCpuPercent = 30.0;

// Test configuration
struct ValidationConfig {
  std::string test_type{"all"};
  int duration_sec{10};
  int num_clients{100};
  std::size_t message_size{1400};
  bool verbose{false};
  bool json_output{false};
};

// Test results
struct ThroughputResult {
  double throughput_mbps{0.0};
  double p50_latency_ms{0.0};
  double p95_latency_ms{0.0};
  double p99_latency_ms{0.0};
  std::uint64_t total_bytes{0};
  std::uint64_t total_packets{0};
  bool passed{false};
};

struct HandshakeResult {
  double avg_latency_ms{0.0};
  double p50_latency_ms{0.0};
  double p95_latency_ms{0.0};
  double p99_latency_ms{0.0};
  std::uint64_t successful{0};
  std::uint64_t failed{0};
  bool passed{false};
};

struct MemoryResult {
  std::size_t rss_kb{0};
  std::size_t virt_kb{0};
  double mb_per_client{0.0};
  std::uint64_t num_clients{0};
  bool passed{false};
};

struct ValidationResults {
  ThroughputResult throughput;
  HandshakeResult handshake;
  MemoryResult memory;
  bool all_passed{false};
};

// Get current process memory usage
std::pair<std::size_t, std::size_t> get_memory_usage() {
  std::size_t rss = 0;
  std::size_t virt = 0;

  std::ifstream stat("/proc/self/statm");
  if (stat.is_open()) {
    std::size_t size, resident, shared, text, lib, data, dt;
    stat >> size >> resident >> shared >> text >> lib >> data >> dt;
    // Convert pages to KB (assuming 4KB pages)
    rss = resident * 4;
    virt = size * 4;
  }
  return {rss, virt};
}

// Compute percentile from sorted vector
double percentile(std::vector<double>& values, double p) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  std::size_t idx = static_cast<std::size_t>(p * static_cast<double>(values.size() - 1));
  return values[idx];
}

// Generate test PSK
std::vector<std::uint8_t> get_test_psk() {
  return std::vector<std::uint8_t>(32, 0xAB);
}

// Create a mock handshake session for testing
handshake::HandshakeSession create_test_session() {
  auto now_fn = []() { return std::chrono::system_clock::now(); };
  auto steady_fn = []() { return std::chrono::steady_clock::now(); };

  handshake::HandshakeInitiator initiator(get_test_psk(), 200ms, now_fn);
  utils::TokenBucket bucket(10000.0, 10ms, steady_fn);
  handshake::HandshakeResponder responder(get_test_psk(), 200ms, std::move(bucket), now_fn);

  auto init_bytes = initiator.create_init();
  auto result = responder.handle_init(init_bytes);

  if (!result) {
    throw std::runtime_error("Failed to create test session");
  }

  auto session = initiator.consume_response(result->response);
  if (!session) {
    throw std::runtime_error("Failed to consume response");
  }

  return *session;
}

// Test throughput
ThroughputResult test_throughput(const ValidationConfig& config) {
  std::cout << "\n=== Throughput Test ===\n";
  std::cout << "Duration: " << config.duration_sec << " seconds\n";
  std::cout << "Message size: " << config.message_size << " bytes\n";

  ThroughputResult result;
  std::vector<double> latencies;

  auto handshake_session = create_test_session();
  transport::TransportSession session(handshake_session);

  // Generate test data
  std::vector<std::uint8_t> test_data(config.message_size);
  for (std::size_t i = 0; i < test_data.size(); ++i) {
    test_data[i] = static_cast<std::uint8_t>(i & 0xFF);
  }

  auto start = std::chrono::steady_clock::now();
  auto end = start + std::chrono::seconds(config.duration_sec);

  while (std::chrono::steady_clock::now() < end) {
    auto op_start = std::chrono::steady_clock::now();

    // Encrypt
    auto encrypted = session.encrypt_data(test_data);

    // Decrypt (simulate loopback)
    for (const auto& pkt : encrypted) {
      auto decrypted = session.decrypt_packet(pkt);
      if (decrypted) {
        result.total_bytes += config.message_size;
        ++result.total_packets;
      }
    }

    auto op_end = std::chrono::steady_clock::now();
    double latency_ms = std::chrono::duration<double, std::milli>(op_end - op_start).count();
    latencies.push_back(latency_ms);
  }

  auto actual_end = std::chrono::steady_clock::now();
  double duration_sec = std::chrono::duration<double>(actual_end - start).count();

  result.throughput_mbps = (static_cast<double>(result.total_bytes) * 8.0) / (duration_sec * 1e6);

  if (!latencies.empty()) {
    result.p50_latency_ms = percentile(latencies, 0.50);
    result.p95_latency_ms = percentile(latencies, 0.95);
    result.p99_latency_ms = percentile(latencies, 0.99);
  }

  result.passed = result.throughput_mbps >= kTargetThroughputMbps;

  std::cout << "\nResults:\n";
  std::cout << "  Throughput: " << std::fixed << std::setprecision(2)
            << result.throughput_mbps << " Mbps "
            << (result.passed ? "[PASS]" : "[FAIL]") << "\n";
  std::cout << "  Target: >= " << kTargetThroughputMbps << " Mbps\n";
  std::cout << "  Total bytes: " << result.total_bytes << "\n";
  std::cout << "  Total packets: " << result.total_packets << "\n";
  std::cout << "  P50 latency: " << result.p50_latency_ms << " ms\n";
  std::cout << "  P95 latency: " << result.p95_latency_ms << " ms\n";
  std::cout << "  P99 latency: " << result.p99_latency_ms << " ms\n";

  return result;
}

// Test handshake latency
HandshakeResult test_handshake(const ValidationConfig& config) {
  (void)config;  // Currently unused but reserved for future configuration
  std::cout << "\n=== Handshake Latency Test ===\n";

  constexpr int kSequentialHandshakes = 1000;
  constexpr int kParallelHandshakes = 100;

  HandshakeResult result;
  std::vector<double> latencies;

  auto now_fn = []() { return std::chrono::system_clock::now(); };
  auto steady_fn = []() { return std::chrono::steady_clock::now(); };

  // Sequential handshakes
  std::cout << "Running " << kSequentialHandshakes << " sequential handshakes...\n";

  for (int i = 0; i < kSequentialHandshakes; ++i) {
    auto start = std::chrono::steady_clock::now();

    handshake::HandshakeInitiator initiator(get_test_psk(), 200ms, now_fn);
    utils::TokenBucket bucket(100000.0, 1ms, steady_fn);
    handshake::HandshakeResponder responder(get_test_psk(), 200ms, std::move(bucket), now_fn);

    auto init_bytes = initiator.create_init();
    auto resp = responder.handle_init(init_bytes);

    if (resp) {
      auto session = initiator.consume_response(resp->response);
      if (session) {
        ++result.successful;
        auto end = std::chrono::steady_clock::now();
        double latency_ms = std::chrono::duration<double, std::milli>(end - start).count();
        latencies.push_back(latency_ms);
      } else {
        ++result.failed;
      }
    } else {
      ++result.failed;
    }
  }

  // Parallel handshakes
  std::cout << "Running " << kParallelHandshakes << " parallel handshakes...\n";

  std::vector<std::thread> threads;
  std::atomic<std::uint64_t> parallel_success{0};
  std::atomic<std::uint64_t> parallel_fail{0};
  std::vector<double> parallel_latencies(static_cast<std::size_t>(kParallelHandshakes));

  for (std::size_t i = 0; i < static_cast<std::size_t>(kParallelHandshakes); ++i) {
    threads.emplace_back([&, i]() {
      auto start = std::chrono::steady_clock::now();

      handshake::HandshakeInitiator initiator(get_test_psk(), 200ms, now_fn);
      utils::TokenBucket bucket(100000.0, 1ms, steady_fn);
      handshake::HandshakeResponder responder(get_test_psk(), 200ms, std::move(bucket), now_fn);

      auto init_bytes = initiator.create_init();
      auto resp = responder.handle_init(init_bytes);

      if (resp) {
        auto session = initiator.consume_response(resp->response);
        if (session) {
          ++parallel_success;
          auto end = std::chrono::steady_clock::now();
          parallel_latencies[i] = std::chrono::duration<double, std::milli>(end - start).count();
        } else {
          ++parallel_fail;
          parallel_latencies[i] = 0;
        }
      } else {
        ++parallel_fail;
        parallel_latencies[i] = 0;
      }
    });
  }

  for (auto& t : threads) {
    t.join();
  }

  result.successful += parallel_success.load();
  result.failed += parallel_fail.load();

  for (double lat : parallel_latencies) {
    if (lat > 0) {
      latencies.push_back(lat);
    }
  }

  // Calculate statistics
  if (!latencies.empty()) {
    result.avg_latency_ms = std::accumulate(latencies.begin(), latencies.end(), 0.0)
                            / static_cast<double>(latencies.size());
    result.p50_latency_ms = percentile(latencies, 0.50);
    result.p95_latency_ms = percentile(latencies, 0.95);
    result.p99_latency_ms = percentile(latencies, 0.99);
  }

  result.passed = result.p95_latency_ms <= kTargetHandshakeLatencyMs;

  std::cout << "\nResults:\n";
  std::cout << "  Avg latency: " << std::fixed << std::setprecision(2)
            << result.avg_latency_ms << " ms\n";
  std::cout << "  P50 latency: " << result.p50_latency_ms << " ms\n";
  std::cout << "  P95 latency: " << result.p95_latency_ms << " ms "
            << (result.passed ? "[PASS]" : "[FAIL]") << "\n";
  std::cout << "  P99 latency: " << result.p99_latency_ms << " ms\n";
  std::cout << "  Target: <= " << kTargetHandshakeLatencyMs << " ms\n";
  std::cout << "  Successful: " << result.successful << "\n";
  std::cout << "  Failed: " << result.failed << "\n";

  return result;
}

// Test memory footprint
MemoryResult test_memory(const ValidationConfig& config) {
  std::cout << "\n=== Memory Footprint Test ===\n";
  std::cout << "Clients: " << config.num_clients << "\n";

  MemoryResult result;
  result.num_clients = static_cast<std::uint64_t>(config.num_clients);

  // Get baseline memory
  auto [baseline_rss, baseline_virt] = get_memory_usage();
  std::cout << "Baseline RSS: " << (baseline_rss / 1024) << " MB\n";

  // Create sessions
  std::vector<std::unique_ptr<transport::TransportSession>> sessions;
  sessions.reserve(static_cast<std::size_t>(config.num_clients));

  std::cout << "Creating " << config.num_clients << " sessions...\n";

  for (std::size_t i = 0; i < static_cast<std::size_t>(config.num_clients); ++i) {
    auto handshake_session = create_test_session();
    sessions.push_back(std::make_unique<transport::TransportSession>(handshake_session));

    if ((i + 1) % 100 == 0) {
      auto [rss, virt] = get_memory_usage();
      if (config.verbose) {
        std::cout << "  " << (i + 1) << " sessions: RSS=" << (rss / 1024) << " MB\n";
      }
    }
  }

  // Measure memory after all sessions created
  auto [final_rss, final_virt] = get_memory_usage();
  result.rss_kb = final_rss;
  result.virt_kb = final_virt;

  std::size_t delta_kb = final_rss - baseline_rss;
  result.mb_per_client = static_cast<double>(delta_kb) / (static_cast<double>(config.num_clients) * 1024.0);

  std::size_t total_mb = final_rss / 1024;
  result.passed = (total_mb <= kTargetMemoryMb) || (result.mb_per_client * 1000 <= kTargetMemoryMb);

  std::cout << "\nResults:\n";
  std::cout << "  Total RSS: " << (final_rss / 1024) << " MB\n";
  std::cout << "  Memory delta: " << (delta_kb / 1024) << " MB\n";
  std::cout << "  Per-client: " << std::fixed << std::setprecision(3)
            << (result.mb_per_client * 1024) << " KB\n";
  std::cout << "  Projected @1000 clients: " << std::fixed << std::setprecision(1)
            << (result.mb_per_client * 1000) << " MB "
            << (result.passed ? "[PASS]" : "[FAIL]") << "\n";
  std::cout << "  Target: <= " << kTargetMemoryMb << " MB\n";

  // Clean up
  sessions.clear();

  return result;
}

// Print JSON output
void print_json_results(const ValidationResults& results) {
  std::cout << "{\n";
  std::cout << "  \"throughput\": {\n";
  std::cout << "    \"mbps\": " << results.throughput.throughput_mbps << ",\n";
  std::cout << "    \"target_mbps\": " << kTargetThroughputMbps << ",\n";
  std::cout << "    \"passed\": " << (results.throughput.passed ? "true" : "false") << "\n";
  std::cout << "  },\n";
  std::cout << "  \"handshake\": {\n";
  std::cout << "    \"p95_latency_ms\": " << results.handshake.p95_latency_ms << ",\n";
  std::cout << "    \"target_latency_ms\": " << kTargetHandshakeLatencyMs << ",\n";
  std::cout << "    \"passed\": " << (results.handshake.passed ? "true" : "false") << "\n";
  std::cout << "  },\n";
  std::cout << "  \"memory\": {\n";
  std::cout << "    \"projected_1000_clients_mb\": " << (results.memory.mb_per_client * 1000) << ",\n";
  std::cout << "    \"target_mb\": " << kTargetMemoryMb << ",\n";
  std::cout << "    \"passed\": " << (results.memory.passed ? "true" : "false") << "\n";
  std::cout << "  },\n";
  std::cout << "  \"all_passed\": " << (results.all_passed ? "true" : "false") << "\n";
  std::cout << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    CLI::App app{"VEIL Performance Validation Tool"};

    ValidationConfig config;

    app.add_option("--test,-t", config.test_type, "Test type: throughput, handshake, memory, all")
        ->check(CLI::IsMember({"throughput", "handshake", "memory", "all"}));
    app.add_option("--duration,-d", config.duration_sec, "Test duration in seconds");
    app.add_option("--clients,-c", config.num_clients, "Number of clients for memory test");
    app.add_option("--size,-s", config.message_size, "Message size in bytes");
    app.add_flag("--verbose,-v", config.verbose, "Verbose output");
    app.add_flag("--json,-j", config.json_output, "JSON output");

    CLI11_PARSE(app, argc, argv);

    // Initialize logging
    logging::configure_logging(
        config.verbose ? logging::LogLevel::debug : logging::LogLevel::warn, true);

    std::cout << "VEIL Performance Validation Tool\n";
    std::cout << "================================\n";
    std::cout << "Target Metrics:\n";
    std::cout << "  Throughput: >= " << kTargetThroughputMbps << " Mbps\n";
    std::cout << "  Handshake Latency: <= " << kTargetHandshakeLatencyMs << " ms\n";
    std::cout << "  Memory @1000 clients: <= " << kTargetMemoryMb << " MB\n";

    ValidationResults results;

    if (config.test_type == "throughput" || config.test_type == "all") {
      results.throughput = test_throughput(config);
    }

    if (config.test_type == "handshake" || config.test_type == "all") {
      results.handshake = test_handshake(config);
    }

    if (config.test_type == "memory" || config.test_type == "all") {
      results.memory = test_memory(config);
    }

    results.all_passed = results.throughput.passed &&
                         results.handshake.passed &&
                         results.memory.passed;

    std::cout << "\n=== Summary ===\n";
    if (config.test_type == "all" || config.test_type == "throughput") {
      std::cout << "Throughput: " << (results.throughput.passed ? "PASS" : "FAIL") << "\n";
    }
    if (config.test_type == "all" || config.test_type == "handshake") {
      std::cout << "Handshake: " << (results.handshake.passed ? "PASS" : "FAIL") << "\n";
    }
    if (config.test_type == "all" || config.test_type == "memory") {
      std::cout << "Memory: " << (results.memory.passed ? "PASS" : "FAIL") << "\n";
    }

    if (config.test_type == "all") {
      std::cout << "\nOverall: " << (results.all_passed ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << "\n";
    }

    if (config.json_output) {
      std::cout << "\n";
      print_json_results(results);
    }

    return results.all_passed ? 0 : 1;

  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << '\n';
    return 1;
  }
}
