// VEIL Transport Layer Benchmark Tool
//
// This tool provides iperf-like functionality for benchmarking the VEIL
// transport layer. It measures throughput, RTT, and retransmission rates.
//
// Usage:
//   veil-transport-bench --mode=server --port=12345
//   veil-transport-bench --mode=client --host=127.0.0.1 --port=12345 --duration=10
//
// Output:
//   Throughput (Mbps), RTT (ms), Retransmit rate (%), Data sent/received (MB)
//

#include <CLI/CLI.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <thread>
#include <vector>

#include "common/crypto/random.h"
#include "common/handshake/handshake_processor.h"
#include "common/logging/logger.h"
#include "common/utils/rate_limiter.h"
#include "transport/event_loop/event_loop.h"
#include "transport/session/transport_session.h"
#include "transport/udp_socket/udp_socket.h"

namespace {

using namespace veil;
using namespace std::chrono_literals;

// Global flag for graceful shutdown.
std::atomic<bool> g_running{true};

void signal_handler(int /*signum*/) { g_running.store(false); }

// Benchmark configuration.
struct BenchConfig {
  std::string mode{"client"};
  std::string host{"127.0.0.1"};
  std::uint16_t port{12345};
  int duration_sec{10};
  std::size_t message_size{1000};
  int num_streams{1};
  bool verbose{false};
};

// Benchmark results.
struct BenchResults {
  std::uint64_t bytes_sent{0};
  std::uint64_t bytes_received{0};
  std::uint64_t packets_sent{0};
  std::uint64_t packets_received{0};
  std::uint64_t retransmits{0};
  double duration_sec{0.0};
  double avg_rtt_ms{0.0};
  double p95_rtt_ms{0.0};

  double throughput_mbps() const {
    if (duration_sec == 0.0) return 0.0;
    return (static_cast<double>(bytes_sent + bytes_received) * 8.0) / (duration_sec * 1000000.0);
  }

  double retransmit_rate() const {
    if (packets_sent == 0) return 0.0;
    return (static_cast<double>(retransmits) / static_cast<double>(packets_sent)) * 100.0;
  }

  void print() const {
    std::cout << "\n=== VEIL Transport Benchmark Results ===\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Duration:         " << duration_sec << " sec\n";
    std::cout << "Bytes sent:       " << (static_cast<double>(bytes_sent) / 1000000.0) << " MB\n";
    std::cout << "Bytes received:   " << (static_cast<double>(bytes_received) / 1000000.0) << " MB\n";
    std::cout << "Packets sent:     " << packets_sent << '\n';
    std::cout << "Packets received: " << packets_received << '\n';
    std::cout << "Retransmits:      " << retransmits << '\n';
    std::cout << "Throughput:       " << throughput_mbps() << " Mbps\n";
    std::cout << "Retransmit rate:  " << retransmit_rate() << " %\n";
    std::cout << "Avg RTT:          " << avg_rtt_ms << " ms\n";
    std::cout << "P95 RTT:          " << p95_rtt_ms << " ms\n";
    std::cout << "========================================\n";
  }
};

// Simple PSK for benchmarking.
std::vector<std::uint8_t> get_bench_psk() {
  return std::vector<std::uint8_t>(32, 0xBE);  // Benchmark PSK
}

// Run server mode.
int run_server(const BenchConfig& config) {
  std::cout << "Starting VEIL transport benchmark server on port " << config.port << '\n';

  // Create UDP socket.
  transport::UdpSocket socket;
  std::error_code ec;
  if (!socket.open(config.port, true, ec)) {
    std::cerr << "Failed to open socket: " << ec.message() << '\n';
    return 1;
  }

  // Setup handshake responder.
  auto now_fn = []() { return std::chrono::system_clock::now(); };
  auto steady_fn = []() { return std::chrono::steady_clock::now(); };
  utils::TokenBucket bucket(1000.0, 100ms, steady_fn);
  handshake::HandshakeResponder responder(get_bench_psk(), 200ms, std::move(bucket), now_fn);

  std::optional<transport::TransportSession> session;
  transport::UdpEndpoint client_endpoint;
  BenchResults results;

  auto start_time = std::chrono::steady_clock::now();

  std::cout << "Waiting for client connection...\n";

  while (g_running.load()) {
    socket.poll(
        [&](const transport::UdpPacket& pkt) {
          if (!session) {
            // Handle handshake.
            auto resp = responder.handle_init(pkt.data);
            if (resp) {
              std::cout << "Handshake completed with client: " << pkt.remote.host << ":"
                        << pkt.remote.port << '\n';
              socket.send(resp->response, pkt.remote, ec);
              session.emplace(resp->session, transport::TransportSessionConfig{}, steady_fn);
              client_endpoint = pkt.remote;
              start_time = std::chrono::steady_clock::now();
            }
          } else {
            // Handle data.
            auto frames = session->decrypt_packet(pkt.data);
            if (frames) {
              results.bytes_received += pkt.data.size();
              ++results.packets_received;

              // Generate ACK periodically.
              for (const auto& frame : *frames) {
                if (frame.kind == mux::FrameKind::kData) {
                  auto ack = session->generate_ack(frame.data.stream_id);
                  auto ack_frame = mux::make_ack_frame(ack.stream_id, ack.ack, ack.bitmap);
                  auto ack_packets = session->encrypt_data(
                      mux::MuxCodec::encode(ack_frame), 0, false);
                  for (const auto& ack_pkt : ack_packets) {
                    socket.send(ack_pkt, client_endpoint, ec);
                  }
                }
              }
            }
          }
        },
        100, ec);

    if (session) {
      // Send retransmits if needed.
      auto retransmits = session->get_retransmit_packets();
      for (const auto& pkt : retransmits) {
        socket.send(pkt, client_endpoint, ec);
        ++results.retransmits;
      }
    }
  }

  auto end_time = std::chrono::steady_clock::now();
  results.duration_sec =
      std::chrono::duration<double>(end_time - start_time).count();

  if (session) {
    const auto& stats = session->stats();
    results.bytes_sent = stats.bytes_sent;
    results.packets_sent = stats.packets_sent;
  }

  results.print();
  return 0;
}

// Run client mode.
int run_client(const BenchConfig& config) {
  std::cout << "Starting VEIL transport benchmark client\n";
  std::cout << "Target: " << config.host << ":" << config.port << '\n';
  std::cout << "Duration: " << config.duration_sec << " seconds\n";
  std::cout << "Message size: " << config.message_size << " bytes\n";

  // Create UDP socket.
  transport::UdpSocket socket;
  std::error_code ec;
  if (!socket.open(0, false, ec)) {
    std::cerr << "Failed to open socket: " << ec.message() << '\n';
    return 1;
  }

  transport::UdpEndpoint server{config.host, config.port};

  // Perform handshake.
  auto now_fn = []() { return std::chrono::system_clock::now(); };
  auto steady_fn = []() { return std::chrono::steady_clock::now(); };
  handshake::HandshakeInitiator initiator(get_bench_psk(), 200ms, now_fn);

  auto init_bytes = initiator.create_init();
  if (!socket.send(init_bytes, server, ec)) {
    std::cerr << "Failed to send handshake: " << ec.message() << '\n';
    return 1;
  }

  std::cout << "Waiting for handshake response...\n";

  std::optional<transport::TransportSession> session;

  // Wait for handshake response.
  for (int i = 0; i < 50 && !session; ++i) {
    socket.poll(
        [&](const transport::UdpPacket& pkt) {
          auto sess = initiator.consume_response(pkt.data);
          if (sess) {
            session.emplace(*sess, transport::TransportSessionConfig{}, steady_fn);
            std::cout << "Handshake completed!\n";
          }
        },
        100, ec);
  }

  if (!session) {
    std::cerr << "Handshake failed\n";
    return 1;
  }

  // Prepare test data.
  std::vector<std::uint8_t> test_data(config.message_size);
  for (std::size_t i = 0; i < test_data.size(); ++i) {
    test_data[i] = static_cast<std::uint8_t>(i & 0xFF);
  }

  BenchResults results;
  auto start_time = std::chrono::steady_clock::now();
  auto end_time = start_time + std::chrono::seconds(config.duration_sec);

  std::cout << "Starting benchmark...\n";

  // RTT measurements.
  std::vector<double> rtt_samples;
  std::chrono::steady_clock::time_point last_send_time;

  while (g_running.load() && std::chrono::steady_clock::now() < end_time) {
    // Send data.
    last_send_time = std::chrono::steady_clock::now();
    auto packets = session->encrypt_data(test_data, 0, false);
    for (const auto& pkt : packets) {
      if (!socket.send(pkt, server, ec)) {
        if (config.verbose) {
          std::cerr << "Send failed: " << ec.message() << '\n';
        }
      } else {
        results.bytes_sent += pkt.size();
        ++results.packets_sent;
      }
    }

    // Receive ACKs and data.
    socket.poll(
        [&](const transport::UdpPacket& pkt) {
          auto frames = session->decrypt_packet(pkt.data);
          if (frames) {
            results.bytes_received += pkt.data.size();
            ++results.packets_received;

            // Measure RTT.
            auto rtt = std::chrono::steady_clock::now() - last_send_time;
            double rtt_ms = std::chrono::duration<double, std::milli>(rtt).count();
            rtt_samples.push_back(rtt_ms);

            // Process ACKs.
            for (const auto& frame : *frames) {
              if (frame.kind == mux::FrameKind::kAck) {
                session->process_ack(frame.ack);
              }
            }
          }
        },
        1, ec);

    // Handle retransmits.
    auto retransmits = session->get_retransmit_packets();
    for (const auto& pkt : retransmits) {
      socket.send(pkt, server, ec);
      ++results.retransmits;
    }

    // Rotate session if needed.
    if (session->should_rotate_session()) {
      session->rotate_session();
    }
  }

  auto actual_end = std::chrono::steady_clock::now();
  results.duration_sec =
      std::chrono::duration<double>(actual_end - start_time).count();

  // Get session stats.
  const auto& stats = session->stats();
  results.retransmits = stats.retransmits;

  // Calculate RTT statistics.
  if (!rtt_samples.empty()) {
    double sum = 0.0;
    for (double rtt : rtt_samples) {
      sum += rtt;
    }
    results.avg_rtt_ms = sum / static_cast<double>(rtt_samples.size());

    // P95 RTT.
    std::sort(rtt_samples.begin(), rtt_samples.end());
    std::size_t p95_idx = static_cast<std::size_t>(static_cast<double>(rtt_samples.size()) * 0.95);
    if (p95_idx >= rtt_samples.size()) p95_idx = rtt_samples.size() - 1;
    results.p95_rtt_ms = rtt_samples[p95_idx];
  }

  results.print();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    CLI::App app{"VEIL Transport Layer Benchmark Tool"};

    BenchConfig config;

    app.add_option("--mode,-m", config.mode, "Mode: server or client")
        ->check(CLI::IsMember({"server", "client"}));
    app.add_option("--host,-H", config.host, "Server host (client mode)");
    app.add_option("--port,-p", config.port, "Port number");
    app.add_option("--duration,-d", config.duration_sec, "Test duration in seconds (client mode)");
    app.add_option("--size,-s", config.message_size, "Message size in bytes");
    app.add_option("--streams,-n", config.num_streams, "Number of streams");
    app.add_flag("--verbose,-v", config.verbose, "Verbose output");

    CLI11_PARSE(app, argc, argv);

    // Setup signal handler.
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Initialize logging.
    logging::configure_logging(
        config.verbose ? logging::LogLevel::debug : logging::LogLevel::info, true);

    if (config.mode == "server") {
      return run_server(config);
    }
    return run_client(config);
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << '\n';
    return 1;
  }
}
