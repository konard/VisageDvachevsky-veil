VEIL Roadmap and Project Structure
==================================

Roadmap (no simplifications)
----------------------------
- Stage 0 (0.5-1 wk): Toolchain C++17/20, CMake, libsodium or boringssl, spdlog/fmt, googletest, clang-tidy, ASan/UBsan; CI; test container with nDPI/tcpdump/tshark.
- Stage 1 (1-1.5 wk): CryptoEngine (X25519, ChaCha20-Poly1305, HKDF, HMAC, IV derivation), PacketFormat/Builder (prefix/padding/frame types), session_id rotation, replay window; unit tests.
- Stage 2 (1-1.5 wk): Handshake + anti-probing (INIT/RESPONSE, timestamp window, silent drop, rate limiting, temp key); integration tests loopback + netem RTT 50 ms.
- Stage 3 (2-3 wk): UDP transport - multiplexing, selective ACK/bitmaps, retransmit timers, reorder/frag reassembly, buffer limits; integrations under loss/RTT, iperf3 >100 Mbps.
- Stage 4 (1.5-2 wk): Obfuscation - size variance (CV > 0.3), variable prefix/padding, heartbeat, jitter (Poisson/exp), seed-based profiles/rotation; pcap + entropy 0.85-0.95 + nDPI "Unknown/Generic UDP".
- Stage 5 (1 wk): TUN/NAT Linux - TUN bring-up, MTU/PMTU, iptables masquerade; end-to-end TCP (curl/ssh), reconnection.
- Stage 6 (1-1.5 wk): Reliability/protection - rate limiter, session cleanup, idle timeouts, optional migration; constrained logging/metrics.
- Stage 7 (1-2 wk, cyclical): DPI/ML loop - auto pcap -> nDPI, entropy, size variance, RF classifier; morphing tuning.
- Stage 8 (1-2 wk): Performance - perf/heaptrack, zero-copy/pools, lock-free queues, sendmmsg/recvmmsg, rmem/wmem tuning, SO_REUSEPORT; targets 500 Mbps, CPU < 30% @ 100 Mbps, 50 MB per 1000 sessions.
- Stage 9 (0.5-1 wk): Documentation, sample configs, test scripts, packages (deb/rpm/tar), final validation.

Project structure
-----------------
```
/CMakeLists.txt
/cmake/              # toolchains, options
/third_party/        # vendored deps (optional)
/docs/               # protocol, configs, test methods
/scripts/            # tun/nat bring-up, test runners (pcap/nDPI/ML)
/configs/
  veil-client.conf.example
  veil-server.conf.example
/src/
  common/
    crypto/          # X25519, ChaCha20-Poly1305, HKDF, HMAC wrappers
    packet/          # PacketFormat, PacketBuilder, frame structs
    utils/           # buffers, timers, byteorder, misc
    config/          # ini/CLI parser
    logging/         # spdlog wrappers
  transport/
    udp_socket/      # epoll, sendmmsg/recvmmsg
    mux/             # streams, seq/ack bitmaps, reorder/frag
    rate_limit/      # token bucket/leaky bucket
  obfuscation/
    morpher/         # size/timing/heartbeat profiles
  session/
    manager/         # session table, rotation, replay window
    handshake/       # INIT/RESPONSE, anti-probing logic
  client/
    main.cpp
    client_app.cpp   # TUN <-> transport
  server/
    main.cpp
    server_app.cpp   # transport <-> TUN, NAT hooks
/tests/
  unit/              # gtest: crypto, packet, morpher, mux
  integration/       # handshake, loss/RTT (netem), iperf3
  dpi/               # pcap + nDPI + ML scripts
```

Next steps
----------
- Fix dependency set: libsodium or boringssl; spdlog/fmt; googletest; CLI11 or inih.
- Create CMake/CI skeleton and add first unit tests for CryptoEngine/PacketBuilder.
