# VEIL Architecture Overview

## Table of Contents
- [Executive Summary](#executive-summary)
- [System Architecture](#system-architecture)
- [Layer Architecture (L0-L3)](#layer-architecture-l0-l3)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)

---

## Executive Summary

VEIL is a secure, obfuscated UDP-based VPN implemented in modern C++20 with a layered architecture designed for DPI (Deep Packet Inspection) evasion. The system implements a complete VPN solution with:

- **Strong Cryptography**: X25519 key exchange + ChaCha20-Poly1305 AEAD
- **Perfect Forward Secrecy**: Ephemeral keys for each handshake
- **DPI Evasion**: Traffic morphing, padding, timing jitter, IoT mimicry
- **Reliable Transport**: Selective ACK, retransmission, fragmentation/reassembly
- **Anti-Probing**: Silent drops, replay protection, rate limiting

---

## System Architecture

### High-Level Components

```
┌─────────────┐                                    ┌─────────────┐
│   Client    │                                    │   Server    │
│             │                                    │             │
│ ┌─────────┐ │                                    │ ┌─────────┐ │
│ │   App   │ │                                    │ │ Network │ │
│ └────┬────┘ │                                    │ └────▲────┘ │
│      │      │                                    │      │      │
│ ┌────▼────┐ │                                    │ ┌────┴────┐ │
│ │   TUN   │ │                                    │ │   TUN   │ │
│ └────┬────┘ │                                    │ └────▲────┘ │
│      │      │                                    │      │      │
│ ┌────▼──────────────────┐          ┌──────────────────┴────┐ │
│ │   TransportSession    │          │  TransportSession     │ │
│ │ ┌──────────────────┐  │          │ ┌──────────────────┐  │ │
│ │ │ L3: Traffic      │  │          │ │ L3: Traffic      │  │ │
│ │ │     Morphing     │  │          │ │     Morphing     │  │ │
│ │ └──────────────────┘  │          │ └──────────────────┘  │ │
│ │ ┌──────────────────┐  │          │ ┌──────────────────┐  │ │
│ │ │ L2: Transport    │  │          │ │ L2: Transport    │  │ │
│ │ │     Mux/ACK      │  │          │ │     Mux/ACK      │  │ │
│ │ └──────────────────┘  │          │ └──────────────────┘  │ │
│ │ ┌──────────────────┐  │          │ ┌──────────────────┐  │ │
│ │ │ L1: Crypto       │  │          │ │ L1: Crypto       │  │ │
│ │ │     Engine       │  │          │ │     Engine       │  │ │
│ │ └──────────────────┘  │          │ └──────────────────┘  │ │
│ └───────────┬───────────┘          │ └───────────▲─────────┘ │
│             │                       │             │           │
│ ┌───────────▼───────────┐          │ ┌───────────┴─────────┐ │
│ │ L0: UDP Socket        │          │ │ L0: UDP Socket      │ │
│ └───────────┬───────────┘          │ └───────────▲─────────┘ │
│             │                       │             │           │
└─────────────┼───────────────────────┼─────────────┼───────────┘
              │                       │             │
              └───────────────────────▼─────────────┘
                    Encrypted UDP Packets
```

### Entry Points

#### Server (`src/server/main.cpp`)
The server implements a multi-client UDP VPN server:

**Key Responsibilities:**
- Loads server configuration and PSK (pre-shared key)
- Opens TUN device for IP packet routing
- Configures NAT/IP forwarding via iptables
- Opens UDP socket on configured port (default: 4443)
- Creates session table for managing multiple clients
- Implements main event loop processing both TUN and UDP events
- Handles handshake for new clients (via HandshakeResponder)
- Routes packets between TUN device and appropriate client sessions

**Main Event Loop:**
```cpp
while (running) {
  // 1. Poll UDP socket for incoming packets
  udp_socket.poll([&](const UdpEndpoint& remote, span<uint8_t> data) {
    // Check if from existing session or new handshake
    if (is_handshake_init(data)) {
      handle_new_handshake(remote, data);
    } else {
      auto* session = session_table.find_by_endpoint(remote);
      if (session) {
        auto decrypted = session->transport.decrypt_packet(data);
        if (decrypted) {
          tun_device.write(*decrypted);  // Forward to TUN
        }
      }
    }
  });

  // 2. Read from TUN device
  auto packet = tun_device.read();
  if (packet) {
    auto dest_ip = extract_destination_ip(*packet);
    auto* session = session_table.find_by_tunnel_ip(dest_ip);
    if (session) {
      auto encrypted = session->transport.encrypt_data(*packet);
      udp_socket.send(encrypted, session->endpoint);
    }
  }

  // 3. Process retransmissions for all sessions
  session_table.process_retransmits();

  // 4. Periodic session cleanup (idle timeout)
  session_table.cleanup_expired();
}
```

#### Client (`src/client/main.cpp` + `src/tunnel/tunnel.h`)
The client implements a single-session VPN client:

**Key Responsibilities:**
- Loads client configuration and PSK
- Creates Tunnel object which encapsulates all functionality
- Initializes TUN device
- Sets up routing (default route, bypass routes)
- Performs handshake with server
- Runs the tunnel event loop (blocking)

**Tunnel Abstraction:**
The `Tunnel` class bridges:
- TUN device (local IP packets)
- UDP socket (encrypted transport to server)
- TransportSession (encryption/decryption)
- Event loop (I/O management)

---

## Layer Architecture (L0-L3)

### L0: UDP Socket Layer

**Location:** `src/transport/udp_socket/`

**Purpose:** Raw UDP packet transmission and reception

**Key Features:**
- Non-blocking I/O with epoll
- Batch send support (`send_batch`)
- Socket configuration (reuse_port, buffer sizes)
- IPv4/IPv6 support

**API:**
```cpp
class UdpSocket {
  bool open(uint16_t bind_port, bool reuse_port, error_code& ec);
  bool send(span<const uint8_t> data, const UdpEndpoint& remote, error_code& ec);
  bool poll(const ReceiveHandler& handler, int timeout_ms, error_code& ec);
  void close();
};
```

**Design Notes:**
- Single-threaded, event-driven
- No threading or locking required
- Uses Linux kernel's efficient `sendmmsg`/`recvmmsg` for batching

---

### L1: Crypto Layer (Encryption Engine)

**Location:** `src/common/crypto/`

**Purpose:** Cryptographic operations for secure communication

#### Cryptographic Primitives

**1. Key Exchange: X25519 (ECDH)**
- Elliptic Curve Diffie-Hellman on Curve25519
- 32-byte public keys, 32-byte private keys
- Provides Perfect Forward Secrecy

```cpp
auto keypair = crypto::generate_x25519_keypair();
auto shared_secret = crypto::compute_shared_secret(my_private, peer_public);
```

**2. Key Derivation: HKDF with HMAC-SHA256**
- Extract-then-Expand construction
- Domain separation via info strings
- Derives encryption keys and nonces

```cpp
auto session_keys = crypto::derive_session_keys(
  shared_secret,
  session_id,
  initiator_public,
  responder_public
);
// Returns: {send_key[32], recv_key[32], send_nonce[12], recv_nonce[12]}
```

**3. AEAD Encryption: ChaCha20-Poly1305**
- Authenticated encryption with associated data
- 256-bit keys, 96-bit nonces
- 128-bit authentication tags

```cpp
auto ciphertext = crypto::aead_encrypt(key, nonce, associated_data, plaintext);
auto plaintext = crypto::aead_decrypt(key, nonce, associated_data, ciphertext);
```

**4. Nonce Derivation**
```cpp
// Unique nonce per packet: base_nonce XOR sequence_counter
auto nonce = crypto::derive_nonce(base_nonce, sequence_number);
```

#### Secure Memory Management

All sensitive data (keys, shared secrets) stored in:
- `SecureArray<N>` - fixed-size sensitive data
- `SecureVector` - variable-size sensitive data
- Automatic clearing with `sodium_memzero()` on destruction

```cpp
SecureArray<32> private_key = generate_key();
// Automatically cleared when private_key goes out of scope
```

---

### L2: Transport Layer (Multiplexing & Reliability)

**Location:** `src/transport/session/`, `src/transport/mux/`

**Purpose:** Reliable, ordered data delivery over unreliable UDP

#### TransportSession

The core transport abstraction providing:

**1. Encryption/Decryption** - Wraps crypto layer
**2. Replay Protection** - Sliding window bitmap (1024 bits)
**3. Fragmentation** - Splits large payloads to fit MTU
**4. Reassembly** - Reconstructs fragmented messages
**5. Retransmission** - ARQ with exponential backoff
**6. Selective ACK** - Bitmap-based acknowledgment
**7. Session Rotation** - Periodic session ID rotation

**Wire Format (Encrypted Packet):**
```
┌──────────────────────────────────────────┐
│ Sequence Number (8 bytes, big-endian)   │
├──────────────────────────────────────────┤
│ ChaCha20-Poly1305 Ciphertext             │
│   ┌────────────────────────────────────┐ │
│   │ MuxFrame (plaintext, encrypted)    │ │
│   │   - Frame Type (1 byte)            │ │
│   │   - Frame-specific fields          │ │
│   │   - Payload                        │ │
│   └────────────────────────────────────┘ │
│ Poly1305 MAC Tag (16 bytes)             │
└──────────────────────────────────────────┘
```

#### Multiplexing System

**Frame Types:**

1. **Data Frame** (`kData`)
   ```
   [kind: 1] [stream_id: 8] [sequence: 8] [flags: 1] [len: 2] [payload]
   ```
   - Carries user data
   - FIN flag indicates end of stream

2. **ACK Frame** (`kAck`)
   ```
   [kind: 1] [stream_id: 8] [ack: 8] [bitmap: 4]
   ```
   - Acknowledges highest received sequence
   - Bitmap for selective ACK of previous packets

3. **Control Frame** (`kControl`)
   ```
   [kind: 1] [type: 1] [len: 2] [payload]
   ```
   - Session management, keep-alives, errors

4. **Heartbeat Frame** (`kHeartbeat`)
   ```
   [kind: 1] [timestamp: 8] [sequence: 8] [len: 2] [payload]
   ```
   - Keep-alive packets
   - IoT sensor data mimicry

#### Selective ACK System

**ACK Bitmap:**
- 32-bit bitmap for selective ACK
- Anchored at highest received sequence
- Bit N set = sequence (head - 1 - N) was received

**Example:**
```
Received: [100, 101, 103, 105, 106]
ACK: {head=106, bitmap=0b10110}
  Bit 0: seq 105 ✓
  Bit 1: seq 104 ✗
  Bit 2: seq 103 ✓
  Bit 3: seq 102 ✗
  Bit 4: seq 101 ✓
  Bit 5: seq 100 ✓
```

#### Retransmission System

**RTT Estimation (RFC 6298):**
```
SRTT = Smoothed RTT (exponential moving average)
RTTVAR = RTT variance

On first sample:
  SRTT = RTT
  RTTVAR = RTT / 2
  RTO = SRTT + max(clock_granularity, 4 × RTTVAR)

On subsequent samples:
  RTTVAR = (1 - β) × RTTVAR + β × |SRTT - RTT|  (β=0.25)
  SRTT = (1 - α) × SRTT + α × RTT               (α=0.125)
  RTO = SRTT + 4 × RTTVAR

Bounds: min_rto (50ms) ≤ RTO ≤ max_rto (10s)
```

**Exponential Backoff:**
```
retry_timeout[n] = RTO × (backoff_factor)^n
Default: backoff_factor = 2.0, max_retries = 5
```

#### Fragment Reassembly

**Fragmentation Trigger:**
- Payload exceeds MTU (default: 1280 bytes)
- Splits into multiple Data frames

**Reassembly Algorithm:**
1. Sender assigns unique `message_id`
2. Each fragment tagged with: `{message_id, offset, last_flag}`
3. Receiver collects fragments by `message_id`
4. When `last_flag` seen, attempts reassembly
5. Verifies no gaps in offsets
6. Concatenates fragments in order
7. Timeout for incomplete messages (5s)

---

### L3: Traffic Morphing / DPI Evasion (Obfuscation Layer)

**Location:** `src/common/obfuscation/`

**Purpose:** Evade Deep Packet Inspection by making traffic appear innocuous

#### Obfuscation Techniques

**1. Deterministic Padding**
- Seed-based HMAC derivation
- Size classes: Small (0-100), Medium (100-400), Large (400-1000)
- Jitter range to avoid fixed sizes
- Padding appears random but is deterministic per sequence

```cpp
uint16_t compute_padding_size(const ObfuscationProfile& profile, uint64_t sequence) {
  // HMAC(profile_seed, sequence) → deterministic pseudo-random padding
  auto hmac = hmac_sha256(profile.profile_seed, encode(sequence));
  uint16_t base = decode_u16(hmac);
  uint16_t padding = min_size + (base % (max_size - min_size));
  int jitter = (hmac[2] % (2 * jitter_range)) - jitter_range;
  return clamp(padding + jitter, min_size, max_size);
}
```

**2. Variable Prefix**
- Random-looking prefix (4-12 bytes)
- Derived from profile seed + sequence
- Breaks fixed header patterns

**3. Timing Jitter**
- Poisson/Exponential distribution models
- Configurable max jitter (default 50ms)
- Breaks constant packet interval patterns

**Jitter Models:**
- **Uniform:** `jitter = random(0, max_jitter)`
- **Poisson:** `jitter = -log(1 - uniform_random()) / λ`
- **Exponential:** `jitter = -log(uniform_random()) × μ`

**4. Heartbeat/Keep-alive**
- **IoT Sensor Mode:** Simulates temperature/humidity/battery telemetry
- **Generic Telemetry Mode:** Random metrics
- Configurable intervals (5-15 sec)
- Maintains traffic flow during idle periods

**IoT Sensor Payload Example:**
```cpp
struct IoTSensorPayload {
  float temperature;      // 20.5°C - 25.3°C
  float humidity;         // 45% - 65%
  float battery_voltage;  // 3.2V - 4.2V
  uint8_t device_id;      // 0x42
  uint64_t timestamp_ms;
};
```

**5. Entropy Normalization**
- Fills gaps with pseudo-random data
- Maintains consistent entropy across packets
- Uses ChaCha20 stream cipher as PRNG

---

## Core Components

### 1. HandshakeProcessor

**Location:** `src/common/handshake/handshake_processor.h`

**Purpose:** Establish secure session via 2-way handshake

#### Handshake Protocol

```
Client (Initiator)                    Server (Responder)
──────────────────                    ──────────────────

Generate ephemeral keypair
Create INIT message:
  Magic: "HS"
  Version: 1
  Type: INIT
  Timestamp: 8 bytes
  Ephemeral Public Key: 32 bytes
  HMAC-SHA256(PSK, payload): 32 bytes
                    ─────────────────▶
                                       Rate limit check
                                       Timestamp validation (±30s)
                                       Replay cache check
                                       HMAC verification
                                       Generate ephemeral keypair
                                       Compute shared secret
                                       Derive session keys
                                       Generate session ID

                                       Create RESPONSE:
                                         Magic: "HS"
                                         Version: 1
                                         Type: RESPONSE
                                         Init Timestamp: 8 bytes
                                         Response Timestamp: 8 bytes
                                         Session ID: 8 bytes
                                         Responder Ephemeral: 32 bytes
                                         HMAC-SHA256(PSK, payload): 32 bytes
                    ◀─────────────────
Verify HMAC
Verify timestamps match
Compute shared secret
Derive session keys

SESSION ESTABLISHED ✓
```

#### Key Derivation Flow

```
1. Both sides compute:
   shared_secret = X25519(my_private_key, peer_public_key)

2. HKDF-Extract:
   salt = session_id (8 bytes)
   ikm = shared_secret (32 bytes)
   prk = HMAC-SHA256(salt, ikm)

3. HKDF-Expand:
   info = "VEILHS1\0" || initiator_ephemeral || responder_ephemeral
   okm = HKDF-Expand(prk, info, 88 bytes)

4. Split okm:
   send_key[0..31]      (32 bytes)
   recv_key[32..63]     (32 bytes)
   send_nonce[64..75]   (12 bytes)
   recv_nonce[76..87]   (12 bytes)

5. Keys swapped based on role (initiator vs responder)
```

**Anti-Probing Features:**
- Replay cache checks BEFORE HMAC validation (prevents timing attacks)
- Silent drop on invalid/duplicate packets
- Rate limiting via token bucket
- Timestamp window validation (±30s default)

---

### 2. HandshakeReplayCache

**Location:** `src/common/handshake/handshake_replay_cache.h`

**Purpose:** Prevent replay attacks during handshake

**Implementation:**
- LRU cache with O(1) operations
- Key: `(timestamp_ms, ephemeral_public_key)`
- Thread-safe with mutex
- Configurable capacity (default: 4096 entries)
- Time window for automatic cleanup (default: 60s)

**Algorithm:**
```cpp
bool mark_and_check(uint64_t timestamp_ms, const array<uint8_t, 32>& pubkey) {
  lock_guard lock(mutex_);

  cleanup_expired(timestamp_ms);  // Remove old entries

  CacheKey key{timestamp_ms, pubkey};

  if (cache_map_.contains(key)) {
    touch(key);  // Move to end of LRU
    return true;  // REPLAY DETECTED
  }

  if (cache_map_.size() >= capacity_) {
    evict_lru();  // Remove oldest entry
  }

  lru_list_.push_back(key);
  cache_map_[key] = --lru_list_.end();

  return false;  // New handshake
}
```

---

### 3. SessionManager (Server)

**Location:** `src/server/session_table.h`

**Purpose:** Manage multiple client sessions

**Responsibilities:**
- Client session tracking
- IP address pool management (10.8.0.2 - 10.8.0.254)
- Session timeout management
- Endpoint mapping (UDP endpoint → session)
- Tunnel IP mapping (tunnel IP → session)

**Key Operations:**
```cpp
class SessionTable {
  optional<uint64_t> create_session(UdpEndpoint, unique_ptr<TransportSession>);
  ClientSession* find_by_endpoint(const UdpEndpoint&);
  ClientSession* find_by_tunnel_ip(const string& ip);
  void update_activity(uint64_t session_id);
  size_t cleanup_expired(duration idle_timeout);
};
```

**Session Structure:**
```cpp
struct ClientSession {
  uint64_t session_id;
  UdpEndpoint remote_endpoint;
  unique_ptr<TransportSession> transport;
  string tunnel_ip;           // Assigned IP (e.g., "10.8.0.5")
  time_point last_activity;
  time_point created_at;
};
```

---

### 4. CryptoEngine

**Location:** `src/common/crypto/crypto_engine.h`

**Design:**
- Stateless pure functions (thread-safe)
- Uses libsodium for all cryptographic operations
- HKDF-based key derivation with domain separation
- Nonce derivation: XOR base nonce with sequence counter

**Key Functions:**

```cpp
namespace crypto {
  // Key exchange
  X25519KeyPair generate_x25519_keypair();
  SecureArray<32> compute_shared_secret(const SecureArray<32>& my_private,
                                        const array<uint8_t, 32>& peer_public);

  // Key derivation
  SessionKeys derive_session_keys(span<const uint8_t> shared_secret,
                                  uint64_t session_id,
                                  span<const uint8_t> initiator_public,
                                  span<const uint8_t> responder_public);

  // AEAD encryption
  vector<uint8_t> aead_encrypt(span<const uint8_t> key,
                               span<const uint8_t> nonce,
                               span<const uint8_t> ad,
                               span<const uint8_t> plaintext);

  optional<vector<uint8_t>> aead_decrypt(span<const uint8_t> key,
                                          span<const uint8_t> nonce,
                                          span<const uint8_t> ad,
                                          span<const uint8_t> ciphertext);

  // Nonce derivation
  array<uint8_t, 12> derive_nonce(span<const uint8_t> base_nonce,
                                  uint64_t sequence);

  // HMAC
  array<uint8_t, 32> hmac_sha256(span<const uint8_t> key,
                                 span<const uint8_t> data);
}
```

---

### 5. Session Rotation

**Location:** `src/common/session/session_rotator.h`

**Purpose:** Prevent long-lived session tracking by DPI/middleboxes

**Triggers:**
1. **Time-based:** Every 30 seconds (default)
2. **Packet-based:** Every 1,000,000 packets (default)

**Implementation:**
```cpp
class SessionRotator {
  bool should_rotate(uint64_t sent_packets, time_point now) const {
    auto elapsed = now - last_rotation_;
    return (elapsed >= interval_) || (sent_packets >= max_packets_);
  }

  uint64_t rotate(time_point now) {
    last_rotation_ = now;
    session_id_ = generate_random_u64();  // New session ID
    return session_id_;
  }
};
```

**Important Notes:**
- Session rotation **does NOT** rotate cryptographic keys
- Keys remain the same throughout connection lifetime
- Only the protocol-level `session_id` changes
- Sequence numbers continue monotonically (no reset)
- Nonce uniqueness guaranteed by 64-bit sequence space

**Nonce Safety:**
```
Nonce = base_nonce XOR sequence_counter

With 64-bit sequence counter:
- Never resets during session lifetime
- 2^64 packets ≈ 10^19 packets
- At 1 Gbps: would take ~500 years to exhaust
- Practical limit: connection will terminate long before
```

---

### 6. Replay Protection

**Location:** `src/common/session/replay_window.h`

**Purpose:** Detect duplicate/replayed packets during transport

**Implementation:**
- Sliding bitmap window (1024 bits default)
- Allows out-of-order delivery within window
- Rejects packets outside window or duplicates

**Algorithm:**
```cpp
bool ReplayWindow::mark_and_check(uint64_t sequence) {
  if (sequence > highest_seen_) {
    // Advance window forward
    uint64_t advance = sequence - highest_seen_;
    if (advance < window_size_) {
      bitmap_ <<= advance;  // Shift bitmap left
    } else {
      bitmap_ = 0;  // Clear entire window (big jump)
    }
    bitmap_ |= 1;  // Set bit for new highest sequence
    highest_seen_ = sequence;
    return true;  // Accept
  }

  uint64_t offset = highest_seen_ - sequence;
  if (offset >= window_size_) {
    return false;  // Too old, reject
  }

  uint64_t bit_mask = 1ULL << offset;
  if (bitmap_ & bit_mask) {
    return false;  // Duplicate, reject
  }

  bitmap_ |= bit_mask;  // Mark as seen
  return true;  // Accept
}
```

---

### 7. Fragment Reassembly

**Location:** `src/transport/mux/fragment_reassembly.h`

**Purpose:** Reconstruct messages split across multiple packets

**Design:**
- Maps `message_id` → list of fragments
- Tracks: offset, data, last_flag
- Timeout for incomplete messages (5s)
- Memory limit enforcement (1MB default)

**Reassembly Flow:**

**Sender:**
```cpp
vector<MuxFrame> fragment_data(span<const uint8_t> data, uint64_t stream_id, bool fin) {
  vector<MuxFrame> frames;
  uint64_t message_id = message_id_counter_++;
  uint16_t offset = 0;

  while (offset < data.size()) {
    size_t chunk_size = min(max_fragment_size, data.size() - offset);
    bool is_last = (offset + chunk_size >= data.size());

    MuxFrame frame = make_data_frame(
      stream_id, send_sequence_++, is_last && fin,
      vector(data.begin() + offset, data.begin() + offset + chunk_size)
    );

    frame.metadata.message_id = message_id;
    frame.metadata.offset = offset;
    frame.metadata.last = is_last;

    frames.push_back(frame);
    offset += chunk_size;
  }

  return frames;
}
```

**Receiver:**
```cpp
optional<vector<uint8_t>> try_reassemble(uint64_t message_id) {
  auto& state = state_[message_id];

  if (!state.has_last) return nullopt;  // Waiting for final fragment

  // Verify no gaps
  uint16_t expected_offset = 0;
  for (const auto& frag : state.fragments) {
    if (frag.offset != expected_offset) return nullopt;  // Gap detected
    expected_offset += frag.data.size();
  }

  // Concatenate all fragments
  vector<uint8_t> result;
  result.reserve(state.total_bytes);
  for (const auto& frag : state.fragments) {
    result.insert(result.end(), frag.data.begin(), frag.data.end());
  }

  state_.erase(message_id);
  return result;
}
```

---

### 8. Retransmit Buffer

**Location:** `src/transport/mux/retransmit_buffer.h`

**Purpose:** Reliable delivery via automatic retransmission

**Features:**
- RTT estimation (EWMA)
- RTO calculation (RFC 6298)
- Exponential backoff
- Configurable max retries (default: 5)
- Drop policies: Oldest, Newest, Low-Priority
- High/Low water marks for adaptive cleanup

**Retransmission Flow:**

```cpp
// On send:
void on_send(uint64_t sequence, vector<uint8_t> packet) {
  auto now = clock::now();
  pending_[sequence] = PendingPacket{
    .sequence = sequence,
    .data = move(packet),
    .first_sent = now,
    .next_retry = now + rto_,
    .retry_count = 0
  };
}

// Periodic check:
vector<PendingPacket*> get_packets_to_retransmit() {
  auto now = clock::now();
  vector<PendingPacket*> to_retransmit;

  for (auto& [seq, pkt] : pending_) {
    if (now >= pkt.next_retry) {
      if (pkt.retry_count >= max_retries_) {
        pending_.erase(seq);  // Give up
        continue;
      }

      pkt.retry_count++;
      pkt.next_retry = now + rto_ * pow(backoff_factor_, pkt.retry_count);
      to_retransmit.push_back(&pkt);
    }
  }

  return to_retransmit;
}

// On ACK:
void on_ack(uint64_t sequence) {
  auto it = pending_.find(sequence);
  if (it != pending_.end()) {
    auto rtt = clock::now() - it->second.first_sent;
    update_rtt(rtt);  // EWMA RTT estimation
    pending_.erase(it);
  }
}
```

---

## Data Flow

### Client → Server (Outbound)

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Application writes IP packet to TUN device              │
│    └─ read() from TUN fd                                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Tunnel::on_tun_packet(packet)                            │
│    └─ Identifies as outbound traffic                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. TransportSession::encrypt_data(packet)                   │
│    ├─ Fragment if needed (MTU exceeded)                     │
│    ├─ For each fragment:                                    │
│    │  ├─ Create MuxFrame (kData, stream_id, seq, payload)   │
│    │  ├─ MuxCodec::encode(frame) → plaintext                │
│    │  ├─ derive_nonce(base_nonce, send_sequence)            │
│    │  ├─ aead_encrypt(send_key, nonce, plaintext)           │
│    │  ├─ Prepend sequence number (8 bytes)                  │
│    │  ├─ Add to retransmit buffer                           │
│    │  └─ Apply obfuscation (padding, jitter)                │
│    └─ Returns vector<encrypted_packets>                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. UdpSocket::send(encrypted_packet, server_endpoint)       │
│    └─ sendto() on UDP socket                                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                   ════════════════════
                    Network Transit
                   ════════════════════
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Server: UdpSocket::poll() receives packet                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. server/main: Check existing sessions                     │
│    ├─ If new: HandshakeResponder::handle_init()             │
│    └─ If existing: Session found                            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. TransportSession::decrypt_packet(ciphertext)             │
│    ├─ Extract sequence number (first 8 bytes)               │
│    ├─ Replay check: replay_window_.mark_and_check(seq)      │
│    ├─ derive_nonce(recv_nonce, sequence)                    │
│    ├─ aead_decrypt(recv_key, nonce, ciphertext[8:])         │
│    ├─ MuxCodec::decode(plaintext) → MuxFrame                │
│    ├─ If kData: Update ACK bitmap, reassemble fragments     │
│    └─ If kAck: Process acknowledgments                      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. Extract destination IP from packet header                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. TunDevice::write(packet)                                 │
│    └─ write() to TUN fd                                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ 10. Kernel routes packet to destination                     │
└─────────────────────────────────────────────────────────────┘
```

### Server → Client (Inbound)

```
Similar flow in reverse direction:
Server TUN → Encrypt → UDP → Network → Client UDP → Decrypt → Client TUN → App
```

---

## Security Architecture

### Cryptographic Guarantees

**1. Perfect Forward Secrecy**
- Ephemeral X25519 keys per handshake
- Shared secret never stored long-term
- Old session keys cleared on rotation
- Compromise of long-term PSK does NOT compromise past sessions

**2. Replay Protection**
- **Handshake:** Replay cache with timestamp window (±30s)
- **Transport:** Sliding window bitmap (1024 bits)
- Prevents duplicate packet acceptance

**3. Authentication**
- PSK-based HMAC for handshake messages
- AEAD (ChaCha20-Poly1305) for all data packets
- Prevents man-in-the-middle attacks

**4. Memory Safety**
- All sensitive data in `SecureArray`/`SecureVector`
- Automatic clearing with `sodium_memzero()`
- Destructor guarantees for key material
- Prevents key leakage via memory dumps

**5. Nonce Uniqueness**
- Base nonce from HKDF (never repeated across sessions)
- Sequence counter XOR (monotonic, never resets)
- 64-bit counter space (practically unlimited: 2^64 packets)
- Prevents nonce reuse attacks

---

### Anti-Probing Features

**1. Silent Drop**
- Invalid handshakes → no response
- Replay attacks → no response
- HMAC failures → no response
- Prevents active probing attacks

**2. Rate Limiting**
- Token bucket per endpoint
- Prevents handshake flooding
- Configurable: rate, burst capacity

**3. Replay Cache Priority**
- Checks BEFORE HMAC validation
- Prevents timing attacks
- O(1) lookup performance

**4. Timestamp Validation**
- Window: ±30 seconds (configurable)
- Prevents replay of old handshakes
- Mitigates time-based attacks

---

### Potential Risks & Mitigations

**1. Session Tracking**
- **Risk:** Long-lived session IDs visible to DPI
- **Mitigation:** Session ID rotation every 30s/1M packets

**2. Traffic Analysis**
- **Risk:** Packet size/timing patterns reveal VPN usage
- **Mitigation:** Obfuscation profile (padding, jitter, heartbeats)

**3. Key Exhaustion**
- **Risk:** Nonce reuse after 2^64 packets
- **Mitigation:** Practically impossible (centuries at 1 Gbps)

**4. Resource Exhaustion (DoS)**
- **Risk:** Handshake flood attacks
- **Mitigation:** Rate limiting, replay cache with LRU eviction

**5. Memory Exhaustion**
- **Risk:** Fragment reassembly buffer overflow
- **Mitigation:** Memory limits (1MB default), timeouts (5s)

---

## File Locations Reference

### Core Entry Points
- **Server:** `src/server/main.cpp`
- **Client:** `src/client/main.cpp`
- **Tunnel:** `src/tunnel/tunnel.{h,cpp}`

### Crypto Layer
- **Engine:** `src/common/crypto/crypto_engine.{h,cpp}`
- **Secure Memory:** `src/common/crypto/secure_buffer.h`
- **Random:** `src/common/crypto/random.{h,cpp}`

### Handshake
- **Processor:** `src/common/handshake/handshake_processor.{h,cpp}`
- **Replay Cache:** `src/common/handshake/handshake_replay_cache.{h,cpp}`

### Transport Session
- **Session:** `src/transport/session/transport_session.{h,cpp}`
- **Replay Window:** `src/common/session/replay_window.{h,cpp}`
- **Session Rotator:** `src/common/session/session_rotator.{h,cpp}`
- **Lifecycle:** `src/common/session/session_lifecycle.{h,cpp}`

### Multiplexing
- **Codec:** `src/transport/mux/mux_codec.{h,cpp}`
- **Frames:** `src/transport/mux/frame.h`
- **ACK Bitmap:** `src/transport/mux/ack_bitmap.{h,cpp}`
- **ACK Scheduler:** `src/transport/mux/ack_scheduler.{h,cpp}`
- **Fragment Reassembly:** `src/transport/mux/fragment_reassembly.{h,cpp}`
- **Retransmit Buffer:** `src/transport/mux/retransmit_buffer.{h,cpp}`

### Obfuscation
- **Profile:** `src/common/obfuscation/obfuscation_profile.{h,cpp}`

### Session Management
- **Session Table:** `src/server/session_table.{h,cpp}`
- **Idle Timeout:** `src/common/session/idle_timeout.{h,cpp}`

### Network Layer
- **UDP Socket:** `src/transport/udp_socket/udp_socket.{h,cpp}`
- **Event Loop:** `src/transport/event_loop/event_loop.{h,cpp}`
- **TUN Device:** `src/tun/tun_device.{h,cpp}`

### Utilities
- **Timer Heap:** `src/common/utils/timer_heap.{h,cpp}`
- **Rate Limiter:** `src/common/utils/rate_limiter.{h,cpp}`
- **Advanced Rate Limiter:** `src/common/utils/advanced_rate_limiter.{h,cpp}`
- **Metrics:** `src/common/metrics/metrics.{h,cpp}`

---

## Diagram Summary

### Layer Stack
```
┌─────────────────────────────────────────┐
│  Application (User Traffic)             │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  TUN Device (Virtual Network Interface) │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  L3: Traffic Morphing / DPI Evasion     │
│  - Padding, Jitter, Heartbeats          │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  L2: Transport Layer (Reliable UDP)     │
│  - Fragmentation, Reassembly, ACK, RTX  │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  L1: Crypto Layer                       │
│  - X25519, ChaCha20-Poly1305, HKDF      │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  L0: UDP Socket Layer                   │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│  Network (Internet)                     │
└─────────────────────────────────────────┘
```

### Handshake Sequence
```
Client                     Server
  │                          │
  ├─── INIT ────────────────▶│
  │   (ephemeral_pub, mac)   │
  │                          │
  │                        [Verify]
  │                        [Generate keys]
  │                          │
  │◀─── RESPONSE ────────────┤
  │   (session_id,           │
  │    ephemeral_pub, mac)   │
  │                          │
[Verify]                     │
[Generate keys]              │
  │                          │
[ESTABLISHED]            [ESTABLISHED]
```

### Session ID Rotation
```
Time ────────────────────────────────────────────▶

Session 1         Session 2         Session 3
[ID: 0x1234]      [ID: 0x5678]      [ID: 0x9ABC]
├─────────────────┼─────────────────┼─────────────
│ Same Keys       │ Same Keys       │ Same Keys
│ Seq: 0-999999   │ Seq: 1000000+   │ Seq: 2000000+
└─────────────────┴─────────────────┴─────────────

Note: Only session_id changes, not cryptographic keys
```

---

**End of Architecture Overview**
