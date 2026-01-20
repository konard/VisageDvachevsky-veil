# VEIL Principles of Operation

## Table of Contents
- [Introduction](#introduction)
- [Security Principles](#security-principles)
- [Transport Principles](#transport-principles)
- [Obfuscation Principles](#obfuscation-principles)

---

## Introduction

This document explains the fundamental principles behind VEIL's design decisions and how the system achieves its security, reliability, and stealth objectives. It complements the [Architecture Overview](architecture_overview.md) by focusing on the "why" rather than the "what".

---

## Security Principles

### 1. Perfect Forward Secrecy

**What it is:**
Perfect Forward Secrecy (PFS) ensures that compromise of long-term secrets (like the PSK) does NOT compromise past or future session keys.

**How VEIL achieves it:**

1. **Ephemeral Key Exchange:**
   - Each handshake generates fresh X25519 keypairs (client and server)
   - These keys exist only in memory, never written to disk
   - Keys are cleared immediately after deriving session keys

2. **Session Key Derivation:**
   ```
   Shared Secret = X25519(client_ephemeral_private, server_ephemeral_public)
   Session Keys = HKDF(shared_secret, session_id, ...)
   ```
   - Even if PSK is compromised, attacker cannot derive session keys without ephemeral private keys
   - Ephemeral private keys are never transmitted and cleared from memory

3. **Key Lifetime:**
   - Ephemeral keys: One handshake only
   - Session keys: One connection only (until client reconnects)
   - PSK: Long-term, but only used for HMAC authentication, NOT encryption

**Why X25519:**
- Fast: ~50μs per operation on modern CPUs
- Secure: 128-bit security level (equivalent to 3072-bit RSA)
- Side-channel resistant: Constant-time implementation
- Widely audited: Part of libsodium, used in Signal, WireGuard, etc.

---

### 2. Replay Protection

**Why replay attacks matter:**

An attacker could:
1. Record legitimate packets
2. Replay them later to:
   - Trigger handshakes (resource exhaustion)
   - Inject duplicate data packets
   - Probe server behavior

**VEIL's two-layer defense:**

#### Layer 1: Handshake Replay Protection

**Location:** `HandshakeReplayCache`

**Mechanism:**
- Cache key: `(timestamp_ms, ephemeral_public_key)`
- Every INIT message checked against cache BEFORE HMAC validation
- If seen before → silent drop (no response)

**Why check BEFORE HMAC:**
```
If we checked AFTER HMAC:
  Attacker sends invalid handshake
    → Server computes HMAC (expensive)
    → Server sends error response
    → Attacker learns server is alive (probing attack!)

If we check BEFORE HMAC:
  Attacker sends duplicate handshake
    → Cache hit (cheap, O(1))
    → Silent drop
    → Attacker learns nothing
```

**Cache properties:**
- LRU eviction (oldest entries removed when full)
- Capacity: 4096 entries (configurable)
- Time window: 60s (entries older than this automatically purged)

**Additional handshake protection:**
- Timestamp window: ±30s (rejects INIT messages with timestamps outside window)
- Combined with replay cache, prevents replay of old handshakes

#### Layer 2: Transport Replay Protection

**Location:** `ReplayWindow`

**Mechanism:**
- Sliding bitmap window (1024 bits default)
- Tracks last 1024 seen sequence numbers
- Packet rejected if:
  - Sequence already seen (duplicate)
  - Sequence too old (outside window)

**Example:**
```
Window size: 8 bits (for illustration)
Highest seen: 106

Bitmap: [106][105][104][103][102][101][100][99]
         ✓    ✓    ✗    ✓    ✗    ✓    ✓    ✓

Packet seq=103 arrives:
  → offset = 106 - 103 = 3
  → Check bit 3: already set
  → REJECT (replay)

Packet seq=104 arrives:
  → offset = 106 - 103 = 2
  → Check bit 2: not set
  → Accept, set bit 2
```

**Why 1024 bits:**
- Allows up to 1024 packets to arrive out-of-order
- Typical network reordering: <100 packets
- 1024 = 128 bytes (minimal memory overhead)

---

### 3. Anti-Probing (Server Silence)

**The probing threat:**

DPI systems actively probe suspected VPN servers:
```
Attacker sends: Invalid handshake
If server responds with error → "VPN server confirmed!"
If server silent → "Maybe not a VPN, unclear"
```

**VEIL's anti-probing rules:**

**Rule 1: Silent drop on ANY invalid input**
```cpp
if (!verify_magic(packet)) {
  // NO ERROR RESPONSE
  return;  // Silent drop
}

if (!verify_hmac(packet, psk)) {
  // NO ERROR RESPONSE
  return;  // Silent drop
}

if (replay_cache.check(packet)) {
  // NO ERROR RESPONSE
  return;  // Silent drop
}

if (!rate_limit.allow(endpoint)) {
  // NO ERROR RESPONSE
  return;  // Silent drop
}
```

**Rule 2: Rate limiting prevents fingerprinting**
- Token bucket per endpoint
- Default: 10 handshakes/minute/endpoint
- Prevents timing-based probing

**Rule 3: No version negotiation**
- Single protocol version (no fallback)
- Invalid version → silent drop
- Prevents version enumeration attacks

**Trade-off:**
- Legitimate clients with wrong PSK get no feedback
- Solution: Clear error messages in client logs (local only)

---

### 4. Authenticated Encryption (AEAD)

**Why ChaCha20-Poly1305:**

**1. Performance:**
- ~3x faster than AES-GCM on CPUs without AES-NI
- Important for ARM devices (routers, mobile)
- ~1 GB/s on typical ARM Cortex-A53

**2. Security:**
- AEAD: Encryption + Authentication in one step
- 256-bit key, 96-bit nonce, 128-bit tag
- No known practical attacks

**3. Simplicity:**
- Single cipher for confidentiality + integrity
- Harder to misuse than separate encrypt-then-MAC

**4. Proven:**
- Used in TLS 1.3, WireGuard, Signal
- Extensively audited

**How AEAD prevents attacks:**

**Tampering:**
```
Attacker modifies ciphertext:
  → Poly1305 MAC verification fails
  → Packet rejected
  → No partial decryption (all-or-nothing)
```

**Forgery:**
```
Attacker crafts fake packet:
  → Without key, cannot generate valid Poly1305 tag
  → Packet rejected
```

---

### 5. Nonce Management

**The nonce uniqueness requirement:**
- ChaCha20-Poly1305 requires **(key, nonce)** pairs to be unique
- Reusing a nonce with the same key → **catastrophic failure**:
  - Keystream reuse allows plaintext recovery
  - Poly1305 key reuse allows forgery

**VEIL's nonce derivation:**

```
Base Nonce (12 bytes):
  - Derived from HKDF during handshake
  - Never repeated across sessions (depends on ephemeral keys)

Packet Nonce (12 bytes):
  - nonce[0..3] = base_nonce[0..3]   (session-specific prefix)
  - nonce[4..11] = base_nonce[4..11] XOR sequence_counter

Sequence Counter:
  - 64-bit monotonic counter
  - Starts at 0, increments with each packet
  - NEVER resets during session lifetime
```

**Why this is safe:**

**Uniqueness within session:**
- Different sequence → different nonce (XOR ensures this)
- Sequence never resets → no nonce reuse

**Uniqueness across sessions:**
- Different ephemeral keys → different base nonce
- Even if two sessions have same sequence, nonces differ

**Nonce space exhaustion:**
```
With 64-bit counter:
  Max packets = 2^64 ≈ 1.8 × 10^19

At 1 Gbps (VPN saturated):
  Packets/sec ≈ 83,000 (assuming 1500-byte packets)
  Time to exhaust = 2^64 / 83000 / (60*60*24*365)
                  ≈ 7 million years

Practical limit:
  Connection will terminate long before (idle timeout, network change, etc.)
```

---

### 6. Session ID Rotation

**The tracking problem:**

DPI systems can track VPN sessions by watching for:
- Long-lived flow identifiers (session IDs)
- Consistent packet patterns between same endpoints

**VEIL's solution: Deterministic Session Rotation**

**Triggers:**
1. **Time-based:** Every 30 seconds (default)
2. **Packet-based:** Every 1,000,000 packets (default)

**What rotates:**
- Session ID (8-byte identifier visible in protocol)

**What does NOT rotate:**
- Cryptographic keys (send_key, recv_key, nonces)
- Sequence counter (continues monotonically)
- Connection state (no re-handshake required)

**Algorithm:**
```cpp
bool should_rotate() {
  auto elapsed = now() - last_rotation_time_;
  return (elapsed >= 30s) || (packets_sent_ >= 1000000);
}

void rotate() {
  old_session_id_ = session_id_;
  session_id_ = generate_random_u64();
  last_rotation_time_ = now();
  // Keys remain unchanged!
}
```

**Why keys don't rotate:**
- Key rotation would require rekeying protocol (expensive)
- Current nonce scheme allows 2^64 packets (no reuse risk)
- Session ID rotation sufficient for DPI evasion

**DPI evasion impact:**
```
Without rotation:
  DPI sees: [Session 0x1234] [Session 0x1234] [Session 0x1234] ...
  → "Long-lived VPN session detected!"

With rotation:
  DPI sees: [Session 0x1234] [Session 0x5678] [Session 0x9ABC] ...
  → "Many short sessions, maybe p2p traffic?"
```

---

## Transport Principles

### 1. Why Not Just TCP?

**TCP over UDP vs Native UDP:**

**Problems with TCP-over-TCP (VPN tunneling TCP):**
```
Application sends TCP packet
  → Tunneled over VPN's TCP connection
  → If VPN packet lost:
    ✗ Application TCP retransmits
    ✗ VPN TCP retransmits
    → Double retransmission (inefficient)
    → Congestion control confusion
    → Poor performance under packet loss
```

**Why VEIL uses UDP + custom reliability:**
- No double retransmission
- Single congestion control layer (application's)
- Selective ACK (better than TCP's cumulative ACK)
- Application determines reliability (VPN just delivers)

---

### 2. Selective Retransmission

**TCP's limitation:**

TCP uses cumulative ACK:
```
Sent: [1] [2] [3] [4] [5]
Received: [1] [2] [4] [5]  (packet 3 lost)

TCP ACK: "ACK 2" (can only acknowledge up to first gap)
  → Must retransmit [3], even though [4][5] received
```

**VEIL's selective ACK:**

```
Sent: [1] [2] [3] [4] [5]
Received: [1] [2] [4] [5]

VEIL ACK: {highest=5, bitmap=0b1011}
  Bit 0: seq 5 ✓
  Bit 1: seq 4 ✓
  Bit 2: seq 3 ✗  ← Only this needs retransmission
  Bit 3: seq 2 ✓
  Bit 4: seq 1 ✓

  → Only retransmit [3]
```

**Benefits:**
- Fewer retransmissions
- Better bandwidth utilization
- Faster recovery from loss

---

### 3. Out-of-Order Reassembly

**Why packets arrive out of order:**
- Network path changes (route flapping)
- Load balancing across multiple paths
- Packet prioritization in routers

**VEIL's approach:**

**Sequence-based ordering:**
- Every packet has monotonic sequence number
- Receiver maintains reorder buffer
- Delivers packets to application in order

**Example:**
```
Receive order: [5] [3] [6] [4] [7] [2]
Reorder buffer: [2] [3] [4] [5] [6] [7]
Deliver to app: [2] [3] [4] [5] [6] [7]
```

**Memory management:**
- Reorder buffer size limit (prevents DoS)
- Timeout for incomplete sequences (5s default)
- Delivers partial data on timeout (with gap marker)

---

### 4. Fragmentation Strategy

**MTU problem:**

```
Typical path MTU: 1500 bytes (Ethernet)
IP header: 20 bytes
UDP header: 8 bytes
Available for VEIL: 1472 bytes

VEIL overhead:
  Sequence: 8 bytes
  Poly1305 tag: 16 bytes
  Obfuscation padding: 0-400 bytes

Effective payload: ~1000 bytes (conservative)
```

**When to fragment:**
- Application sends 4000-byte IP packet
- Exceeds VEIL MTU (1280 bytes default)
- Split into multiple VEIL packets

**VEIL fragmentation:**

**Sender:**
```cpp
message_id = generate_unique_id();
offset = 0;

while (offset < data.size()) {
  chunk_size = min(MAX_FRAGMENT, data.size() - offset);
  is_last = (offset + chunk_size >= data.size());

  send_fragment({
    message_id,
    offset,
    is_last,
    data[offset : offset+chunk_size]
  });

  offset += chunk_size;
}
```

**Receiver:**
```cpp
on_fragment_received(frag) {
  state[frag.message_id].add(frag);

  if (state[frag.message_id].has_last &&
      state[frag.message_id].is_complete()) {

    reassembled = concatenate_fragments(state[frag.message_id]);
    deliver_to_app(reassembled);
    state.erase(frag.message_id);
  }
}
```

**Timeout handling:**
- If fragments incomplete after 5s → discard entire message
- Prevents memory exhaustion from partial messages

---

### 5. RTT Estimation and Adaptive Retransmission

**Why fixed timeouts fail:**

```
Fixed RTO = 500ms

Low-latency network (RTT=10ms):
  → Wait 490ms unnecessarily before retransmitting
  → Poor performance

High-latency network (RTT=600ms):
  → Retransmit too early (packet still in flight)
  → Spurious retransmissions
  → Congestion
```

**VEIL's adaptive RTO (RFC 6298):**

**1. Measure RTT:**
```cpp
on_packet_sent(seq, time) {
  pending_acks_[seq] = time;
}

on_ack_received(seq, time) {
  rtt_sample = time - pending_acks_[seq];
  update_rtt(rtt_sample);
}
```

**2. Update smoothed RTT (SRTT):**
```cpp
// First sample:
SRTT = rtt_sample
RTTVAR = rtt_sample / 2

// Subsequent samples:
RTTVAR = (1 - β) × RTTVAR + β × |SRTT - rtt_sample|
SRTT = (1 - α) × SRTT + α × rtt_sample

// Standard values: α = 0.125, β = 0.25
```

**3. Calculate RTO:**
```cpp
RTO = SRTT + 4 × RTTVAR

// Bounds:
RTO = clamp(RTO, min_rto=50ms, max_rto=10s)
```

**4. Exponential backoff on retransmit:**
```cpp
first_transmission: wait RTO
1st retransmit:     wait 2 × RTO
2nd retransmit:     wait 4 × RTO
3rd retransmit:     wait 8 × RTO
...
max_retries (default 5): give up
```

**Why exponential backoff:**
- Network congestion → longer delays
- Backing off reduces load
- Prevents retransmit storms

---

### 6. Multiplexing (Stream Isolation)

**Stream concept:**

A single VPN connection carries multiple logical streams:
```
Stream 0: Control messages (handshake, keep-alive)
Stream 1: IP packets from TUN device
Stream 2: (Reserved for future use)
...
```

**Why multiplexing:**
- Separate ACK state per stream
- Priority handling (control > data)
- Future extensibility (multiple tunnels, QoS)

**Current usage:**
- Stream 0: Control frames
- Stream 1: All tunneled IP traffic

**Future possibilities:**
- Stream-per-application (QoS)
- Stream-per-protocol (TCP, UDP separate)
- Stream-per-priority (interactive, bulk)

---

## Obfuscation Principles

### 1. Why VEIL Traffic Must Look "Natural"

**DPI detection methods:**

**1. Entropy analysis:**
```
Encrypted data: High entropy (random-looking)
Normal web traffic: Mixed entropy (text + images)

DPI heuristic:
  if (avg_entropy > 7.5 bits/byte):
    flag_as_encrypted_vpn()
```

**2. Packet size distribution:**
```
VPN traffic: 1500-byte packets (MTU-sized)
Normal traffic: Varied sizes (web requests: 200-800 bytes)

DPI heuristic:
  if (most_packets == MTU_size):
    flag_as_vpn_tunnel()
```

**3. Timing regularity:**
```
VPN keep-alive: Every 60s exactly
Normal traffic: Irregular, bursty

DPI heuristic:
  if (packet_interval_stddev < threshold):
    flag_as_automated_traffic()
```

---

### 2. Deterministic Padding

**Challenge:**
- Need to add padding to vary packet sizes
- Both endpoints must agree on padding (to remove it)
- Padding must appear random to DPI

**VEIL's solution: Deterministic Pseudo-Random Padding**

**Algorithm:**
```cpp
uint16_t compute_padding_size(profile, sequence) {
  // Derive deterministic value from seed + sequence
  seed = profile.profile_seed;  // 32 bytes, shared secret
  input = seed || sequence;     // Concatenate

  hmac = HMAC-SHA256(seed, input);  // Deterministic "random" value

  // Map to padding range
  base = decode_u16(hmac[0:2]);
  padding = min_padding + (base % (max_padding - min_padding));

  // Add jitter for variance
  jitter = (hmac[2] % (2 * jitter_range)) - jitter_range;

  return clamp(padding + jitter, min_padding, max_padding);
}
```

**Properties:**
- **Deterministic:** Same (seed, sequence) → same padding
- **Pseudo-random:** Looks random to observer without seed
- **Synchronized:** Sender and receiver compute same value
- **Unpredictable:** DPI cannot predict next padding size

**Padding removal:**
```cpp
// Receiver knows padding size (deterministic)
expected_padding = compute_padding_size(profile, sequence);

// Strip padding from end of packet
payload = packet[0 : packet.size() - expected_padding];
```

---

### 3. Packet Size Distribution

**Goal:** Mimic real-world traffic patterns

**Size classes:**

**Small (0-100 bytes):** 40% of packets
- Use case: ACKs, DNS queries, API requests
- VEIL usage: Heartbeats, ACK frames

**Medium (100-400 bytes):** 40% of packets
- Use case: HTTP headers, small responses
- VEIL usage: Control messages, small data packets

**Large (400-1000 bytes):** 20% of packets
- Use case: Images, file downloads
- VEIL usage: Bulk data transfer

**Distribution algorithm:**
```cpp
PaddingClass choose_class(profile, sequence) {
  rand = hmac_based_random(profile.seed, sequence) % 100;

  if (rand < 40)  return SMALL;   // 0-39
  if (rand < 80)  return MEDIUM;  // 40-79
  return LARGE;                   // 80-99
}

uint16_t get_padding_for_class(class) {
  switch (class) {
    case SMALL:  return random_range(0, 100);
    case MEDIUM: return random_range(100, 400);
    case LARGE:  return random_range(400, 1000);
  }
}
```

**Rationale:**
- Matches empirical web traffic studies
- Breaks VPN fingerprint (fixed MTU sizes)
- Adds moderate overhead (~200 bytes avg)

---

### 4. Timing Jitter

**The timing fingerprint:**

```
Regular VPN keep-alive:
  ├── 60.00s ──┤── 60.00s ──┤── 60.00s ──┤
  [packet]     [packet]     [packet]     [packet]

DPI: "This is automated, likely VPN keep-alive"
```

**VEIL with jitter:**

```
  ├─ 58.2s ─┤── 61.7s ──┤─ 59.4s ─┤── 62.1s ──┤
  [packet]   [packet]   [packet]   [packet]

DPI: "Irregular intervals, looks like human-initiated traffic"
```

**Jitter models:**

**1. Uniform (simple):**
```
jitter = random(0, max_jitter)
delay = base_interval + jitter
```

**2. Poisson (natural):**
```
Models random arrival process (like web requests)
λ = arrival rate (events per second)
jitter = -log(1 - uniform_random()) / λ
```

**3. Exponential (bursty):**
```
Models time between events in exponential process
μ = mean interval
jitter = -log(uniform_random()) × μ
```

**VEIL default: Poisson**
- Resembles natural network traffic
- Configurable via profile

**Implementation:**
```cpp
duration compute_next_heartbeat_delay(profile) {
  base = random_range(profile.heartbeat_min, profile.heartbeat_max);

  switch (profile.timing_model) {
    case UNIFORM:
      jitter = random(0, profile.max_jitter);
      break;

    case POISSON:
      lambda = 1.0 / profile.mean_interval.count();
      jitter = -log(1 - uniform_random()) / lambda;
      break;

    case EXPONENTIAL:
      mu = profile.mean_interval.count();
      jitter = -log(uniform_random()) * mu;
      break;
  }

  return base + jitter;
}
```

---

### 5. Heartbeat as IoT Telemetry

**Observation:**
- IoT devices send periodic telemetry (sensor readings)
- Billions of IoT devices worldwide
- DPI cannot block all IoT traffic

**VEIL's IoT mimicry:**

**Heartbeat payload (IoT sensor mode):**
```
┌────────────────────────────────────┐
│ Temperature (float32): 22.3°C      │
│ Humidity (float32): 54.2%          │
│ Battery (float32): 3.87V           │
│ Device ID (uint8): 0x42            │
│ Timestamp (uint64): 1638360000000  │
│ Padding (random): ...              │
└────────────────────────────────────┘
```

**Values are pseudo-random but plausible:**
```cpp
float generate_temperature(seed, sequence) {
  rand = hmac_based_float(seed, sequence);
  return 20.0 + rand * 10.0;  // 20-30°C (room temperature)
}

float generate_humidity(seed, sequence) {
  rand = hmac_based_float(seed, sequence);
  return 40.0 + rand * 30.0;  // 40-70% (comfortable range)
}

float generate_battery(seed, sequence) {
  rand = hmac_based_float(seed, sequence);
  return 3.2 + rand * 1.0;  // 3.2-4.2V (Li-ion battery range)
}
```

**Why this works:**
- DPI sees plausible IoT telemetry
- Cannot distinguish from real IoT traffic without decryption
- Blends into background IoT noise

**Alternative: Generic Telemetry Mode**
```
┌────────────────────────────────────┐
│ Metric 1 (uint64): 1234567890      │
│ Metric 2 (uint64): 9876543210      │
│ Metric 3 (uint32): 42              │
│ Timestamp (uint64): 1638360000000  │
│ Padding (random): ...              │
└────────────────────────────────────┘
```

---

### 6. Random Prefix

**The header fingerprint:**

```
VPN packets often have fixed headers:
  [0x17][0x03][0x03][...] (TLS record header)
  [0x00][0x00][0x00][0x01] (VPN protocol magic)

DPI: "First 4 bytes always same → VPN signature"
```

**VEIL's random prefix:**

```
Packet structure:
┌──────────────────────────────────────────────┐
│ Random Prefix (4-12 bytes, varies)          │
├──────────────────────────────────────────────┤
│ Sequence Number (8 bytes)                   │
├──────────────────────────────────────────────┤
│ ChaCha20-Poly1305 Ciphertext + Tag          │
└──────────────────────────────────────────────┘
```

**Prefix generation:**
```cpp
vector<uint8_t> generate_random_prefix(seed, sequence) {
  // Deterministic length
  length = 4 + (hmac_based_random(seed, sequence) % 9);  // 4-12 bytes

  // Deterministic content (looks random)
  prefix = chacha20_stream(seed, nonce=sequence, length);

  return prefix;
}
```

**Properties:**
- **Variable length:** Breaks fixed-offset assumptions
- **Appears random:** High entropy
- **Deterministic:** Receiver can compute expected prefix
- **Removable:** Receiver strips prefix before decryption

---

### 7. Entropy Normalization

**The entropy problem:**

```
Plaintext (unencrypted): Low entropy
  "GET /index.html HTTP/1.1\r\n\r\n"
  Entropy: ~4.5 bits/byte

Ciphertext (encrypted): High entropy
  0x7a 0xf3 0x29 0x8c 0xd1 ...
  Entropy: ~7.9 bits/byte

DPI: "High entropy → encryption detected!"
```

**VEIL's approach:**

**All packets have high entropy:**
1. Payload is always encrypted (ChaCha20-Poly1305)
2. Padding is pseudo-random (ChaCha20 stream)
3. Prefix is pseudo-random
4. Result: Uniform ~8 bits/byte entropy

**Why this is good:**
- Consistent entropy profile
- No entropy spikes to detect
- Blends with other encrypted traffic (HTTPS, etc.)

---

### 8. Why Obfuscation Profile is Seed-Based

**Requirement:**
- Client and server must agree on obfuscation parameters
- Parameters must appear random to observer
- Parameters must be unpredictable by DPI

**Solution: Shared Seed**

**Seed derivation:**
```
obfuscation_seed = HKDF-Expand(session_keys, "obfuscation_seed", 32 bytes)
```

**Properties:**
- Unique per session (depends on ephemeral handshake)
- Unpredictable without session keys
- Synchronized (both endpoints compute same seed)

**Usage:**
```cpp
ObfuscationProfile profile{
  .profile_seed = obfuscation_seed,
  .enabled = true,
  .max_padding_size = 400,
  .min_padding_size = 0,
  // ... other params ...
};

// All obfuscation decisions deterministic from seed + sequence
padding_size = compute_padding_size(profile, sequence);
prefix = generate_random_prefix(profile, sequence);
jitter_delay = compute_jitter(profile, sequence);
```

**Benefits:**
- No negotiation required (derived from handshake)
- Unpredictable to attacker
- Reproducible by both endpoints
- Changes every session (seed changes)

---

## Summary

### Security Design Principles

1. **Defense in Depth:** Multiple layers (handshake replay cache, transport replay window, AEAD authentication)
2. **Fail Secure:** Invalid input → silent drop (no information leakage)
3. **Minimal Trust:** PSK only for authentication, not encryption (PFS via ephemeral keys)
4. **Cryptographic Agility:** Easy to swap primitives (X25519, ChaCha20-Poly1305 modular)

### Transport Design Principles

1. **UDP-based:** Avoid TCP-over-TCP problems
2. **Selective reliability:** Application decides what to retransmit (VPN just delivers)
3. **Adaptive:** RTT estimation, dynamic RTO, exponential backoff
4. **Efficient:** Selective ACK, out-of-order reassembly, minimal overhead

### Obfuscation Design Principles

1. **Mimic Real Traffic:** Look like IoT/HTTPS/generic UDP, not like VPN
2. **Deterministic Randomness:** Unpredictable to observer, reproducible by endpoints
3. **Multi-Layered:** Padding + timing + prefix + entropy (hard to fingerprint)
4. **Configurable:** Profiles allow adaptation to different threat models

---

**End of Principles of Operation**
