# VEIL Protocol DPI Resistance Analysis

**Analysis Date:** 2026-01-20
**Issue Reference:** [#16](https://github.com/VisageDvachevsky/veil/issues/16)
**Purpose:** Evaluate protocol resistance to Deep Packet Inspection (DPI), TSPU, and similar detection systems
**Auditor:** AI Code Reviewer (Claude)

---

## Executive Summary

This analysis evaluates the VEIL protocol's resistance to traffic analysis and detection by Deep Packet Inspection (DPI) systems, TSPU (Technical Means for Countering Threats), and similar traffic classification systems.

### Overall Assessment

**Current Status:** The protocol has **PARTIAL** DPI resistance.

| Component | Resistance Level | Risk |
|-----------|-----------------|------|
| Data Phase (encrypted traffic) | HIGH | Low |
| Handshake Phase | LOW | **CRITICAL** |
| Packet Size Distribution | MEDIUM | Medium |
| Timing Patterns | MEDIUM | Medium |
| Sequence Number Exposure | MEDIUM | Medium |

### Critical Findings

1. **CRITICAL:** Handshake packets contain plaintext magic bytes "HS" (0x48, 0x53) and fixed structure
2. **HIGH:** 8-byte sequence numbers visible in plaintext on all data packets
3. **MEDIUM:** Handshake packet sizes are fixed (76 bytes INIT, 92 bytes RESPONSE)
4. **MEDIUM:** Session establishment pattern easily identifiable (request-response timing)

---

## Detailed Analysis

### 1. Handshake Phase - CRITICAL VULNERABILITY

**Location:** `src/common/handshake/handshake_processor.cpp`

#### 1.1 Plaintext Magic Bytes

The handshake uses magic bytes `"HS"` (0x48, 0x53) sent **completely unencrypted**:

```cpp
// handshake_processor.cpp:16
constexpr std::array<std::uint8_t, 2> kMagic{'H', 'S'};
```

**DPI Detection Rule (pseudocode):**
```
if (udp.payload[0:2] == 0x4853 && udp.payload.length == 76):
    flag_as_veil_handshake_init()
```

#### 1.2 Handshake INIT Message Structure (100% Plaintext)

```
Offset  | Field                    | Size | Plaintext | DPI Fingerprintable
--------|--------------------------|------|-----------|--------------------
0-1     | Magic "HS"               | 2    | YES       | YES - Direct signature
2       | Version (0x01)           | 1    | YES       | YES - Known value
3       | Message Type (0x01)      | 1    | YES       | YES - Known value
4-11    | Timestamp (ms)           | 8    | YES       | YES - Timestamp format
12-43   | Ephemeral Public Key     | 32   | YES       | Partial - X25519 format
44-75   | HMAC-SHA256              | 32   | YES       | No - Random appearance
        | TOTAL                    | 76   |           |
```

**Fingerprint:** Fixed 76-byte UDP packets starting with `0x48 0x53 0x01 0x01`

#### 1.3 Handshake RESPONSE Message Structure (100% Plaintext)

```
Offset  | Field                    | Size | Plaintext | DPI Fingerprintable
--------|--------------------------|------|-----------|--------------------
0-1     | Magic "HS"               | 2    | YES       | YES
2       | Version (0x01)           | 1    | YES       | YES
3       | Message Type (0x02)      | 1    | YES       | YES
4-11    | Init Timestamp           | 8    | YES       | YES
12-19   | Response Timestamp       | 8    | YES       | YES
20-27   | Session ID               | 8    | YES       | Partial
28-59   | Responder Ephemeral Key  | 32   | YES       | Partial
60-91   | HMAC-SHA256              | 32   | YES       | No
        | TOTAL                    | 92   |           |
```

**Fingerprint:** Fixed 92-byte UDP response starting with `0x48 0x53 0x01 0x02`

#### 1.4 Connection Establishment Pattern

DPI systems can easily identify VEIL connections by:

1. **Request-Response Pattern:** 76-byte packet followed by 92-byte response
2. **Timing:** Response typically within milliseconds
3. **Both packets start with:** `0x48 0x53 0x01` (HS + version)
4. **Message types:** 0x01 for INIT, 0x02 for RESPONSE

**Risk Level:** CRITICAL - Allows complete identification of VEIL protocol usage

---

### 2. Data Phase - Sequence Number Exposure

**Location:** `src/transport/session/transport_session.cpp:250-257`

#### 2.1 Plaintext Sequence Numbers

```cpp
// transport_session.cpp:250-257
// Prepend sequence number (8 bytes big-endian).
// The sequence is sent in plaintext to allow the receiver to derive the same nonce.
std::vector<std::uint8_t> packet;
packet.reserve(8 + ciphertext.size());
for (int i = 7; i >= 0; --i) {
  packet.push_back(static_cast<std::uint8_t>((send_sequence_ >> (8 * i)) & 0xFF));
}
```

**Wire Format:**
```
[8 bytes: Plaintext Sequence] [Variable: AEAD Ciphertext]
```

#### 2.2 Why Sequence Numbers are Exposed

The sequence number is required in plaintext for nonce derivation:
- Receiver needs exact sequence to compute `nonce = XOR(base_nonce, sequence)`
- Without plaintext sequence, decryption is impossible
- This is a cryptographic necessity for stateless packet processing

#### 2.3 Information Leakage

Exposed sequence numbers allow DPI to determine:

1. **Exact packet count** in session
2. **Packet ordering** and out-of-order delivery
3. **Sequence gaps** indicating packet loss or retransmission
4. **Traffic volume** correlation
5. **Session continuity** (monotonically increasing sequences)

**DPI Detection Rule:**
```
if (packet.first_8_bytes is monotonically_increasing over 10+ packets):
    likely_veil_session()
```

**Risk Level:** MEDIUM - Enables traffic analysis but not direct identification

---

### 3. Encrypted Data - STRONG

**Location:** `src/transport/session/transport_session.cpp:248`

#### 3.1 Encryption Strength

Data packets use ChaCha20-Poly1305 AEAD:

```cpp
auto ciphertext = crypto::aead_encrypt(keys_.send_key, nonce, {}, plaintext);
```

**Protected Content:**
- Magic bytes "VL" (inside ciphertext)
- Version, flags, session ID
- Frame type, length, payload
- Authentication tag

**Entropy Analysis (from tests/integration/security_integration.cpp):**
- Ciphertext entropy: >7.5 bits per byte (expected ~8 for random)
- No detectable patterns in encrypted portion
- No magic byte leakage after position 8

**Risk Level:** LOW - Encrypted data is cryptographically indistinguishable from random

---

### 4. Packet Size Distribution

**Location:** `src/common/obfuscation/obfuscation_profile.cpp`

#### 4.1 Current Implementation

The protocol supports padding with configurable distribution:

```cpp
struct PaddingDistribution {
  std::uint8_t small_weight{40};   // 0-100 bytes
  std::uint8_t medium_weight{40};  // 100-400 bytes
  std::uint8_t large_weight{20};   // 400-1000 bytes
  std::uint16_t jitter_range{20};
};
```

#### 4.2 Weakness: Handshake Sizes Fixed

Despite data packet padding, handshake packets have **fixed sizes**:
- INIT: Always 76 bytes
- RESPONSE: Always 92 bytes

This creates a clear fingerprint for session establishment.

#### 4.3 Data Packet Size Analysis

With obfuscation enabled, data packets have:
- Variable padding (0-400+ bytes)
- Three size classes with jitter
- HMAC-deterministic padding (reproducible but not fingerprint-able)

**Risk Level:** MEDIUM - Data packets vary, but handshake is fixed

---

### 5. Timing Analysis

**Location:** `src/common/obfuscation/obfuscation_profile.cpp:258-307`

#### 5.1 Timing Jitter Implementation

The protocol supports timing obfuscation:

```cpp
enum class TimingJitterModel : std::uint8_t {
  kUniform = 0,      // Uniform random
  kPoisson = 1,      // Network-like
  kExponential = 2,  // Bursty
};
```

#### 5.2 Weakness: Handshake Timing

Handshake request-response timing is predictable:
- No jitter applied to handshake
- Response typically immediate (< 100ms)
- Pattern: Single UDP packet -> Single UDP response

#### 5.3 Weakness: Heartbeat Patterns

Heartbeats have configurable but regular intervals:
- Default: 5-15 seconds (IoT mode)
- Creates periodic traffic pattern
- IoT payload structure may be detectable

**Risk Level:** MEDIUM - Jitter helps data, but patterns exist

---

### 6. Protocol Mimicry Analysis

**Location:** `docs/dpi_bypass_modes.md`

#### 6.1 Supported DPI Bypass Modes

```cpp
enum class DPIBypassMode : std::uint8_t {
  kIoTMimic = 0,     // IoT sensor telemetry
  kQUICLike = 1,     // QUIC/HTTP3 traffic
  kRandomNoise = 2,  // Maximum unpredictability
  kTrickle = 3,      // Low-and-slow
  kCustom = 255      // User-defined
};
```

#### 6.2 Weakness: No Actual Protocol Mimicry

Current implementation:
- **Claims** to mimic IoT/QUIC but doesn't implement actual protocol headers
- Only adjusts timing and padding patterns
- Does NOT inject real QUIC headers or IoT protocol signatures
- DPI looking for actual QUIC handshake won't be fooled

**Risk Level:** MEDIUM - Statistical mimicry only, not protocol-level

---

## Detection Methods Analysis

### What DPI Can Detect

| Detection Method | Effectiveness | Mitigation Exists? |
|-----------------|---------------|-------------------|
| Magic bytes "HS" in handshake | HIGH | NO |
| Fixed handshake packet sizes | HIGH | NO |
| Request-response pattern | HIGH | NO |
| Monotonic sequence numbers | MEDIUM | Partial |
| Traffic volume correlation | MEDIUM | Partial (padding) |
| Timing analysis | LOW | YES (jitter) |
| Encrypted payload patterns | NONE | YES (AEAD) |

### DPI Evasion Test Results

Based on `tests/integration/security_integration.cpp`:

| Test | Result | Notes |
|------|--------|-------|
| High entropy packets | PASS | >7.5 bits/byte |
| Variable packet sizes | PASS | >5 distinct sizes |
| No magic in ciphertext | PASS | Position 8+ random |
| Timing consistency | PARTIAL | Valid/invalid similar |

---

## Recommendations for 100% Invisibility

### Critical Priority (Must Implement)

#### R1: Encrypt Handshake Packets

**Current:** Magic bytes "HS" in plaintext
**Required:** Full handshake encryption

Options:
1. **Noise Protocol Handshake** - Encrypt entire handshake with pre-shared key
2. **Two-phase handshake** - Initial probe looks like random data, server responds with encrypted challenge
3. **DTLS-like handshake** - Mimic legitimate DTLS handshake structure

#### R2: Variable Handshake Padding

**Current:** Fixed 76/92 byte packets
**Required:** Add random padding to handshake packets

```cpp
// Proposed change
size_t init_size = 76 + random_padding(0, 400);
size_t response_size = 92 + random_padding(0, 400);
```

#### R3: Remove Plaintext Sequence Numbers

**Current:** 8 bytes plaintext
**Required:** Encrypted or obfuscated sequence

Options:
1. **Implicit sequence** - Derive from previous packet hash
2. **Encrypted sequence prefix** - Use PSK to encrypt sequence
3. **Random padding before sequence** - Make position unpredictable

### High Priority (Should Implement)

#### R4: Protocol Mimicry for Real Protocols

**Current:** Statistical patterns only
**Required:** Actual protocol header injection

Options:
1. **QUIC mimicry** - Inject real QUIC long header
2. **DNS-over-HTTPS mimicry** - Tunnel via DNS
3. **WebRTC mimicry** - Look like video calls
4. **Gaming protocol mimicry** - Look like game traffic

#### R5: Randomize Session Establishment

**Current:** Predictable request-response
**Required:** Variable timing and dummy packets

- Add random delay before response
- Send decoy packets before handshake
- Support "stealth knock" where server doesn't respond unless specific pattern

### Medium Priority (Nice to Have)

#### R6: Heartbeat Randomization

**Current:** Regular intervals with fixed IoT structure
**Required:** Irregular timing, varied payload structure

#### R7: Multi-path/Multi-hop Support

Support routing through multiple endpoints to prevent traffic correlation.

#### R8: Traffic Shaping

Match traffic patterns of legitimate services (Netflix, YouTube, etc.).

---

## Attack Scenarios and Mitigations

### Scenario 1: DPI Signature Detection

**Attack:** DPI scans for "HS" magic bytes
**Current Risk:** HIGH
**Mitigation:** Encrypt handshake (R1)

### Scenario 2: Packet Size Fingerprinting

**Attack:** Detect fixed 76/92 byte handshake
**Current Risk:** HIGH
**Mitigation:** Variable padding (R2)

### Scenario 3: Statistical Traffic Analysis

**Attack:** ML classifier on packet sizes/timing
**Current Risk:** MEDIUM
**Mitigation:** Protocol mimicry (R4)

### Scenario 4: Active Probing

**Attack:** Send probe packets, observe response
**Current Risk:** LOW (silent drop implemented)
**Mitigation:** Already implemented

### Scenario 5: Sequence Correlation

**Attack:** Track monotonic sequences across sessions
**Current Risk:** MEDIUM
**Mitigation:** Obfuscate sequences (R3)

---

## Compliance with Issue #16 Requirements

| Requirement | Status | Details |
|-------------|--------|---------|
| Test DPI resistance | DONE | Analysis complete |
| Check VPN/proxy detection | FAIL | Handshake identifiable |
| Check for patterns/markers | FAIL | Multiple patterns found |
| Create issues for vulnerabilities | PENDING | Issues to be created |
| 100% invisible protocol | NOT MET | Critical changes needed |

---

## New Issues to Create

Based on this analysis, the following issues should be created:

1. **[CRITICAL] Plaintext Handshake Magic Bytes Enable DPI Detection**
2. **[HIGH] Fixed Handshake Packet Sizes Create Fingerprint**
3. **[MEDIUM] Plaintext Sequence Numbers Enable Traffic Analysis**
4. **[MEDIUM] Heartbeat Patterns May Enable Protocol Detection**
5. **[LOW] DPI Bypass Modes Lack Real Protocol Mimicry**

---

## Conclusion

The VEIL protocol currently provides **strong encryption** for data packets but has **critical weaknesses** in the handshake phase that make it **easily detectable** by DPI systems.

### To achieve 100% invisibility:

1. **Immediate:** Encrypt handshake packets
2. **Immediate:** Add variable padding to handshake
3. **Short-term:** Obfuscate sequence numbers
4. **Medium-term:** Implement real protocol mimicry
5. **Long-term:** Add traffic shaping and multi-path support

### Estimated Effort

| Priority | Change | Effort | Impact |
|----------|--------|--------|--------|
| Critical | Encrypt handshake | 2-3 weeks | HIGH |
| Critical | Variable handshake padding | 1 week | HIGH |
| High | Obfuscate sequences | 2 weeks | MEDIUM |
| High | Protocol mimicry | 4+ weeks | HIGH |
| Medium | Traffic shaping | 4+ weeks | MEDIUM |

**Total to reach 100% invisibility:** 8-12 weeks of development

---

**End of Analysis**

*Generated: 2026-01-20*
*Auditor: Claude (AI Code Reviewer)*
*Version: 1.0*
