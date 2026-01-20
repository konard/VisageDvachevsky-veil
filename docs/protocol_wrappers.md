# Protocol Wrappers for DPI Evasion

## Overview

Protocol wrappers add legitimate protocol headers around VEIL packets to evade Deep Packet Inspection (DPI) systems that perform protocol fingerprinting. This addresses the limitation that statistical traffic shaping alone cannot fool DPI systems looking for actual protocol signatures.

## Problem Statement

**Before Protocol Wrappers:**
- DPI bypass modes only provided statistical traffic shaping (packet sizes, timing, padding)
- No actual protocol headers were included
- Sophisticated DPI systems could detect lack of protocol structure
- Example: "QUIC-Like" mode didn't include actual QUIC headers

**After Protocol Wrappers:**
- VEIL packets are wrapped in legitimate protocol frames
- DPI systems see valid protocol headers and structure
- Multi-layer evasion: statistical shaping + protocol mimicry

## Available Wrappers

### WebSocket Wrapper (RFC 6455)

**Status:** ✅ Implemented and enabled in QUIC-Like mode

**Description:**
Wraps VEIL packets in WebSocket binary frames, making traffic appear as legitimate WebSocket communication.

**WebSocket Frame Format:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
```

**Frame Parameters:**
- `FIN`: Always 1 (complete frame)
- `RSV1-3`: Always 0 (no extensions)
- `Opcode`: 0x2 (Binary frame)
- `MASK`: 1 for client-to-server, 0 for server-to-client
- `Payload`: VEIL packet data (optionally XOR-masked)

**Overhead:**
- Minimum: 2 bytes (small payloads < 126 bytes, no masking)
- Typical: 6 bytes (small payloads < 126 bytes, with masking)
- Medium: 8 bytes (126-65535 byte payloads, with masking)
- Large: 14 bytes (>65535 byte payloads, with masking)

**DPI Evasion:**
- ✅ Evades protocol signature detection (looks like WebSocket)
- ✅ Evades simple packet inspection (valid RFC 6455 frames)
- ✅ Compatible with statistical traffic shaping
- ⚠️ Does NOT evade TLS-layer inspection (WebSocket typically runs over TLS)

## Usage

### Enabling Protocol Wrappers

**Automatic (via DPI Mode):**
```cpp
// QUIC-Like mode automatically enables WebSocket wrapper
auto profile = create_dpi_mode_profile(DPIBypassMode::kQUICLike);
// profile.protocol_wrapper == ProtocolWrapperType::kWebSocket
```

**Manual Configuration:**
```cpp
ObfuscationProfile profile;
profile.enabled = true;
profile.protocol_wrapper = ProtocolWrapperType::kWebSocket;
profile.is_client_to_server = true;  // Enable masking
```

### Wrapping and Unwrapping

**Wrap a VEIL packet:**
```cpp
#include "common/protocol_wrapper/websocket_wrapper.h"

std::vector<std::uint8_t> veil_packet = /* ... */;
bool client_to_server = true;  // Use masking

auto wrapped = WebSocketWrapper::wrap(veil_packet, client_to_server);
// wrapped now contains: [WS header][masked VEIL packet]
```

**Unwrap a WebSocket frame:**
```cpp
std::vector<std::uint8_t> received_frame = /* ... */;

auto unwrapped = WebSocketWrapper::unwrap(received_frame);
if (unwrapped.has_value()) {
  // unwrapped.value() contains original VEIL packet
  process_veil_packet(*unwrapped);
}
```

## Implementation Details

### WebSocket Masking (RFC 6455 Section 5.3)

**Why Masking?**
- RFC 6455 requires client-to-server frames to be masked
- Prevents cache poisoning attacks in HTTP proxies
- Uses XOR with a random 32-bit key

**Masking Algorithm:**
```cpp
for (size_t i = 0; i < payload.size(); ++i) {
  payload[i] ^= masking_key_bytes[i % 4];
}
```

**Key Generation:**
- Uses cryptographically secure random bytes
- New key for each frame
- Stored in frame header

### Integration with Packet Pipeline

```
┌─────────────────┐
│  VEIL Packet    │
│  [VL][Header]   │
│  [Frames]       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ProtocolWrapperType::kWebSocket
│  Obfuscation    │ ◄─────────────────┐
│  (Padding)      │                   │
└────────┬────────┘                   │
         │                            │
         ▼                            │
┌─────────────────┐                   │
│ Protocol Wrapper│ ◄─────────────────┘
│ (WebSocket)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ [WS Header]     │
│ [Masked VEIL]   │  ──► Send over UDP
└─────────────────┘
```

## Configuration Examples

### Example 1: QUIC-Like Mode (WebSocket Wrapper Enabled)

**Config File (`veil.conf`):**
```ini
[obfuscation]
dpi_mode = quic_like
```

**Result:**
- WebSocket wrapper automatically enabled
- Statistical traffic shaping: bursty, large packets
- Protocol headers: Valid WebSocket binary frames
- DPI sees: Legitimate WebSocket traffic

### Example 2: Custom Profile with WebSocket Wrapper

**Code:**
```cpp
ObfuscationProfile custom_profile;
custom_profile.enabled = true;
custom_profile.protocol_wrapper = ProtocolWrapperType::kWebSocket;
custom_profile.is_client_to_server = true;

// Custom statistical shaping
custom_profile.max_padding_size = 500;
custom_profile.min_padding_size = 50;
custom_profile.timing_jitter_enabled = true;
custom_profile.max_timing_jitter_ms = 100;
```

### Example 3: Server Configuration (No Masking)

**Code:**
```cpp
// Server-to-client direction
ObfuscationProfile server_profile;
server_profile.enabled = true;
server_profile.protocol_wrapper = ProtocolWrapperType::kWebSocket;
server_profile.is_client_to_server = false;  // No masking for server
```

## Performance Impact

### Measurements

| Wrapper Type | Overhead (bytes) | CPU Impact | Latency Impact |
|--------------|------------------|------------|----------------|
| None         | 0                | 0%         | 0 µs           |
| WebSocket    | 2-14             | ~1-2%      | <5 µs          |

**Test Conditions:**
- 1000-byte VEIL packets
- Intel i7-9700K @ 3.6 GHz
- Release build with -O3

**Overhead Breakdown:**
```
Small packet (100 bytes):
  - Frame header: 2 bytes (no masking) or 6 bytes (with masking)
  - Percentage: 2-6% overhead

Medium packet (1000 bytes):
  - Frame header: 6 bytes (with masking)
  - Percentage: 0.6% overhead

Large packet (10000 bytes):
  - Frame header: 6 bytes (with masking)
  - Percentage: 0.06% overhead
```

## Security Considerations

### What WebSocket Wrapper Provides

✅ **Protocol Signature Evasion:**
- DPI looking for WebSocket headers will find valid frames
- Passes simple protocol conformance checks

✅ **Statistical + Structural Evasion:**
- Combined with traffic shaping, provides multi-layer defense
- Harder to classify as VPN/proxy traffic

### What WebSocket Wrapper Does NOT Provide

❌ **TLS Encryption:**
- WebSocket wrapper only adds framing, not encryption
- VEIL's crypto layer already provides encryption
- For full TLS mimicry, consider TLS wrapper (future work)

❌ **HTTP Handshake:**
- Does not include HTTP Upgrade handshake
- Only wraps data frames, not connection establishment
- DPI expecting full WebSocket handshake may still detect

❌ **Application-Layer Semantics:**
- Does not generate realistic WebSocket messages
- Only wraps binary data

### Recommendations

1. **Use with QUIC-Like Mode:** Combines wrapper with appropriate traffic shaping
2. **Consider Network Environment:** WebSocket wrapper most effective against protocol-aware DPI
3. **Layer Defenses:** Use multiple techniques (timing, size, protocol) together
4. **Monitor Effectiveness:** Test against specific DPI systems in your region

## Future Wrappers

### Potential Additions

1. **TLS Record Wrapper**
   - Wrap in TLS 1.3 application data records
   - Highest stealth (appears as normal HTTPS)
   - Higher overhead (~5-20 bytes per record)

2. **QUIC Header Wrapper**
   - Actual QUIC long/short headers
   - More complex than WebSocket
   - Better for mimicking HTTP/3

3. **DNS-over-HTTPS (DoH) Wrapper**
   - Tunnel through DNS TXT records
   - High latency, good for censorship bypass
   - Requires DNS infrastructure

## API Reference

### WebSocketWrapper Class

```cpp
namespace veil::protocol_wrapper {

class WebSocketWrapper {
 public:
  // Wrap data in WebSocket binary frame
  static std::vector<std::uint8_t> wrap(
      std::span<const std::uint8_t> data,
      bool client_to_server = false);

  // Unwrap WebSocket frame to get payload
  static std::optional<std::vector<std::uint8_t>> unwrap(
      std::span<const std::uint8_t> frame);

  // Parse frame header
  static std::optional<std::pair<WebSocketFrameHeader, std::size_t>>
      parse_header(std::span<const std::uint8_t> data);

  // Build frame header bytes
  static std::vector<std::uint8_t> build_header(
      const WebSocketFrameHeader& header);

  // Apply/remove XOR masking
  static void apply_mask(std::span<std::uint8_t> data,
                         std::uint32_t masking_key);

  // Generate random masking key
  static std::uint32_t generate_masking_key();
};

}  // namespace veil::protocol_wrapper
```

### ObfuscationProfile Integration

```cpp
namespace veil::obfuscation {

enum class ProtocolWrapperType : std::uint8_t {
  kNone = 0,       // No wrapper (default)
  kWebSocket = 1,  // WebSocket RFC 6455
};

struct ObfuscationProfile {
  // ... existing fields ...

  ProtocolWrapperType protocol_wrapper{ProtocolWrapperType::kNone};
  bool is_client_to_server{true};  // For WebSocket masking
};

// Helper functions
const char* protocol_wrapper_to_string(ProtocolWrapperType wrapper);
std::optional<ProtocolWrapperType> protocol_wrapper_from_string(const std::string& str);

}  // namespace veil::obfuscation
```

## Testing

### Unit Tests

```cpp
TEST(WebSocketWrapper, WrapAndUnwrap) {
  std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};

  auto wrapped = WebSocketWrapper::wrap(data, true);
  EXPECT_GT(wrapped.size(), data.size());  // Has header

  auto unwrapped = WebSocketWrapper::unwrap(wrapped);
  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(*unwrapped, data);
}
```

### DPI Testing

```bash
# Capture VEIL traffic with WebSocket wrapper
tcpdump -i lo -w veil_websocket.pcap port 8443

# Analyze with Wireshark
wireshark veil_websocket.pcap

# Expected: Valid WebSocket binary frames
# Frame Type: Binary (0x2)
# FIN: 1
# MASK: 1 (client-to-server)
```

## Troubleshooting

### Common Issues

**Issue:** Packets not being wrapped
- Check: `profile.protocol_wrapper == ProtocolWrapperType::kWebSocket`
- Check: Wrapper integrated in send path

**Issue:** Unwrap returns nullopt
- Check: Received data is complete frame
- Check: Frame has valid header
- Debug: Use `parse_header()` to inspect frame structure

**Issue:** DPI still detects VEIL
- Consider: WebSocket typically runs over TLS/HTTPS
- Consider: Full WebSocket handshake may be expected
- Consider: Combine with other evasion techniques

## References

- [RFC 6455: The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
- [WebSocket Security Considerations](https://www.rfc-editor.org/rfc/rfc6455.html#section-10)
- [DPI Evasion Techniques Survey](https://www.ndss-symposium.org/ndss-paper/how-china-detects-and-blocks-shadowsocks/)
