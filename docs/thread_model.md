# VEIL Thread Model Documentation

## Overview

This document describes the thread model used in VEIL, including thread ownership,
synchronization mechanisms, and memory safety guarantees.

## Component Thread Model

### 1. Client Application

The VEIL client uses a single-threaded event-driven model:

```
┌─────────────────────────────────────────────────────┐
│                   Main Thread                        │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  TUN Device │  │  UDP Socket │  │   Tunnel    │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
│         │                │                │         │
│         └────────────────┼────────────────┘         │
│                          ▼                          │
│                   ┌─────────────┐                   │
│                   │ Event Loop  │                   │
│                   │   (epoll)   │                   │
│                   └─────────────┘                   │
└─────────────────────────────────────────────────────┘
```

**Thread Safety:**
- All operations occur on the main thread
- No mutex required for normal operation
- Signal handler uses atomic flags for shutdown

### 2. Server Application

The server supports multi-client handling with the following model:

```
┌─────────────────────────────────────────────────────┐
│                   Main Thread                        │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  UDP Socket │  │Session Table│  │   Routing   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
│         │                │                │         │
│         └────────────────┼────────────────┘         │
│                          ▼                          │
│                   ┌─────────────┐                   │
│                   │ Event Loop  │                   │
│                   └─────────────┘                   │
└─────────────────────────────────────────────────────┘
```

**Thread Safety:**
- Single-threaded event loop handles all I/O
- Session table uses internal synchronization for cleanup timers
- Handshake processing uses thread-safe replay cache

### 3. Cryptographic Components

**Thread Safety Guarantees:**

| Component | Thread Safe | Notes |
|-----------|-------------|-------|
| `crypto::generate_x25519_keypair()` | ✓ | Uses libsodium (thread-safe) |
| `crypto::compute_shared_secret()` | ✓ | Pure function |
| `crypto::derive_session_keys()` | ✓ | Pure function |
| `crypto::aead_encrypt()` | ✓ | Pure function |
| `crypto::aead_decrypt()` | ✓ | Pure function |
| `crypto::secure_zero()` | ✓ | Uses libsodium |
| `HandshakeInitiator` | ✗ | Single-use, not thread-safe |
| `HandshakeResponder` | ✓ | Internal mutex for replay cache |
| `TransportSession` | ✗ | Single-owner, not thread-safe |

### 4. Handshake Components

```
HandshakeResponder:
┌─────────────────────────────────────────┐
│          Public Interface               │
├─────────────────────────────────────────┤
│  handle_init() ─────┬─▶ rate_limiter_   │
│                     │     (atomic)       │
│                     ├─▶ replay_cache_    │
│                     │     (mutex)        │
│                     └─▶ psk_             │
│                           (immutable)    │
└─────────────────────────────────────────┘
```

**Synchronization:**
- `TokenBucket`: Uses atomic operations
- `HandshakeReplayCache`: Internal mutex for LRU map

### 5. Transport Session

```
TransportSession:
┌─────────────────────────────────────────┐
│              Single Owner               │
├─────────────────────────────────────────┤
│  encrypt_data()                         │
│  decrypt_packet()                       │
│  process_ack()                          │
│  rotate_session()                       │
│                                         │
│  Internal State:                        │
│  ├─ keys_           (immutable once set)│
│  ├─ send_sequence_  (monotonic)         │
│  ├─ replay_window_  (no sync needed)    │
│  ├─ retransmit_buffer_  (owned)         │
│  └─ fragment_reassembly_ (owned)        │
└─────────────────────────────────────────┘
```

**Thread Safety:**
- `TransportSession` is NOT thread-safe
- Must be owned by a single thread
- If shared access is needed, external synchronization required

## Memory Ownership

### Packet Buffers

```
Encryption Path:
  User Data ─▶ encrypt_data() ─▶ vector<vector<uint8_t>>
                                       │
                                       ▼
                               Caller owns result
                               (Copy semantics)

Decryption Path:
  Ciphertext ─▶ decrypt_packet() ─▶ optional<vector<MuxFrame>>
       │                                    │
       │                                    ▼
       │                            Caller owns result
       ▼
  Input remains valid (borrowed view via span)
```

### Session Lifecycle

```
┌─────────────────────────────────────────────────────┐
│                 Session Lifecycle                    │
├─────────────────────────────────────────────────────┤
│                                                      │
│  Handshake ──▶ Session Created ──▶ Active ──┐       │
│                     │                        │       │
│                     ▼                        ▼       │
│               Keys Owned               Rotation      │
│                     │                   (ID only)    │
│                     │                        │       │
│                     ▼                        │       │
│               Destruction ◀──────────────────┘       │
│                     │                                │
│                     ▼                                │
│          Keys Securely Cleared                       │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Data Race Prevention

### Critical Sections

1. **Replay Cache** (HandshakeReplayCache)
   - Protected by: `std::mutex`
   - Access pattern: mark_and_check() is atomic

2. **Token Bucket** (Rate Limiter)
   - Protected by: atomic operations
   - Access pattern: allow() is lock-free

3. **Session Table** (Server)
   - Protected by: external synchronization in single-threaded event loop
   - Access pattern: all mutations on event loop thread

### Atomic Operations

```cpp
// Rate limiter uses atomics
std::atomic<double> tokens_;
std::atomic<TimePoint> last_fill_;

// Signal handler uses atomic flags
std::atomic<bool> should_terminate_{false};
```

## Security Considerations

### Sensitive Data Handling

All sensitive data is cleared using `sodium_memzero()`:

1. **Ephemeral Private Keys**: Cleared after ECDH computation
2. **Shared Secrets**: Cleared after key derivation
3. **Session Keys**: Cleared on session destruction
4. **PSK**: Cleared on handshake object destruction
5. **HKDF Intermediate State**: Cleared after each operation

### Destructor Guarantees

```cpp
~HandshakeInitiator() {
  sodium_memzero(psk_.data(), psk_.size());
  sodium_memzero(ephemeral_.secret_key.data(), ...);
}

~TransportSession() {
  sodium_memzero(keys_.send_key.data(), ...);
  sodium_memzero(keys_.recv_key.data(), ...);
  // ... all key material
}
```

## Runtime Thread Safety Assertions

VEIL provides a `ThreadChecker` utility class (`src/common/utils/thread_checker.h`) for
enforcing thread ownership at runtime. This utility provides debug-only assertions
with zero overhead in release builds.

### ThreadChecker Usage

```cpp
#include "common/utils/thread_checker.h"

class SingleThreadedComponent {
 public:
  void do_work() {
    // Asserts in debug builds if called from wrong thread
    VEIL_DCHECK_THREAD(thread_checker_);
    // ... component logic ...
  }

 private:
  VEIL_THREAD_CHECKER(thread_checker_);
};
```

### Components with Thread Assertions

The following components use `ThreadChecker` to enforce single-threaded access:

| Component | File | Thread Binding |
|-----------|------|----------------|
| `EventLoop` | `src/transport/event_loop/event_loop.h` | Binds to thread that calls `run()` |
| `TransportSession` | `src/transport/session/transport_session.h` | Binds to creating thread |

### ThreadChecker API

- `VEIL_THREAD_CHECKER(name)` - Declare a thread checker member
- `VEIL_DCHECK_THREAD(checker)` - Assert current thread is owner (debug only)
- `VEIL_DCHECK_THREAD_SCOPE(checker)` - Scoped check on entry and exit
- `checker.rebind_to_current()` - Transfer ownership to current thread
- `checker.detach()` - Release thread ownership

## Recommendations

### For Library Users

1. **Single-threaded usage recommended**
   - Use one `TransportSession` per thread
   - No external synchronization needed

2. **Multi-threaded usage**
   - Create separate sessions per thread
   - Or use external mutex to protect shared session

3. **Memory safety**
   - Don't hold references to internal buffers
   - All data is returned by copy (safe)

### For Contributors

1. **Adding new components**
   - Document thread safety guarantees in class documentation
   - Prefer single-threaded designs
   - Use `VEIL_THREAD_CHECKER` macro to enforce single-threaded access
   - Use atomics for simple flags
   - Use mutex only when necessary

2. **Thread Safety Documentation**
   - Add Thread Safety section to class docstrings
   - Specify which methods are thread-safe
   - Reference this document for details

3. **Modifying crypto code**
   - Always clear sensitive data
   - Use `crypto::secure_zero()` or `sodium_memzero()`
   - Test for memory leaks with valgrind

## Testing Thread Safety

Run the thread safety tests:

```bash
# Build with ThreadSanitizer
cmake --preset debug -DVEIL_ENABLE_SANITIZERS=THREAD
cmake --build build/debug

# Run tests
ctest --test-dir build/debug --output-on-failure
```

## Appendix: Component Ownership Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Application                                   │
├───────────────┬─────────────────────────────────────┬───────────────┤
│               │                                     │               │
│   ┌───────────▼───────────┐         ┌──────────────▼──────────────┐│
│   │    HandshakeManager   │         │       SessionManager        ││
│   │                       │         │                             ││
│   │ owns:                 │         │ owns:                       ││
│   │ ├─ HandshakeInitiator │         │ ├─ map<id, TransportSession>││
│   │ └─ HandshakeResponder │         │ └─ cleanup timer            ││
│   └───────────────────────┘         └─────────────────────────────┘│
│               │                                     │               │
│               │ creates                             │ uses          │
│               ▼                                     ▼               │
│   ┌───────────────────────────────────────────────────────────────┐│
│   │                    TransportSession                            ││
│   │                                                                ││
│   │ owns:                                                          ││
│   │ ├─ SessionKeys (encrypted)                                     ││
│   │ ├─ ReplayWindow                                                ││
│   │ ├─ SessionRotator                                              ││
│   │ ├─ RetransmitBuffer                                            ││
│   │ └─ FragmentReassembly                                          ││
│   └───────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```
