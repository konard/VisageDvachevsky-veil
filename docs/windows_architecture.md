# Windows Architecture for VEIL

## Overview

This document describes the Windows-specific architecture for VEIL VPN client and server with GUI support.

## Architecture Components

```
┌──────────────────────────────────┐
│ 1. GUI Application (Frontend)    │
│ Qt6 (Cross-platform)              │
└───────────────┬──────────────────┘
                │ IPC (Named Pipes on Windows, Unix Sockets on Linux)
┌───────────────▼──────────────────┐
│ 2. Core Service (Backend)         │
│ Windows Service + VEIL core       │
│ Owns: TUN, UDP socket, logic      │
└───────────────┬──────────────────┘
                │ Kernel-mode driver
┌───────────────▼──────────────────┐
│ 3. wintun.sys (WireGuard TUN)    │
│ Virtual network interface         │
└───────────────────────────────────┘
```

## Platform Abstraction Strategy

### 1. TUN Device Abstraction

**File Structure:**
- `src/tun/tun_device.h` - Common interface (already exists)
- `src/tun/tun_device_linux.cpp` - Linux implementation (rename from tun_device.cpp)
- `src/tun/tun_device_windows.cpp` - Windows implementation (new)
- `src/tun/tun_device.cpp` - Platform dispatcher (new)

**Windows Implementation:**
- Uses wintun.dll API
- Manages adapter lifecycle
- Ring buffer for packet I/O
- Thread-based packet reading (wintun doesn't provide fd for epoll)

### 2. IPC Abstraction

**File Structure:**
- `src/common/ipc/ipc_protocol.h` - Protocol definitions (already exists)
- `src/common/ipc/ipc_socket.h` - Common interface (already exists)
- `src/common/ipc/ipc_socket_unix.cpp` - Unix domain socket impl (rename)
- `src/common/ipc/ipc_socket_windows.cpp` - Named pipes impl (new)
- `src/common/ipc/ipc_socket.cpp` - Platform dispatcher (new)

**Windows Implementation:**
- Named Pipes (`\\.\pipe\veil-client`, `\\.\pipe\veil-server`)
- Overlapped I/O for async operations
- Same JSON protocol over pipes

### 3. Routing Abstraction

**File Structure:**
- `src/tun/routing.h` - Common interface (already exists)
- `src/tun/routing_linux.cpp` - Linux implementation (rename)
- `src/tun/routing_windows.cpp` - Windows implementation (new)
- `src/tun/routing.cpp` - Platform dispatcher (new)

**Windows Implementation:**
- IP Helper API (iphlpapi.h)
- CreateIpForwardEntry/DeleteIpForwardEntry
- GetIpForwardTable for route enumeration
- No shell commands needed

### 4. Windows Service

**New Component:**
- `src/windows/service_main.cpp` - Windows service entry point
- `src/windows/service_manager.cpp` - Service control
- Service name: "VEILService"
- Auto-start capability
- Graceful shutdown handling

## DPI Bypass Modes

### Mode A: IoT Mimic
Already partially implemented via IoTSensor heartbeat type.

**Enhancements:**
- Lower heartbeat interval (10-20 sec)
- Smaller packet sizes (prefer small padding class 60%)
- More consistent timing (lower jitter)

### Mode B: QUIC-Like
New profile configuration.

**Characteristics:**
- Large initial packets (800-1200 bytes)
- Higher timing jitter
- Burst patterns
- Exponential timing model

### Mode C: Random-Noise Stealth
Maximum entropy mode.

**Characteristics:**
- Maximum size variance
- Maximum timing jitter
- Aggressive fragmentation
- Disable regular heartbeats

### Mode D: Trickle Mode
Low-bandwidth stealth.

**Characteristics:**
- Rate limiting (10-50 kbit/s)
- High delays (100-500ms jitter)
- Small packets only
- Very infrequent heartbeats

## Implementation Phases

### Phase 1: Core Platform Abstraction (Current)
- [x] Document Windows architecture
- [ ] Create platform abstraction for TUN device
- [ ] Add Windows-specific CMake configuration
- [ ] Create Windows TUN stub implementation

### Phase 2: Windows TUN Integration
- [ ] Integrate wintun SDK
- [ ] Implement Windows TUN device
- [ ] Test basic packet I/O

### Phase 3: Windows IPC
- [ ] Implement Named Pipes IPC
- [ ] Test GUI-to-service communication
- [ ] Port existing IPC server/client

### Phase 4: Windows Routing
- [ ] Implement IP Helper API routing
- [ ] Test route manipulation
- [ ] Implement split-tunneling

### Phase 5: DPI Bypass Modes
- [ ] Define 4 DPI mode profiles
- [ ] Add mode selection to GUI
- [ ] Implement mode-specific parameters
- [ ] Add metrics for mode effectiveness

### Phase 6: Windows Service
- [ ] Implement service wrapper
- [ ] Add service installation/uninstallation
- [ ] Integrate with daemon main loop

### Phase 7: Production Features
- [ ] Auto-update module
- [ ] Diagnostics enhancements
- [ ] Installer creation
- [ ] Documentation

## Build System Changes

### CMake Platform Detection

```cmake
if(WIN32)
  # Windows-specific sources
  set(VEIL_TUN_IMPL src/tun/tun_device_windows.cpp)
  set(VEIL_IPC_IMPL src/common/ipc/ipc_socket_windows.cpp)
  set(VEIL_ROUTING_IMPL src/tun/routing_windows.cpp)

  # Windows-specific libraries
  target_link_libraries(veil_common PRIVATE iphlpapi ws2_32)

  # Wintun SDK
  find_package(Wintun REQUIRED)
  target_link_libraries(veil_common PRIVATE Wintun::Wintun)
else()
  # Linux-specific sources
  set(VEIL_TUN_IMPL src/tun/tun_device_linux.cpp)
  set(VEIL_IPC_IMPL src/common/ipc/ipc_socket_unix.cpp)
  set(VEIL_ROUTING_IMPL src/tun/routing_linux.cpp)
endif()
```

## Testing Strategy

### Windows-Specific Tests
- Unit tests for wintun adapter management
- Integration tests for Windows routing
- IPC communication tests (Named Pipes)

### CI/CD
- Add Windows runner to GitHub Actions
- Build on Windows with MSVC
- Run tests on Windows Server

## Security Considerations

### Service Isolation
- Run service with minimal privileges
- Use service-specific user account
- Restrict file system access

### Driver Trust
- Wintun.sys is signed by WireGuard
- Verify driver signature on installation
- No custom kernel drivers

### IPC Security
- Named Pipes with restricted ACLs
- Only local administrator can connect
- Message validation and authentication

## Open Questions

1. **Development Environment**: Need Windows dev environment with Visual Studio
2. **Wintun Licensing**: Wintun is GPL/Apache dual-licensed, need to verify compatibility
3. **Service Privileges**: What minimum privileges does the service need?
4. **GUI Elevation**: Should GUI require administrator, or only service?

## References

- [Wintun Documentation](https://www.wintun.net/)
- [IP Helper API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/)
- [Windows Services](https://docs.microsoft.com/en-us/windows/win32/services/services)
- [Named Pipes](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes)
