# VEIL Client UI/UX Design

## Table of Contents
- [Introduction](#introduction)
- [Design Philosophy](#design-philosophy)
- [Visual Design Language](#visual-design-language)
- [Main Screen](#main-screen)
- [Settings Screen](#settings-screen)
- [Developer/Diagnostics Screen](#developerddiagnostics-screen)
- [Implementation Notes](#implementation-notes)

---

## Introduction

This document outlines the proposed UI/UX design for the VEIL VPN client. The goal is to create a modern, minimalist, and user-friendly interface that makes VPN connectivity accessible while providing advanced users with detailed diagnostics.

**Design Goals:**
- **Simplicity:** One-click connect/disconnect
- **Transparency:** Clear status indicators and real-time metrics
- **Power:** Advanced settings and diagnostics for technical users
- **Modern:** Contemporary design language (glassmorphism, smooth animations)
- **Accessible:** Clear visual hierarchy, readable fonts, colorblind-friendly

---

## Design Philosophy

### Core Principles

**1. Progressive Disclosure**
- Basic users see: Connect button, status, basic metrics
- Advanced users reveal: Detailed statistics, protocol settings, logs
- Developer users access: Low-level diagnostics, packet stats, debug info

**2. Trustworthy Feedback**
- Connection status always visible
- Real-time metrics (latency, throughput)
- Clear error messages with actionable suggestions

**3. Performance-First**
- UI should not impact VPN performance
- Async updates (don't block connection on UI rendering)
- Efficient rendering (only update changed elements)

**4. Dark Mode Default**
- Reduce eye strain for long-running VPN connections
- Better for privacy (less screen glow)
- Optional light mode for user preference

---

## Visual Design Language

### Color Palette

**Dark Theme (Default):**
```
Background (Primary):   #1a1d23  (Dark charcoal)
Background (Secondary): #252932  (Slightly lighter charcoal)
Background (Tertiary):  #2e3440  (Card backgrounds)

Text (Primary):         #eceff4  (Off-white)
Text (Secondary):       #8fa1b3  (Muted blue-gray)
Text (Tertiary):        #5c687a  (Dim gray)

Accent (Primary):       #3aafff  (Bright blue)
Accent (Success):       #38e2c7  (Teal/turquoise)
Accent (Warning):       #ffb347  (Soft orange)
Accent (Error):         #ff6b6b  (Soft red)

Glassmorphism overlay:  rgba(255, 255, 255, 0.05)
Glassmorphism border:   rgba(255, 255, 255, 0.1)
Shadow:                 rgba(0, 0, 0, 0.3)
```

**Light Theme (Optional):**
```
Background (Primary):   #f8f9fa
Background (Secondary): #e9ecef
Background (Tertiary):  #ffffff

Text (Primary):         #212529
Text (Secondary):       #6c757d
Text (Tertiary):        #adb5bd

Accent (Primary):       #0d6efd
Accent (Success):       #20c997
Accent (Warning):       #fd7e14
Accent (Error):         #dc3545
```

### Typography

**Font Family:**
- **UI Text:** Inter, SF Pro, Segoe UI, system-ui (sans-serif stack)
- **Monospace:** JetBrains Mono, Consolas, Monaco (for IPs, session IDs, logs)

**Font Sizes:**
- **Headline:** 28px / 700 weight
- **Title:** 20px / 600 weight
- **Body:** 15px / 400 weight
- **Caption:** 13px / 400 weight
- **Monospace:** 13px / 400 weight

### Visual Effects

**Glassmorphism Cards:**
```css
background: rgba(255, 255, 255, 0.05);
backdrop-filter: blur(10px);
border: 1px solid rgba(255, 255, 255, 0.1);
border-radius: 16px;
box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
```

**Button Styles:**
```css
/* Primary Button (Connect) */
background: linear-gradient(135deg, #3aafff 0%, #38e2c7 100%);
border-radius: 12px;
padding: 16px 32px;
font-size: 16px;
font-weight: 600;
transition: transform 0.2s, box-shadow 0.2s;

/* Hover */
transform: translateY(-2px);
box-shadow: 0 12px 24px rgba(58, 175, 255, 0.3);

/* Active */
transform: translateY(0);
box-shadow: 0 4px 8px rgba(58, 175, 255, 0.2);
```

**Animations:**
- **Transition Duration:** 200ms (UI interactions)
- **Easing:** cubic-bezier(0.4, 0.0, 0.2, 1) (Material Design standard)
- **Pulse:** 1.5s infinite for "connecting" state

---

## Main Screen

### Layout

```
┌────────────────────────────────────────────────┐
│  VEIL                                    [≡]   │  ← Header
├────────────────────────────────────────────────┤
│                                                │
│         ╭──────────────────────────╮          │
│         │                          │          │
│         │    ● Disconnected        │          │  ← Status Card
│         │                          │          │
│         ╰──────────────────────────╯          │
│                                                │
│         ┌──────────────────────────┐          │
│         │      [  Connect  ]       │          │  ← Main Action
│         └──────────────────────────┘          │
│                                                │
│  ╭─ Session Info ──────────────────────────╮  │
│  │                                          │  │
│  │  Session ID:  [Not Connected]           │  │
│  │  Server:      vpn.example.com:4433      │  │  ← Session Info
│  │  Latency:     —                         │  │
│  │  TX / RX:     0 KB/s / 0 KB/s           │  │
│  │  Uptime:      —                         │  │
│  │                                          │  │
│  ╰──────────────────────────────────────────╯  │
│                                                │
│                 [  Settings  ]                 │  ← Footer
│                                                │
└────────────────────────────────────────────────┘
```

### Connection States

**1. Disconnected**
```
Visual:
  Status Indicator: Gray circle (●)
  Status Text: "Disconnected"
  Button: "Connect" (enabled, gradient background)
  Session Info: Grayed out, showing "—" for metrics

Color Scheme:
  Status color: #8fa1b3 (muted)
  Button: Gradient (blue → teal)
```

**2. Connecting (Handshake in progress)**
```
Visual:
  Status Indicator: Yellow circle (●) with pulse animation
  Status Text: "Connecting..." + spinner
  Button: "Cancel" (enabled, red outline)
  Session Info: Partially visible, showing "Handshake..."

Color Scheme:
  Status color: #ffb347 (warning yellow)
  Button: Red outline (#ff6b6b)

Animation:
  Pulse: opacity 0.5 ↔ 1.0 (1.5s cycle)
```

**3. Connected**
```
Visual:
  Status Indicator: Green circle (●)
  Status Text: "Connected"
  Button: "Disconnect" (enabled, red background)
  Session Info: Fully visible, live metrics updating

Color Scheme:
  Status color: #38e2c7 (success teal)
  Button: Solid red (#ff6b6b)

Metrics Update:
  Refresh rate: 1 second
  Smooth number transitions (no flickering)
```

**4. Reconnecting**
```
Visual:
  Status Indicator: Orange circle (●) with pulse
  Status Text: "Reconnecting... (Attempt 2/5)"
  Button: "Cancel" (enabled)
  Session Info: Shows last known values, dimmed

Color Scheme:
  Status color: #ffb347 (warning)
  Previous metrics: 50% opacity
```

**5. Error**
```
Visual:
  Status Indicator: Red circle (●)
  Status Text: "Connection Failed"
  Error Message: "Handshake timeout. Check server address."
  Button: "Retry" (enabled, gradient)
  Session Info: Hidden

Color Scheme:
  Status color: #ff6b6b (error red)
  Error text: #ff6b6b on dark background card
```

### Session Info Details

**Session ID:**
```
Display Format: 0x1234567890abcdef
Font: Monospace, 13px
Tooltip: "Internal session identifier. Rotates every 30s for privacy."
```

**Server:**
```
Display Format: vpn.example.com:4433
Font: Monospace, 13px
Clickable: No
```

**Latency (RTT):**
```
Display Format: 25 ms
Update: Every 1 second
Color coding:
  0-50ms:   #38e2c7 (green)
  51-100ms: #ffb347 (yellow)
  >100ms:   #ff6b6b (red)
```

**TX / RX (Throughput):**
```
Display Format: 1.2 MB/s / 3.4 MB/s
Update: Every 1 second
Units: Auto-scale (KB/s, MB/s, GB/s)
Graph: Optional mini sparkline (last 60 seconds)
```

**Uptime:**
```
Display Format: 02:34:56 (HH:MM:SS)
Update: Every 1 second
Tooltip: "Session started at 14:30:00"
```

---

## Settings Screen

### Layout

```
┌────────────────────────────────────────────────┐
│  ← Back      Settings                          │
├────────────────────────────────────────────────┤
│                                                │
│  ╭─ Server Configuration ───────────────────╮ │
│  │                                           │ │
│  │  Server Address:                          │ │
│  │  ┌───────────────────────────────────┐    │ │
│  │  │ vpn.example.com                   │    │ │
│  │  └───────────────────────────────────┘    │ │
│  │                                           │ │
│  │  Port:                                    │ │
│  │  ┌───────────────────────────────────┐    │ │
│  │  │ 4433                              │    │ │
│  │  └───────────────────────────────────┘    │ │
│  │                                           │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│  ╭─ Routing ────────────────────────────────╮ │
│  │                                           │ │
│  │  [✓] Route all traffic through VPN       │ │
│  │  [ ] Split tunnel mode                    │ │
│  │                                           │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│  ╭─ Connection ────────────────────────────╮  │
│  │                                           │ │
│  │  [✓] Auto-reconnect on disconnect        │ │
│  │                                           │ │
│  │  Reconnect Interval:  [  5  ] seconds    │ │
│  │                                           │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│  ╭─ Advanced ──────────────────────────────╮  │
│  │                                           │ │
│  │  [✓] Enable obfuscation                  │ │
│  │  [ ] Verbose logging                      │ │
│  │  [ ] Developer mode                       │ │
│  │                                           │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│              [  Save Changes  ]                │
│                                                │
└────────────────────────────────────────────────┘
```

### Settings Categories

**1. Server Configuration**
- **Server Address:** Text input, placeholder: "vpn.example.com"
- **Port:** Number input, range: 1-65535, default: 4433
- **Validation:** Real-time validation (valid hostname/IP, valid port)

**2. Routing**
- **Route all traffic:** Checkbox (sets default route through VPN)
- **Split tunnel mode:** Checkbox (only route specific networks)
  - Sub-option: "Custom routes" (comma-separated CIDR list)

**3. Connection**
- **Auto-reconnect:** Checkbox
- **Reconnect interval:** Slider (1-60 seconds)
- **Max reconnect attempts:** Number input (0 = unlimited)

**4. Advanced**
- **Enable obfuscation:** Checkbox (traffic morphing, padding, jitter)
- **Verbose logging:** Checkbox (logs handshake details, retransmissions)
- **Developer mode:** Checkbox (enables Developer/Diagnostics screen)

**5. Appearance (Future)**
- **Theme:** Radio buttons (Dark / Light / Auto)
- **Color accent:** Color picker
- **Compact mode:** Checkbox (reduce spacing for smaller windows)

---

## Developer/Diagnostics Screen

### Layout

```
┌────────────────────────────────────────────────┐
│  ← Back      Diagnostics                       │
├────────────────────────────────────────────────┤
│                                                │
│  ╭─ Protocol Metrics ──────────────────────╮  │
│  │                                           │ │
│  │  Sequence Counter:     0x000000012345    │ │
│  │  Send Sequence:        0x000000012300    │ │
│  │  Recv Sequence:        0x000000012400    │ │
│  │                                           │ │
│  │  Packets Sent:         12,345            │ │
│  │  Packets Received:     12,400            │ │
│  │  Packets Lost:         5 (0.04%)         │ │
│  │  Packets Retransmitted: 3 (0.02%)        │ │
│  │                                           │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│  ╭─ Reassembly Stats ──────────────────────╮  │
│  │                                           │ │
│  │  Fragments Received:   42                │ │
│  │  Messages Reassembled: 38                │ │
│  │  Fragments Pending:    4                 │ │
│  │  Reassembly Timeouts:  0                 │ │
│  │                                           │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│  ╭─ Obfuscation Profile ───────────────────╮  │
│  │                                           │ │
│  │  Padding Enabled:      Yes               │ │
│  │  Current Padding Size: 234 bytes         │ │
│  │  Timing Jitter:        Poisson (λ=0.5)   │ │
│  │  Heartbeat Mode:       IoT Sensor        │ │
│  │  Last Heartbeat:       3.2s ago          │ │
│  │                                           │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│  ╭─ Live Event Log ────────────────────────╮  │
│  │ [14:32:05] Handshake INIT sent           │ │
│  │ [14:32:05] Handshake RESPONSE received   │ │
│  │ [14:32:05] Session established (ID=0x...) │ │
│  │ [14:32:10] Data packet sent (seq=1)      │ │
│  │ [14:32:10] ACK received (ack=1, bitmap=0)│ │
│  │ [14:32:35] Session ID rotated (0x... → 0x│ │
│  │                      [  Clear Log  ]      │ │
│  ╰───────────────────────────────────────────╯ │
│                                                │
│           [  Export Diagnostics  ]             │
│                                                │
└────────────────────────────────────────────────┘
```

### Diagnostic Sections

**1. Protocol Metrics**
- Sequence counters (send/recv)
- Packet counts (sent, received, lost, retransmitted)
- Loss percentage (color-coded: <1% green, 1-5% yellow, >5% red)

**2. Reassembly Stats**
- Fragment counters
- Pending reassembly operations
- Timeout events

**3. Obfuscation Profile**
- Current padding size
- Timing jitter model and parameters
- Heartbeat mode and last sent time

**4. Live Event Log**
- Scrollable log (last 100 events)
- Timestamps for each event
- Event types:
  - Handshake (INIT, RESPONSE)
  - Connection (established, disconnected, reconnecting)
  - Session rotation
  - Data frames (sent/received)
  - ACKs
  - Errors
- Color coding:
  - Info: white
  - Success: green
  - Warning: yellow
  - Error: red

**5. Export Diagnostics**
- Button: "Export Diagnostics"
- Generates JSON file with:
  - Current metrics
  - Configuration
  - Event log
  - System info (OS, version, architecture)
- Use case: Bug reports, performance analysis

---

## Implementation Notes

### Technology Stack Options

**Option 1: Qt/C++ (Native)**
- **Pros:** Native performance, seamless integration with C++ backend
- **Cons:** Larger binary size, Qt dependency
- **Best for:** Desktop-first, performance-critical

**Option 2: Electron (Web Technologies)**
- **Pros:** Cross-platform, modern UI frameworks (React, Vue)
- **Cons:** Large memory footprint, slower startup
- **Best for:** Rapid development, modern design

**Option 3: GTK/C++ (Native Linux)**
- **Pros:** Lightweight, native Linux integration
- **Cons:** Limited cross-platform support
- **Best for:** Linux-only deployments

**Recommendation:** Qt/C++ for balance of performance and UI capabilities

### IPC Architecture

```
┌──────────────┐                 ┌──────────────┐
│   GUI        │                 │  VEIL Daemon │
│  Process     │  ◀─── IPC ────▶ │  (veil-client)│
│ (veil-gui)   │   (Unix socket) │              │
└──────────────┘                 └──────────────┘
      │                                 │
      │ Sends:                          │ Sends:
      │ - Connect/Disconnect            │ - Status updates
      │ - Config changes                │ - Metrics (1/sec)
      │ - Request diagnostics           │ - Event log
```

**IPC Protocol (JSON over Unix socket):**

**Client → Daemon:**
```json
{
  "command": "connect",
  "params": {
    "server": "vpn.example.com",
    "port": 4433
  }
}
```

**Daemon → Client:**
```json
{
  "event": "status_update",
  "data": {
    "state": "connected",
    "session_id": "0x1234567890abcdef",
    "latency_ms": 25,
    "tx_bytes_per_sec": 1048576,
    "rx_bytes_per_sec": 3145728,
    "uptime_sec": 12345
  }
}
```

### Responsive Design

**Window Sizes:**
- **Minimum:** 400 × 600 px
- **Optimal:** 480 × 720 px
- **Maximum:** 1200 × 1600 px (for developer mode with logs)

**Breakpoints:**
- **Compact (<500px width):** Single column, reduce padding
- **Normal (500-800px width):** Standard layout
- **Wide (>800px width):** Side-by-side panels for diagnostics

### Accessibility

**1. Keyboard Navigation**
- Tab order: Connect button → Settings → Advanced options
- Enter/Space to activate buttons
- Escape to cancel/close modals

**2. Screen Reader Support**
- ARIA labels for all interactive elements
- Status announcements (e.g., "Connected to VPN")
- Error messages read aloud

**3. Color Blindness**
- Do not rely solely on color for status (use shapes + text)
- Status indicator: ● (shape) + "Connected" (text)
- High contrast mode option

**4. Font Scaling**
- Respect system font size settings
- Minimum 13px base font (readability)

### Animation Details

**Connection State Transitions:**
```
Disconnected → Connecting:
  Status indicator: Fade from gray to yellow (200ms)
  Start pulse animation (1.5s cycle)
  Button: Morph "Connect" to "Cancel" (200ms)

Connecting → Connected:
  Status indicator: Fade from yellow to green (300ms)
  Stop pulse, add success checkmark (500ms)
  Button: Morph "Cancel" to "Disconnect" (200ms)
  Session info: Slide in from bottom (400ms)

Connected → Disconnected:
  Session info: Fade out (200ms)
  Status indicator: Fade from green to gray (300ms)
  Button: Morph "Disconnect" to "Connect" (200ms)
```

**Metric Updates:**
```
Number changes:
  - Animate digit transitions (flip clock style)
  - Duration: 300ms
  - Easing: cubic-bezier(0.4, 0.0, 0.2, 1)

Throughput graph (if enabled):
  - Update every 1 second
  - Slide left (new data on right)
  - Smooth line interpolation
```

---

## Mockups (Text-Based)

### Main Screen - Disconnected
```
╔══════════════════════════════════════════════╗
║  VEIL                                    ≡   ║
╠══════════════════════════════════════════════╣
║                                              ║
║         ╭──────────────────────────╮         ║
║         │                          │         ║
║         │    ● Disconnected        │         ║
║         │                          │         ║
║         ╰──────────────────────────╯         ║
║                                              ║
║         ┌──────────────────────────┐         ║
║         │  ▶  Connect              │         ║
║         └──────────────────────────┘         ║
║                                              ║
║  ╭─ Session Info ─────────────────────────╮ ║
║  │  Session ID:  —                        │ ║
║  │  Server:      vpn.example.com:4433     │ ║
║  │  Latency:     —                        │ ║
║  │  TX / RX:     — / —                    │ ║
║  │  Uptime:      —                        │ ║
║  ╰────────────────────────────────────────╯ ║
║                                              ║
║              [  ⚙ Settings  ]                ║
╚══════════════════════════════════════════════╝
```

### Main Screen - Connected
```
╔══════════════════════════════════════════════╗
║  VEIL                                    ≡   ║
╠══════════════════════════════════════════════╣
║                                              ║
║         ╭──────────────────────────╮         ║
║         │                          │         ║
║         │    ● Connected ✓         │         ║
║         │                          │         ║
║         ╰──────────────────────────╯         ║
║                                              ║
║         ┌──────────────────────────┐         ║
║         │  ■  Disconnect           │         ║
║         └──────────────────────────┘         ║
║                                              ║
║  ╭─ Session Info ─────────────────────────╮ ║
║  │  Session ID:  0x9abc123...             │ ║
║  │  Server:      vpn.example.com:4433     │ ║
║  │  Latency:     25 ms                    │ ║
║  │  TX / RX:     1.2 MB/s / 3.4 MB/s      │ ║
║  │  Uptime:      02:34:56                 │ ║
║  ╰────────────────────────────────────────╯ ║
║                                              ║
║              [  ⚙ Settings  ]                ║
╚══════════════════════════════════════════════╝
```

---

## Future Enhancements

**1. System Tray Integration**
- Minimize to tray (background operation)
- Tray icon: Shows connection status (green/red/yellow)
- Right-click menu: Connect, Disconnect, Quit

**2. Multi-Profile Support**
- Save multiple server configurations
- Quick switch between profiles
- Import/export profiles

**3. Statistics/History**
- Daily/weekly/monthly data usage
- Connection history (uptime, disconnects)
- Latency graphs over time

**4. Notifications**
- Connection established
- Disconnected (with reason)
- Approaching data limit (if configured)

**5. Kill Switch UI**
- Toggle for "Block traffic if VPN disconnects"
- Visual indicator when kill switch is active

---

**End of Client UI/UX Design**
