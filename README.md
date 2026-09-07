# DPI Engine - Deep Packet Inspection System


This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/main_working.cpp` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.cpp` | Production, large captures |

---

## 4. File Structure

```
packet_analyzer/
├── include/                    # Header files (declarations)
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing
│   ├── sni_extractor.h        # TLS/HTTP inspection
│   ├── types.h                # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.h         # Blocking rules (multi-threaded version)
│   ├── connection_tracker.h   # Flow tracking (multi-threaded version)
│   ├── load_balancer.h        # LB thread (multi-threaded version)
│   ├── fast_path.h            # FP thread (multi-threaded version)
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Main orchestrator
│
├── src/                        # Implementation files
│   ├── pcap_reader.cpp        # PCAP file handling
│   ├── packet_parser.cpp      # Protocol parsing
│   ├── sni_extractor.cpp      # SNI/Host extraction
│   ├── types.cpp              # Helper functions
│   ├── main_working.cpp       # ★ SIMPLE VERSION ★
│   ├── dpi_mt.cpp             # ★ MULTI-THREADED VERSION ★
│   └── [other files]          # Supporting code
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `main_working.cpp`:

### Step 1: Read PCAP File

```cpp
PcapReader reader;
reader.open("capture.pcap");
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```cpp
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```cpp
PacketParser::parse(raw, parsed);
```

**What happens (in packet_parser.cpp):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```cpp
FiveTuple tuple;
tuple.src_ip = parseIP(parsed.src_ip);
tuple.dst_ip = parseIP(parsed.dest_ip);
tuple.src_port = parsed.src_port;
tuple.dst_port = parsed.dest_port;
tuple.protocol = parsed.protocol;

Flow& flow = flows[tuple];  // Get or create
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```cpp
// For HTTPS traffic (port 443)
if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
    auto sni = SNIExtractor::extract(payload, payload_length);
    if (sni) {
        flow.sni = *sni;                    // "www.youtube.com"
        flow.app_type = sniToAppType(*sni); // AppType::YOUTUBE
    }
}
```

**What happens (in sni_extractor.cpp):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Skip variable-length fields:**
   - Session ID
   - Cipher Suites
   - Compression Methods

3. **Search extensions for type 0x0000 (SNI):**
   ```
   Extension Type: 0x0000
   SNI List Length: 18
   Name Type: 0x00 (hostname)
   Name Length: 15
   Name: "www.youtube.com"
   ```

4. **Return the domain name**

### Step 6: Classify Application

```cpp
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos ||
        sni.find("googlevideo") != std::string::npos)
        return AppType::YOUTUBE;
    
    if (sni.find("facebook") != std::string::npos ||
        sni.find("fbcdn") != std::string::npos)
        return AppType::FACEBOOK;
    
    if (sni.find("tiktok") != std::string::npos)
        return AppType::TIKTOK;
    
    // ... more apps
}
```

**Supported Applications:**
- YouTube, Facebook, Instagram, TikTok
- Netflix, Twitter, WhatsApp
- Google, GitHub, Amazon
- LinkedIn, Reddit
- Plus generic: HTTPS, HTTP, DNS, QUIC

### Step 7: Check Blocking Rules

```cpp
bool should_drop = false;

// Check IP block
if (blocked_ips.count(pkt.tuple.src_ip)) {
    should_drop = true;
}

// Check app block
if (blocked_apps.count(flow.app_type)) {
    should_drop = true;
}

// Check domain block
for (const auto& domain : blocked_domains) {
    if (flow.sni.find(domain) != std::string::npos) {
        should_drop = true;
    }
}
```

### Step 8: Forward or Drop

```cpp
if (!should_drop) {
    writer.writePacket(raw);  // Write to output PCAP
    forwarded++;
} else {
    dropped++;  // Don't write = dropped
}
```

### Step 9: Update Statistics

```cpp
stats.total_packets++;
stats.app_packets[flow.app_type]++;
stats.total_bytes += raw.header.incl_len;
```

At the end, print a report showing:
- Total packets/bytes
- Forwarded vs dropped
- Application breakdown
- Detected domains

---

## 6. The Journey of a Packet (Multi-threaded Version)

For high performance, packets are processed in parallel:

```
                        ┌─────────────────────────────────────┐
                        │           MAIN THREAD               │
                        │   (Reads PCAP, distributes packets) │
                        └──────────────┬──────────────────────┘
                                       │
                    hash(5-tuple) % num_LBs
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
        ┌──────────┐            ┌──────────┐            ┌──────────┐
        │   LB 0   │            │   LB 1   │            │   LB 2   │
        │  Thread  │            │  Thread  │            │  Thread  │
        └────┬─────┘            └────┬─────┘            └────┬─────┘
             │                       │                       │
        hash % FPs              hash % FPs              hash % FPs
             │                       │                       │
        ┌────┴────┐             ┌────┴────┐             ┌────┴────┐
        ▼         ▼             ▼         ▼             ▼         ▼
      FP0       FP1           FP2       FP3           FP4       FP5
      Thread    Thread        Thread    Thread        Thread    Thread
        │         │             │         │             │         │
        └────┬────┘             └────┬────┘             └────┬────┘
             │                       │                       │
             └───────────────────────┼───────────────────────┘
                                     ▼
                              ┌─────────────┐
                              │   OUTPUT    │
                              │   WRITER    │
                              └─────────────┘
```

### Why Two Levels (LB + FP)?

This mimics real telecom DPI architecture:

1. **Load Balancer (LB)**:
   - Receives packets from main thread
   - Hashes the 5-tuple
   - Routes to a Fast Path worker
   - **Guarantees all packets of same flow go to same FP**

2. **Fast Path (FP)**:
   - Maintains flow state
   - Does DPI inspection
   - Applies blocking rules
   - Decides forward/drop

### The Key: Flow Consistency

```cpp
size_t hash = FiveTupleHash{}(tuple);
size_t fp_index = hash % num_fps;
```

**Why this matters:**
```
Flow A packets: hash = 12345 → FP 1 (always)
Flow B packets: hash = 67890 → FP 2 (always)
Flow C packets: hash = 11111 → FP 3 (always)
```

All packets of Flow A go to FP 1, so FP 1 can safely maintain the flow's state without locks!

---

## 7. Deep Dive: Each Component

### 7.1 PcapReader (`pcap_reader.cpp`)

**Purpose:** Read/write PCAP files

**Key Structures:**
```cpp
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;        // Max packet size
    uint32_t network;        // 1 = Ethernet
};

struct PcapPacketHeader {
    uint32_t ts_sec;    // Timestamp seconds
    uint32_t ts_usec;   // Timestamp microseconds
    uint32_t incl_len;  // Captured bytes
    uint32_t orig_len;  // Original packet length
};
```

**Functions:**
- `open(filename)` - Opens PCAP, reads global header
- `readNextPacket(raw)` - Reads one packet
- `writePacket(raw)` - Writes packet to output
- `close()` - Closes files

---

### 7.2 PacketParser (`packet_parser.cpp`)

**Purpose:** Decode raw packet bytes into meaningful fields

**Parsing Chain:**
```
Raw Bytes
    │
    ▼
┌──────────────┐
│ Ethernet     │ → src_mac, dest_mac, ethertype
└──────┬───────┘
       │ ethertype == 0x0800?
       ▼
┌──────────────┐
│ IPv4         │ → src_ip, dest_ip, protocol
└──────┬───────┘
       │
       ├── protocol == 6 ──► TCP → ports, flags, payload
       │
       └── protocol == 17 ─► UDP → ports, payload
```

**Important:** Network byte order is big-endian. We convert:
```cpp
uint16_t readUint16BE(const uint8_t* data) {
    return (data[0] << 8) | data[1];
}
```

---

### 7.3 SNIExtractor (`sni_extractor.cpp`)

**Purpose:** Extract domain names from TLS Client Hello and HTTP Host headers

**TLS Detection:**
```cpp
bool isTLSClientHello(const uint8_t* data, size_t len) {
    return len > 5 &&
           data[0] == 0x16 &&  // Handshake content type
           data[5] == 0x01;    // Client Hello
}
```

**HTTP Host Detection:**
```cpp
// Search for "Host: " header
std::string payloadStr((char*)data, len);
size_t pos = payloadStr.find("Host: ");
if (pos != std::string::npos) {
    // Extract until \r\n
    return payloadStr.substr(pos + 6, ...);
}
```

---

### 7.4 Types (`types.h`, `types.cpp`)

**Purpose:** Define shared data structures

**FiveTuple:**
```cpp
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    
    bool operator==(const FiveTuple& other) const;
};
```

**Flow:**
```cpp
struct Flow {
    FiveTuple tuple;
    AppType app_type;
    FlowAction action;      // FORWARD or DROP
    std::string sni;        // Extracted domain
    uint64_t packet_count;
    uint64_t byte_count;
};
```

**AppType:**
```cpp
enum class AppType {
    UNKNOWN,
    HTTP, HTTPS, DNS, QUIC,
    YOUTUBE, FACEBOOK, INSTAGRAM,
    TIKTOK, NETFLIX, TWITTER,
    WHATSAPP, GOOGLE, GITHUB,
    AMAZON, LINKEDIN, REDDIT
};
```

---

### 7.5 ThreadSafeQueue (`thread_safe_queue.h`)

**Purpose:** Safely pass packets between threads

**How It Works:**
```cpp
template<typename T>
class ThreadSafeQueue {
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    
public:
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(item));
        cv_.notify_one();  // Wake up waiting thread
    }
    
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this]{ return !queue_.empty() || stopped_; });
        if (queue_.empty()) return false;
        item = std::move(queue_.front());
        queue_.pop();
        return true;
    }
};
```

**The Producer-Consumer Pattern:**
```
Producer Thread          Queue              Consumer Thread
     │                     │                       │
     │── push(packet) ─────►│                       │
     │                     │── notify ─────────────►│
     │                     │                       │── pop(packet)
     │                     │                       │── process
```

---

### 7.6 RuleManager (`rule_manager.cpp`)

**Purpose:** Store and check blocking rules (thread-safe)

**Rules:**
```cpp
std::unordered_set<uint32_t> blocked_ips_;      // IP addresses
std::unordered_set<AppType> blocked_apps_;      // App types
std::unordered_set<std::string> blocked_domains_; // Domain patterns
```

**Thread Safety:** Uses `std::shared_mutex`:
- Multiple threads can **read** rules simultaneously
- Only one thread can **modify** rules at a time

---

### 7.7 ConnectionTracker (`connection_tracker.cpp`)

**Purpose:** Track flows and their states

```cpp
std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows_;
```

**Key Operations:**
- `getOrCreateFlow(tuple)` - Find or create flow
- `updateFlow(flow, packet)` - Update statistics
- `cleanupOldFlows()` - Remove expired flows

---

## 8. How SNI Extraction Works (Detailed)

### The TLS Handshake

```
Client                                    Server
   │                                         │
   │ ──── Client Hello ─────────────────────►│
   │      - Supported TLS versions           │
   │      - Cipher suites                    │
   │      - SNI: "www.youtube.com" ← HERE!  │
   │                                         │
   │ ◄──── Server Hello ─────────────────────│
   │      - Selected cipher                  │
   │      - Certificate                      │
   │                                         │
   │ ──── Key Exchange ─────────────────────►│
   │                                         │
   │ ◄═══ Encrypted Data ══════════════════► │
   │      (from here on, everything is       │
   │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, size_t length
) {
    // Check TLS record header
    if (payload[0] != 0x16) return std::nullopt;  // Not handshake
    if (payload[5] != 0x01) return std::nullopt;  // Not Client Hello
    
    size_t offset = 43;  // Skip to session ID
    
    // Skip Session ID
    uint8_t session_len = payload[offset];
    offset += 1 + session_len;
    
    // Skip Cipher Suites
    uint16_t cipher_len = readUint16BE(payload + offset);
    offset += 2 + cipher_len;
    
    // Skip Compression Methods
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;
    
    // Read Extensions Length
    uint16_t ext_len = readUint16BE(payload + offset);
    offset += 2;
    
    // Search for SNI extension
    size_t ext_end = offset + ext_len;
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + offset);
        uint16_t ext_data_len = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (ext_type == 0x0000) {  // SNI!
            // Parse SNI structure
            uint16_t sni_len = readUint16BE(payload + offset + 3);
            return std::string(
                (char*)(payload + offset + 5), 
                sni_len
            );
        }
        
        offset += ext_data_len;
    }
    
    return std::nullopt;  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **macOS/Linux** with C++17 compiler
- **g++** or **clang++**
- No external libraries needed!

### Build Commands

**Simple Version:**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

**Multi-threaded Version:**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Running

**Basic usage:**
```bash
./dpi_engine test_dpi.pcap output.pcap
```

**With blocking:**
```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure threads (multi-threaded only):**
```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
```

### Creating Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```cpp
   // In types.cpp
   if (sni.find("twitch") != std::string::npos)
       return AppType::TWITCH;
   ```

2. **Add Bandwidth Throttling**
   ```cpp
   // Instead of DROP, delay packets
   if (shouldThrottle(flow)) {
       std::this_thread::sleep_for(10ms);
   }
   ```

3. **Add Live Statistics Dashboard**
   ```cpp
   // Separate thread printing stats every second
   void statsThread() {
       while (running) {
           printStats();
           sleep(1);
       }
   }
   ```

4. **Add QUIC/HTTP3 Support**
   - QUIC uses UDP on port 443
   - SNI is in the Initial packet (encrypted differently)

5. **Add Persistent Rules**
   - Save rules to file
   - Load on startup

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with the simple version (`main_working.cpp`) to understand the concepts, then move to the multi-threaded version (`dpi_mt.cpp`) to see how parallelism is added.

Happy learning! 🚀
