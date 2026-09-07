<div align="center">

  <img src="https://capsule-render.vercel.app/api?type=waving&height=190&color=0:020617,45:0F766E,100:2563EB&text=Deep%20Packet%20Inspection%20Engine&fontColor=FFFFFF&fontSize=38&fontAlignY=36&animation=fadeIn" alt="Deep Packet Inspection Engine Banner" />

  <br />

  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=21&duration=2600&pause=900&color=0F766E&center=true&vCenter=true&width=850&lines=C%2B%2B+Network+Packet+Analyzer;PCAP+Parsing+%7C+TLS+SNI+Extraction+%7C+Traffic+Classification;Rule-Based+Blocking+%7C+Flow+Tracking+%7C+Multithreaded+DPI" alt="Typing animation" />

  <br />
  <br />

  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" alt="C++17" />
  <img src="https://img.shields.io/badge/PCAP-Packet%20Analysis-0F766E?style=for-the-badge" alt="PCAP" />
  <img src="https://img.shields.io/badge/TCP%2FIP-Networking-2563EB?style=for-the-badge" alt="TCP/IP" />
  <img src="https://img.shields.io/badge/TLS-SNI%20Extraction-7C3AED?style=for-the-badge" alt="TLS SNI" />
  <img src="https://img.shields.io/badge/Multithreading-High%20Performance-EA580C?style=for-the-badge" alt="Multithreading" />

  <br />
  <br />

  <b>A C++ Deep Packet Inspection system that reads PCAP traffic, parses network protocols, classifies applications, applies blocking rules, and writes filtered output captures.</b>

</div>

---

## Overview

**Deep Packet Inspection Engine** is a C++ network analysis project built to understand how traffic filtering systems work under the hood.

Instead of only reading packet headers like a basic packet viewer, this project goes deeper into packet payloads to identify application traffic using **TLS SNI** and **HTTP Host** data. It can classify flows, apply blocking rules, forward allowed packets, drop blocked packets, and generate traffic reports.

The project includes both:

- A **simple single-threaded version** for learning and debugging packet flow.
- A **multi-threaded DPI version** for higher-throughput packet processing.

---

## What Problem It Solves

Normal packet analyzers can show packet fields, but they usually stop at inspection. This project adds a real filtering pipeline:

1. Read packets from a PCAP capture.
2. Parse Ethernet, IPv4, TCP, and UDP headers.
3. Track traffic using a five-tuple flow key.
4. Extract domain information from TLS SNI or HTTP Host headers.
5. Classify traffic into applications such as HTTPS, DNS, YouTube, Facebook, Google, and GitHub.
6. Apply blocking rules based on IP, application, or domain.
7. Write only allowed packets to a new output PCAP file.
8. Generate a summary report with packet counts, dropped traffic, forwarded traffic, and application breakdown.

That makes it closer to a small DPI firewall engine than a normal packet display tool.

---

## Key Features

<table>
  <tr>
    <td><b>PCAP Reader</b></td>
    <td>Reads network capture files and validates PCAP headers before packet processing.</td>
  </tr>
  <tr>
    <td><b>Protocol Parser</b></td>
    <td>Extracts Ethernet, IPv4, TCP, UDP, port, protocol, timestamp, and payload metadata.</td>
  </tr>
  <tr>
    <td><b>Deep Packet Inspection</b></td>
    <td>Inspects payload data to extract TLS SNI and HTTP Host values for application identification.</td>
  </tr>
  <tr>
    <td><b>Flow Tracking</b></td>
    <td>Uses source IP, destination IP, source port, destination port, and protocol to track connections.</td>
  </tr>
  <tr>
    <td><b>Rule-Based Blocking</b></td>
    <td>Blocks traffic by source IP, application type, or domain match.</td>
  </tr>
  <tr>
    <td><b>Multithreaded Pipeline</b></td>
    <td>Uses load balancers, fast-path worker threads, queues, and an output writer for parallel processing.</td>
  </tr>
  <tr>
    <td><b>Traffic Reports</b></td>
    <td>Shows total packets, forwarded packets, dropped packets, thread statistics, app breakdown, and detected domains.</td>
  </tr>
</table>

---

## Tech Stack

### Core

![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=cplusplus&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-Build%20System-064F8C?style=flat-square&logo=cmake&logoColor=white)
![PCAP](https://img.shields.io/badge/PCAP-Capture%20Format-0F766E?style=flat-square)

### Networking

![TCP/IP](https://img.shields.io/badge/TCP%2FIP-Network%20Protocols-2563EB?style=flat-square)
![TLS](https://img.shields.io/badge/TLS-SNI%20Inspection-7C3AED?style=flat-square)
![HTTP](https://img.shields.io/badge/HTTP-Host%20Extraction-EA580C?style=flat-square)

### Systems Concepts

![Multithreading](https://img.shields.io/badge/Multithreading-Worker%20Pipeline-DC2626?style=flat-square)
![Flow Tracking](https://img.shields.io/badge/Flow%20Tracking-Five%20Tuple-0891B2?style=flat-square)
![Queues](https://img.shields.io/badge/Thread%20Safe%20Queues-Producer%20Consumer-16A34A?style=flat-square)

---

## Architecture

```text
Input PCAP
    |
    v
PCAP Reader
    |
    v
Packet Parser
    |
    v
Five-Tuple Flow Tracker
    |
    v
Deep Packet Inspection
    |
    +--> TLS SNI Extraction
    +--> HTTP Host Extraction
    |
    v
Rule Engine
    |
    +--> Forward Allowed Packets
    +--> Drop Blocked Packets
    |
    v
Output PCAP + Traffic Report
```

---

## Multithreaded Design

The multi-threaded version is designed around a packet-processing pipeline.

```text
                 +----------------+
                 |  Reader Thread |
                 +--------+-------+
                          |
                          v
              +-----------+-----------+
              |   Load Balancer Pool  |
              +-----------+-----------+
                          |
                          v
              +-----------+-----------+
              | Fast Path Worker Pool |
              +-----------+-----------+
                          |
                          v
              +-----------+-----------+
              |    Output Queue       |
              +-----------+-----------+
                          |
                          v
                 +--------+--------+
                 | Output Writer   |
                 +-----------------+
```

### Why This Design Matters

- Load balancers distribute traffic across worker threads.
- Fast-path workers handle parsing, DPI, classification, and rule checks.
- Consistent hashing keeps packets from the same connection on the same worker.
- Thread-safe queues separate packet reading, processing, and output writing.
- Output writer creates a filtered PCAP containing only forwarded traffic.

---

## How Traffic Is Classified

The engine identifies traffic using protocol headers and payload inspection.

```text
Packet
  |
  +--> Ethernet Header
  +--> IPv4 Header
  +--> TCP / UDP Header
  +--> Payload
         |
         +--> TLS Client Hello
         |      |
         |      +--> SNI: www.youtube.com
         |
         +--> HTTP Request
                |
                +--> Host: example.com
```

After extracting SNI or Host data, the engine maps domains to application categories and applies rules.

---

## Blocking Rules

The rule engine supports three types of filtering.

| Rule Type | Example | Result |
|---|---|---|
| IP Rule | `192.168.1.50` | Blocks traffic from a source IP |
| App Rule | `YouTube` | Blocks all traffic classified as YouTube |
| Domain Rule | `facebook` | Blocks traffic whose SNI or Host matches the domain |

Example:

```bash
./dpi_engine test_dpi.pcap output.pcap \
  --block-app YouTube \
  --block-domain facebook \
  --block-ip 192.168.1.50
```

---

## Project Structure

```text
packet_analyzer/
├── include/
│   ├── pcap_reader.h
│   ├── packet_parser.h
│   ├── sni_extractor.h
│   ├── types.h
│   ├── rule_manager.h
│   ├── connection_tracker.h
│   ├── load_balancer.h
│   ├── fast_path.h
│   ├── thread_safe_queue.h
│   └── dpi_engine.h
│
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp
│   ├── main.cpp
│   ├── main_working.cpp
│   ├── main_dpi.cpp
│   ├── dpi_mt.cpp
│   ├── dpi_engine.cpp
│   ├── rule_manager.cpp
│   ├── connection_tracker.cpp
│   ├── load_balancer.cpp
│   └── fast_path.cpp
│
├── generate_test_pcap.py
├── test_dpi.pcap
├── output.pcap
├── CMakeLists.txt
└── README.md
```

---

## Build And Run

### Prerequisites

- C++17 compiler
- CMake or g++
- Python 3 for generating test PCAP data

---

### Build Simple Packet Analyzer

```bash
g++ -std=c++17 -O2 -I include -o packet_analyzer \
  src/main.cpp \
  src/pcap_reader.cpp \
  src/packet_parser.cpp
```

Run:

```bash
./packet_analyzer test_dpi.pcap
```

---

### Build Simple DPI Version

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
  src/main_working.cpp \
  src/pcap_reader.cpp \
  src/packet_parser.cpp \
  src/sni_extractor.cpp \
  src/types.cpp
```

Run:

```bash
./dpi_simple test_dpi.pcap output.pcap
```

---

### Build Multithreaded DPI Version

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
  src/dpi_mt.cpp \
  src/pcap_reader.cpp \
  src/packet_parser.cpp \
  src/sni_extractor.cpp \
  src/types.cpp
```

Run:

```bash
./dpi_engine test_dpi.pcap output.pcap
```

Run with blocking rules:

```bash
./dpi_engine test_dpi.pcap output.pcap \
  --block-app YouTube \
  --block-app TikTok \
  --block-domain facebook
```

Configure processing threads:

```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
```

---

## Generate Test Traffic

The project includes a Python script to generate sample PCAP traffic.

```bash
python3 generate_test_pcap.py
```

This creates test traffic with multiple protocols and domains so the DPI engine can classify and report them.

---

## Sample Output

```text
DPI ENGINE v2.0 (Multi-threaded)

Load Balancers: 2
FPs per LB: 2
Total FPs: 4

Processing Report
-----------------
Total Packets: 77
TCP Packets:   73
UDP Packets:   4
Forwarded:     69
Dropped:       8

Application Breakdown
---------------------
HTTPS       39
Unknown     16
YouTube      4  BLOCKED
DNS          4
Facebook     3

Detected Domains
----------------
www.youtube.com  -> YouTube
www.facebook.com -> Facebook
www.google.com   -> Google
github.com       -> GitHub
```

---

## Screenshots

Add screenshots or terminal images inside a `screenshots` folder and update these paths.

<table>
  <tr>
    <td align="center"><b>Packet Report</b></td>
    <td align="center"><b>Blocking Rules</b></td>
  </tr>
  <tr>
    <td><img src="screenshots/report.png" width="420" alt="Packet Report Screenshot" /></td>
    <td><img src="screenshots/rules.png" width="420" alt="Blocking Rules Screenshot" /></td>
  </tr>
  <tr>
    <td align="center"><b>Thread Statistics</b></td>
    <td align="center"><b>Detected Domains</b></td>
  </tr>
  <tr>
    <td><img src="screenshots/threads.png" width="420" alt="Thread Statistics Screenshot" /></td>
    <td><img src="screenshots/domains.png" width="420" alt="Detected Domains Screenshot" /></td>
  </tr>
</table>

---

## Resume Highlights

This project demonstrates:

- C++ systems programming
- Network protocol parsing
- PCAP file processing
- TCP/IP fundamentals
- TLS SNI extraction
- HTTP Host inspection
- Flow tracking with five-tuples
- Rule-based packet filtering
- Multithreaded pipeline design
- Producer-consumer queues
- Traffic classification and reporting

---

## Future Improvements

- Add IPv6 packet parsing
- Add QUIC and HTTP/3 traffic support
- Add persistent rule configuration files
- Add live dashboard for real-time statistics
- Add bandwidth throttling instead of only blocking
- Add JSON or CSV export for reports
- Add unit tests for packet parsing and SNI extraction

---

## Author

<div align="center">

  <b>Aman Sharma</b>

  <br />
  <br />

  <a href="https://github.com/Softeraman">
    <img src="https://img.shields.io/badge/GitHub-Softeraman-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub" />
  </a>
  <a href="https://www.linkedin.com/in/aman-sharma-8ab247239">
    <img src="https://img.shields.io/badge/LinkedIn-Aman%20Sharma-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn" />
  </a>

</div>

---

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&height=120&section=footer&color=0:2563EB,45:0F766E,100:020617" alt="Footer wave" />
</div>
