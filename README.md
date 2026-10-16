# 🔬 DPI Engine — Deep Packet Inspection System

[![Live Demo](https://img.shields.io/badge/Live%20Demo-packet--analyzer--dpi.vercel.app-00f2fe?style=for-the-badge&logo=vercel&logoColor=white)](https://packet-analyzer-dpi.vercel.app)
[![Java](https://img.shields.io/badge/Java-17+-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> **🚀 Live Demo:** [https://packet-analyzer-dpi.vercel.app](https://packet-analyzer-dpi.vercel.app)

A production-grade **Deep Packet Inspection (DPI) engine** that analyzes real network traffic (PCAP files), identifies applications by inspecting TLS SNI / HTTP Host headers, enforces firewall rules, and visualizes everything in a real-time web dashboard.

Built from scratch in **Java** with a **Next.js** interactive dashboard — deployable on Vercel in one click.

---

This document explains **everything** about this project - from basic networking concepts to the complete code architecture across **Java**, **Next.js (Web/Vercel)**, and **C++**. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

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
12. [Deploying to Vercel (Live Web Dashboard)](#12-deploying-to-vercel-live-web-dashboard)
13. [Resume & Interview Highlights](#13-resume--interview-highlights)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent).
- **Enterprises**: Block social media or streaming services on corporate networks.
- **Parental Controls**: Restrict inappropriate websites.
- **Security & Threat Intelligence**: Detect malware, command-and-control beacons, and intrusion attempts.

### What Our DPI Engine Does:
```text
User Traffic (PCAP) ──► [DPI Engine] ──► Filtered Traffic (PCAP)
                              │
                              ├── Identifies Apps (YouTube, Facebook, Netflix, etc.)
                              ├── Blocks traffic in real time based on security rules
                              └── Generates high-fidelity traffic & protocol reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple networking layers:

```text
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

Every network packet is structured like Russian nesting dolls—headers wrapped inside headers:

```text
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

A **connection** (or "flow") is uniquely identified by 5 core values:

| Field | Example | Purpose |
| :--- | :--- | :--- |
| **Source IP** | `192.168.1.100` | Sender host address |
| **Destination IP** | `172.217.14.206` | Destination server address |
| **Source Port** | `54321` | Client application ephemeral identifier |
| **Destination Port**| `443` | Service port (443 = HTTPS, 80 = HTTP, 53 = DNS) |
| **Protocol** | `TCP (6)` | Transport protocol (6 = TCP, 17 = UDP) |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection.
- If we block one packet of a connection, we must consistently block all subsequent packets in that flow.
- This is how stateful conversation tracking between hosts is achieved.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When your browser connects to `https://www.youtube.com`:
1. The browser sends a `Client Hello` message.
2. This message includes the domain name in **plaintext** before cryptographic encryption begins.
3. The server inspects this domain to determine which SSL/TLS certificate to present.

```text
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension (Type 0x0000):
        └── Server Name: "www.youtube.com"  ← DPI Engine extracts THIS!
```

---

## 3. Project Overview

```text
┌─────────────┐     ┌────────────────────────────────────┐     ┌─────────────┐
│  Wireshark  │     │             DPI Engine             │     │   Output    │
│   Capture   │ ──► │  • Zero-copy packet parsing        │ ──► │    PCAP     │
│ (input.pcap)│     │  • Layer 7 SNI / Host extraction   │     │  (filtered) │
└─────────────┘     │  • Multi-threaded Flow Tracking    │     └─────────────┘
                    │  • Policy Firewall & Quarantine    │
                    │  • Interactive Web Dashboard       │
                    └────────────────────────────────────┘
```

### Editions Available:

| Edition | Location | Technology | Best For |
| :--- | :--- | :--- | :--- |
| **Interactive Web App** | `web/` | Next.js 14, React, Vercel | Live browser demo for interviewers, Wireshark 3-pane viewer, live hex dump, PCAP download |
| **Java Multi-Threaded Engine** | `Packet_analyzer/java/` | Pure Java (JDK 11+), zero deps | High-throughput backend processing, cross-platform CLI |
| **C++ Production Engine** | `Packet_analyzer/src/` | C++17, POSIX/Win32 threads | Systems-level reference implementation |

---

## 4. File Structure

```text
network_packet_analyzer/
├── web/                                    # ★ NEXT.JS VERCEL WEB APPLICATION ★
│   ├── src/app/
│   │   ├── page.jsx                        # Interactive dashboard & tab orchestrator
│   │   └── globals.css                     # Cyber dark-mode design system
│   ├── src/components/
│   │   ├── Header.jsx                      # Navigation, demo loader, file upload
│   │   ├── StatsCards.jsx                  # Real-time traffic metric cards
│   │   ├── PacketViewer.jsx                # Wireshark 3-pane dissector & hex dump
│   │   ├── DpiAnalytics.jsx                # App distribution & detected domain charts
│   │   ├── FirewallRules.jsx               # Rule enforcement & binary PCAP exporter
│   │   ├── ThreadArchitecture.jsx          # Multi-core pipeline visualizer
│   │   └── ResumePortfolio.jsx             # Tailored resume bullet points for interviews
│   └── src/lib/
│       ├── pcap-parser.js                  # In-browser binary PCAP & DPI engine
│       └── pcap-writer.js                  # In-browser binary PCAP exporter
│
├── Packet_analyzer/
│   ├── java/                               # ★ PURE JAVA MULTI-THREADED DPI ENGINE ★
│   │   ├── src/main/java/com/dpianalyzer/
│   │   │   ├── Main.java                   # Java CLI entrypoint
│   │   │   ├── model/                      # FiveTuple, AppType, Connection, PacketJob
│   │   │   ├── pcap/                       # PcapReader, PcapWriter, Headers
│   │   │   ├── parser/                     # PacketParser, SniExtractor, HttpHostExtractor
│   │   │   ├── rules/                      # RuleManager (IP, App, Domain wildcard, Port)
│   │   │   ├── tracker/                    # ConnectionTracker (bidirectional flow LRU)
│   │   │   └── engine/                     # FastPathProcessor, LoadBalancer, DpiEngine
│   │   └── pom.xml                         # Maven build configuration
│   │
│   ├── src/                                # C++ Reference Implementation
│   │   ├── main_working.cpp                # Simple single-threaded C++ engine
│   │   └── dpi_mt.cpp                      # Multi-threaded C++ engine
│   └── test_dpi.pcap                       # Sample multi-application capture
│
├── run_web.bat                             # One-click start for Web Dashboard
├── run_java.bat                            # One-click start for Java DPI Engine
└── README.md                               # This documentation
```

---

## 5. The Journey of a Packet (Simple Version)

### Step 1: Read PCAP File
```java
PcapReader reader = new PcapReader("capture.pcap");
```
- Opens the capture in binary stream mode.
- Validates the 24-byte global header (`0xa1b2c3d4` or byte-swapped `0xd4c3b2a1`).
- Configures big-endian or little-endian byte ordering dynamically.

### Step 2: Read Each Packet Header & Frame
```java
while ((raw = reader.readNextPacket()) != null) {
    // raw.data contains the packet bytes
    // raw.header contains timestamps and length
}
```

### Step 3: Parse Protocol Headers
```java
PacketParser.parse(raw, parsed);
```
- **Ethernet (14 bytes)**: Source MAC, Destination MAC, EtherType (`0x0800` = IPv4).
- **IPv4 (20+ bytes)**: Header length, TTL, Protocol (`6` = TCP, `17` = UDP), Source IP, Destination IP.
- **TCP (20+ bytes)**: Ports, Sequence/Ack numbers, Data offset, Flags (`SYN`, `ACK`, `FIN`, `RST`).

### Step 4: Create Five-Tuple & Track Flow
```java
FiveTuple tuple = parsed.toFiveTuple();
Connection conn = tracker.getOrCreateConnection(tuple);
```
- Maps bidirectional traffic `(A:54321 -> B:443)` and `(B:443 -> A:54321)` to the same flow state.

### Step 5: Extract SNI (Deep Packet Inspection)
```java
if (tuple.getDstPort() == 443) {
    String sni = SniExtractor.extract(payload, offset, len);
    if (sni != null) {
        conn.classify(AppType.fromSni(sni), sni);
    }
}
```

### Step 6: Check Blocking Rules
```java
BlockReason reason = ruleManager.shouldBlock(srcIp, dstPort, app, sni);
if (reason != null) {
    conn.block();
}
```

### Step 7: Forward or Drop
```java
if (conn.isBlocked()) {
    droppedCount++; // Do not write to output
} else {
    forwardedCount++;
    writer.writePacket(tsSec, tsUsec, data); // Write to output PCAP
}
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

```text
┌─────────────────┐
│  Reader Thread  │ (Zero-copy binary file read)
└────────┬────────┘
         │
 ┌───────┴───────┐ Consistent Hashing: hash(5-tuple) % num_lbs
 ▼               ▼
┌─────────┐     ┌─────────┐
│   LB0   │     │   LB1   │ (Load Balancer Threads)
└────┬────┘     └────┬────┘
     │               │ Consistent Hashing: hash(5-tuple) % num_fps
 ┌───┴───┐       ┌───┴───┐
 ▼       ▼       ▼       ▼
┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐
│ FP0 │ │ FP1 │ │ FP2 │ │ FP3 │ (Fast Path Worker Threads)
└──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘
   │       │       │       │
   └───────┴───────┴───────┘
               │
               ▼
   ┌───────────────────────┐
   │ Async PCAP Output Q   │
   └───────────┬───────────┘
               ▼
   ┌───────────────────────┐
   │ Output Writer Thread  │ (Writes sanitized .pcap)
   └───────────────────────┘
```

### Why Consistent Hashing Matters:
All packets belonging to the same flow `(IP_A:Port_A <-> IP_B:Port_B)` always hash to the **exact same Fast Path (FP) worker thread**. 
- Eliminates mutex lock contention between worker threads.
- Enables lock-free per-thread flow state tracking and LRU eviction.

---

## 7. Deep Dive: Each Component

- **`PcapReader`**: Handles reading binary PCAP captures across native and swapped endian architectures.
- **`PacketParser`**: Extracts Layer 2 Ethernet, Layer 3 IPv4, and Layer 4 TCP/UDP headers.
- **`SniExtractor`**: Traverses TLS Record and Handshake layers to isolate Extension `0x0000` (SNI hostname).
- **`HttpHostExtractor`**: Scans unencrypted HTTP requests for the `Host:` header.
- **`DnsExtractor`**: Unpacks DNS QNAME labels from UDP/TCP port 53.
- **`RuleManager`**: Thread-safe policy firewall supporting IP, App, Port, and domain wildcard (`*.domain.com`) matching.
- **`ConnectionTracker`**: Manages bidirectional flow records, traffic volume counters, and TCP state transitions.

---

## 8. How SNI Extraction Works

```text
TLS Client Hello Structure:
Byte 0: Content Type = 0x16 (Handshake)
Bytes 1-2: Version = 0x0301 (TLS 1.0) through 0x0304 (TLS 1.3)
Bytes 3-4: Record Length
-- Handshake Layer --
Byte 5: Handshake Type = 0x01 (Client Hello)
Bytes 6-8: Handshake Length
-- Client Hello Body --
Bytes 9-10: Client Version
Bytes 11-42: Random (32 bytes)
Byte 43: Session ID Length (N)
... Cipher Suites Length & Data ...
... Compression Methods Length & Data ...
-- Extensions --
Bytes X to X+1: Extensions Length
  Extension Type: 0x0000 (Server Name Indication)
  Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (Hostname)
  SNI Length: K
  SNI Value: "www.youtube.com"  ← Extracted!
```

---

## 9. How Blocking Works

```text
Packet arrives
      │
      ▼
┌───────────────────────────────┐
│ Is Source IP in blocked list? │─── Yes ──► [DROP PACKET]
└──────────────┬────────────────┘
               │ No
               ▼
┌───────────────────────────────┐
│ Is App Type in blocked list?  │─── Yes ──► [DROP PACKET]
└──────────────┬────────────────┘
               │ No
               ▼
┌───────────────────────────────┐
│ Does SNI match blocked domain?│─── Yes ──► [DROP PACKET]
└──────────────┬────────────────┘
               │ No
               ▼
       [FORWARD PACKET]
```

---

## 10. Building and Running

### Option A: Interactive Web App (Recommended for Demos)

Start the Next.js web application locally:
```cmd
run_web.bat
```
*(Or in Git Bash: `./run_web.sh`)*

Open your browser to: **[http://localhost:3000](http://localhost:3000)**

---

### Option B: Java Multi-Threaded Engine (CLI)

#### Command Prompt (`cmd`) or PowerShell:
```cmd
.\run_java.bat test_dpi.pcap output.pcap --block-app YouTube
```

#### Git Bash:
```bash
./run_java.sh test_dpi.pcap output.pcap --block-app YouTube
```

#### Wireshark-Style Terminal Packet Inspector:
```cmd
.\run_java.bat --inspect test_dpi.pcap 10
```

---

## 11. Understanding the Output

```text
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Java Edition)                  ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[RuleManager] Blocked app: YouTube
Opened PCAP file: test_dpi.pcap (Version: 2.4, Snaplen: 65535 bytes)
[FP0] BLOCKED packet: APP (YouTube)
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ Total Bytes:                5738                             ║
║ TCP Packets:                  77                             ║
║ UDP Packets:                   0                             ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    76                             ║
║ Dropped:                       1                             ║
╠══════════════════════════════════════════════════════════════╣
║ APPLICATION BREAKDOWN                                        ║
╠══════════════════════════════════════════════════════════════╣
║ Unknown               12   15.6% ###                         ║
║ Google                 4    5.2% #                           ║
║ Facebook               4    5.2% #                           ║
║ Twitter/X              4    5.2% #                           ║
║ Amazon                 4    5.2% #                           ║
║ Microsoft              4    5.2% #                           ║
║ Apple                  4    5.2% #                           ║
║ YouTube                3    3.9% (BLOCKED)                   ║
║ Netflix                3    3.9%                             ║
║ TikTok                 3    3.9%                             ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 12. Deploying to Vercel (Live Web Dashboard)

1. Push your repository to **GitHub**:
   ```bash
   git add .
   git commit -m "feat: DPI Engine with Java core and Vercel Next.js web app"
   git push origin main
   ```
2. Log into [Vercel](https://vercel.com) and click **"Add New" $\rightarrow$ "Project"**.
3. Import this GitHub repository.
4. Set the **Root Directory** to `web`.
5. Click **"Deploy"**! In ~60 seconds, your interactive Wireshark-grade packet analyzer will be live online.

---

## 13. Resume & Interview Highlights

Copy these bullet points directly onto your software engineering resume:

- **Engineered a multi-threaded Deep Packet Inspection (DPI) & Traffic Analyzer** in Java/C++ capable of parsing binary PCAP network captures and classifying Layer 7 protocols with sub-millisecond latency.
- **Designed a high-throughput pipeline** utilizing consistent 5-tuple hashing to distribute network flows across parallel Fast Path worker threads without mutex contention.
- **Implemented zero-copy binary parsers** for Ethernet II, IPv4, TCP, and UDP headers, accurately tracking bidirectional flow state and TCP flag handshakes (SYN, ACK, FIN, RST).
- **Built an L7 inspection engine** extracting TLS Server Name Indication (SNI), HTTP Host headers, and DNS queries to categorize traffic across 20+ major enterprise applications.
- **Developed an interactive Next.js web application deployed to Vercel** featuring Wireshark-grade 3-pane packet dissection, live hex dump viewer, and an in-browser PCAP exporter.
