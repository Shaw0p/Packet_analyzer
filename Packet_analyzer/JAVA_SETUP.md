# Packet Analyzer & DPI Engine (Java Edition)

The entire C++ Deep Packet Inspection (DPI) & Packet Analyzer codebase has been completely rewritten in **modern, pure Java** (JDK 11+). It requires **zero external third-party dependencies**—using only standard Java libraries (`java.nio`, `java.util.concurrent`, etc.).

---

## 🚀 Features

- **Full PCAP Parser & Writer**:
  - Binary `.pcap` reading & writing with automatic endianness detection (native `0xa1b2c3d4` & swapped `0xd4c3b2a1`).
  - Supports Ethernet (Layer 2), IPv4 (Layer 3), and TCP / UDP (Layer 4).
- **Deep Packet Inspection (Layer 7 DPI)**:
  - **TLS Server Name Indication (SNI)** extraction from Client Hello handshakes (identifies YouTube, Google, Facebook, Instagram, Twitter/X, Netflix, Amazon, Microsoft, TikTok, Discord, Spotify, etc.).
  - **HTTP Host** header extraction for plaintext HTTP traffic.
  - **DNS Query (QNAME)** extraction for port 53 traffic.
- **Multi-threaded Architecture**:
  - Consistent hashing of Five-Tuple flows (`FiveTupleHash`) across **Load Balancer (LB)** threads.
  - Independent **Fast Path (FP)** processing threads for flow state tracking, LRU eviction, and rule matching.
  - Asynchronous non-blocking PCAP file writer thread.
- **Rule Filtering Engine**:
  - Block by Source IP (`--block-ip <ip>`).
  - Block by Application Name (`--block-app <app>` e.g., `YouTube`, `Facebook`).
  - Block by Domain / Subdomain pattern (`--block-domain <pattern>` e.g., `*.tiktok.com`).
  - Block by Destination Port (`--block-port <port>`).

---

## 📁 Project Structure

```
Packet_analyzer/
├── java/
│   ├── pom.xml                                    # Maven project configuration
│   ├── compile.bat                                # Quick compilation script
│   ├── run.bat                                    # Quick run script
│   └── src/main/java/com/dpianalyzer/
│       ├── Main.java                              # Main CLI entrypoint
│       ├── model/
│       │   ├── FiveTuple.java                     # 5-tuple flow identifier
│       │   ├── AppType.java                       # Application taxonomy & SNI matcher
│       │   ├── Connection.java                    # Flow tracking entry
│       │   ├── ConnectionState.java               # NEW, ESTABLISHED, CLASSIFIED, etc.
│       │   ├── PacketAction.java                  # FORWARD, DROP, INSPECT
│       │   ├── RawPacket.java                     # Raw packet wrapper
│       │   ├── ParsedPacket.java                  # Dissected protocol fields
│       │   └── PacketJob.java                     # Worker queue packet job
│       ├── pcap/
│       │   ├── PcapGlobalHeader.java              # 24-byte PCAP header
│       │   ├── PcapPacketHeader.java              # 16-byte packet header
│       │   ├── PcapReader.java                    # PCAP binary reader
│       │   └── PcapWriter.java                    # PCAP binary writer
│       ├── parser/
│       │   ├── PacketParser.java                  # Ethernet / IPv4 / TCP / UDP parser
│       │   ├── SniExtractor.java                  # TLS Client Hello SNI parser
│       │   ├── HttpHostExtractor.java             # HTTP Host header parser
│       │   └── DnsExtractor.java                  # DNS QNAME query parser
│       ├── rules/
│       │   └── RuleManager.java                   # Thread-safe filtering rules & INI loader
│       ├── tracker/
│       │   └── ConnectionTracker.java             # Bidirectional flow tracker & LRU
│       └── engine/
│           ├── FastPathProcessor.java             # Fast Path worker thread
│           ├── LoadBalancer.java                  # Consistent hashing LB worker
│           └── DpiEngine.java                     # Multi-threaded DPI engine coordinator
├── compile_java.bat                               # Root 1-click compile script
├── run_java.bat                                   # Root 1-click run script
├── test_dpi.pcap                                  # Sample input capture
└── output.pcap                                    # Output filtered capture
```

---

## 💻 How to Run

### Method 1: Quick Batch Scripts (Windows CMD or PowerShell)

From the `Packet_analyzer` directory:

1. **Compile the Java code**:
   ```cmd
   compile_java.bat
   ```

2. **Run DPI Engine (Multi-threaded Deep Packet Inspection & Filtering)**:
   ```cmd
   run_java.bat test_dpi.pcap filtered_output.pcap
   ```

3. **Run with Application Blocking**:
   ```cmd
   run_java.bat test_dpi.pcap filtered_output.pcap --block-app YouTube
   ```

4. **Run with IP or Domain Blocking**:
   ```cmd
   run_java.bat test_dpi.pcap filtered_output.pcap --block-ip 192.168.1.100 --block-domain *.facebook.com
   ```

5. **Inspect & Dissect Packets (First 10 packets)**:
   ```cmd
   run_java.bat --inspect test_dpi.pcap 10
   ```

---

### Method 2: Using Maven

1. Navigate to the `java` directory:
   ```cmd
   cd java
   mvn clean package
   ```

2. Run the generated JAR:
   ```cmd
   java -jar target/packet-analyzer-2.0.0.jar ..\test_dpi.pcap ..\filtered_output.pcap --block-app YouTube
   ```

---

### Method 3: Direct `javac` / `java`

```cmd
cd java
javac -d bin src\main\java\com\dpianalyzer\*.java src\main\java\com\dpianalyzer\model\*.java src\main\java\com\dpianalyzer\pcap\*.java src\main\java\com\dpianalyzer\parser\*.java src\main\java\com\dpianalyzer\rules\*.java src\main\java\com\dpianalyzer\tracker\*.java src\main\java\com\dpianalyzer\engine\*.java
java -cp bin com.dpianalyzer.Main ..\test_dpi.pcap ..\filtered.pcap
```
