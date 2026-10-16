package com.dpianalyzer;

import com.dpianalyzer.engine.DpiEngine;
import com.dpianalyzer.model.ParsedPacket;
import com.dpianalyzer.model.RawPacket;
import com.dpianalyzer.parser.PacketParser;
import com.dpianalyzer.pcap.PcapReader;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Main entrypoint for Packet Analyzer & DPI Engine in Java.
 */
public class Main {

    public static void printUsage() {
        System.out.println(
            "Packet Analyzer & DPI Engine (Java Edition)\n" +
            "===========================================\n\n" +
            "Usage Mode 1 - Deep Packet Inspection & Filtering:\n" +
            "  java -cp target/classes com.dpianalyzer.Main <input.pcap> <output.pcap> [options]\n\n" +
            "Options:\n" +
            "  --block-ip <ip>        Block source IP address (e.g., 192.168.1.50)\n" +
            "  --block-app <app>      Block application (YouTube, Facebook, Netflix, etc.)\n" +
            "  --block-domain <dom>   Block domain substring or pattern (e.g., *.tiktok.com)\n" +
            "  --block-port <port>    Block destination port (e.g., 443)\n" +
            "  --lbs <n>              Number of load balancer threads (default: 2)\n" +
            "  --fps <n>              Fast path threads per LB (default: 2)\n\n" +
            "Usage Mode 2 - Packet Inspection & Dissection Summary:\n" +
            "  java -cp target/classes com.dpianalyzer.Main --inspect <pcap_file> [max_packets]\n\n" +
            "Examples:\n" +
            "  java -jar dpi-engine.jar test_dpi.pcap filtered.pcap --block-app YouTube\n" +
            "  java -jar dpi-engine.jar --inspect test_dpi.pcap 10\n"
        );
    }

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equalsIgnoreCase("--help") || args[0].equalsIgnoreCase("-h")) {
            printUsage();
            return;
        }

        // Mode 2: Packet Inspection
        if (args[0].equalsIgnoreCase("--inspect")) {
            if (args.length < 2) {
                System.err.println("Error: Please provide a pcap file to inspect.");
                printUsage();
                return;
            }
            String pcapFile = args[1];
            int maxPackets = (args.length >= 3) ? Integer.parseInt(args[2]) : -1;
            runPacketInspector(pcapFile, maxPackets);
            return;
        }

        // Mode 1: DPI Engine
        if (args.length < 2) {
            printUsage();
            return;
        }

        String inputPcap = args[0];
        String outputPcap = args[1];

        DpiEngine.Config config = new DpiEngine.Config(2, 2);
        DpiEngine engine = new DpiEngine(config);

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equalsIgnoreCase("--block-ip") && i + 1 < args.length) {
                engine.blockIp(args[++i]);
            } else if (arg.equalsIgnoreCase("--block-app") && i + 1 < args.length) {
                engine.blockApp(args[++i]);
            } else if (arg.equalsIgnoreCase("--block-domain") && i + 1 < args.length) {
                engine.blockDomain(args[++i]);
            } else if (arg.equalsIgnoreCase("--block-port") && i + 1 < args.length) {
                engine.blockPort(Integer.parseInt(args[++i]));
            } else if (arg.equalsIgnoreCase("--lbs") && i + 1 < args.length) {
                config.numLbs = Integer.parseInt(args[++i]);
            } else if (arg.equalsIgnoreCase("--fps") && i + 1 < args.length) {
                config.fpsPerLb = Integer.parseInt(args[++i]);
            }
        }

        boolean success = engine.process(inputPcap, outputPcap);
        if (!success) {
            System.exit(1);
        }
    }

    private static void runPacketInspector(String filename, int maxPackets) {
        System.out.println("====================================");
        System.out.println("     Packet Analyzer v1.0 (Java)    ");
        System.out.println("====================================\n");

        File file = new File(filename);
        if (!file.exists()) {
            System.err.println("File not found: " + filename);
            return;
        }

        try (PcapReader reader = new PcapReader(file)) {
            System.out.println("\n--- Reading and Parsing Packets ---\n");

            RawPacket raw;
            ParsedPacket parsed = new ParsedPacket();
            int count = 0;
            int parseErrors = 0;
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

            while ((raw = reader.readNextPacket()) != null) {
                count++;
                if (PacketParser.parse(raw, parsed)) {
                    printPacketDetails(parsed, count, sdf);
                } else {
                    System.err.println("Warning: Failed to parse packet #" + count);
                    parseErrors++;
                }

                if (maxPackets > 0 && count >= maxPackets) {
                    System.out.println("\n(Stopped after " + maxPackets + " packets)");
                    break;
                }
            }

            System.out.println("\n====================================");
            System.out.println("Summary:");
            System.out.println("  Total packets read:  " + count);
            System.out.println("  Parse errors:        " + parseErrors);
            System.out.println("====================================");

        } catch (Exception e) {
            System.err.println("Error reading pcap: " + e.getMessage());
        }
    }

    private static void printPacketDetails(ParsedPacket pkt, int num, SimpleDateFormat sdf) {
        Date date = new Date(((long) pkt.getTimestampSec()) * 1000);
        System.out.println("\n========== Packet #" + num + " ==========");
        System.out.println("Time: " + sdf.format(date) + "." + String.format("%06d", pkt.getTimestampUsec()));

        // Ethernet
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.getSrcMac());
        System.out.println("  Destination MAC: " + pkt.getDestMac());
        String ethTypeStr = (pkt.getEtherType() == PacketParser.ETHERTYPE_IPV4) ? " (IPv4)" :
                            (pkt.getEtherType() == PacketParser.ETHERTYPE_IPV6) ? " (IPv6)" :
                            (pkt.getEtherType() == PacketParser.ETHERTYPE_ARP) ? " (ARP)" : "";
        System.out.println(String.format("  EtherType:       0x%04X%s", pkt.getEtherType(), ethTypeStr));

        // IP
        if (pkt.hasIp()) {
            System.out.println("\n[IPv" + pkt.getIpVersion() + "]");
            System.out.println("  Source IP:      " + pkt.getSrcIp());
            System.out.println("  Destination IP: " + pkt.getDestIp());
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.getProtocol()));
            System.out.println("  TTL:            " + pkt.getTtl());
        }

        // TCP
        if (pkt.hasTcp()) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.getSrcPort());
            System.out.println("  Destination Port: " + pkt.getDestPort());
            System.out.println("  Sequence Number:  " + pkt.getSeqNumber());
            System.out.println("  Ack Number:       " + pkt.getAckNumber());
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.getTcpFlags()));
        }

        // UDP
        if (pkt.hasUdp()) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.getSrcPort());
            System.out.println("  Destination Port: " + pkt.getDestPort());
        }

        // Payload
        if (pkt.getPayloadLength() > 0) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.getPayloadLength() + " bytes");
            System.out.print("  Preview: ");
            byte[] raw = pkt.getRawData();
            int offset = pkt.getPayloadOffset();
            int previewLen = Math.min(pkt.getPayloadLength(), 32);
            for (int i = 0; i < previewLen; i++) {
                System.out.print(String.format("%02x ", raw[offset + i] & 0xFF));
            }
            if (pkt.getPayloadLength() > 32) {
                System.out.print("...");
            }
            System.out.println();
        }
    }
}
