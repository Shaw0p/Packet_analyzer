package com.dpianalyzer.model;

import java.util.Objects;

/**
 * FiveTuple uniquely identifies a bidirectional network connection/flow.
 * (Source IP, Destination IP, Source Port, Destination Port, Protocol)
 */
public class FiveTuple {
    private final int srcIp;       // Stored as 32-bit int
    private final int dstIp;
    private final int srcPort;     // 0 - 65535
    private final int dstPort;     // 0 - 65535
    private final int protocol;    // 6 = TCP, 17 = UDP, 1 = ICMP

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort & 0xFFFF;
        this.dstPort = dstPort & 0xFFFF;
        this.protocol = protocol & 0xFF;
    }

    public int getSrcIp() {
        return srcIp;
    }

    public int getDstIp() {
        return dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public static String ipToString(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip & 0xFF),
                ((ip >> 8) & 0xFF),
                ((ip >> 16) & 0xFF),
                ((ip >> 24) & 0xFF));
    }

    public static int parseIp(String ipStr) {
        if (ipStr == null || ipStr.trim().isEmpty()) {
            return 0;
        }
        String[] parts = ipStr.trim().split("\\.");
        if (parts.length != 4) {
            return 0;
        }
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(parts[i].trim()) & 0xFF;
            result |= (octet << (i * 8));
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple fiveTuple = (FiveTuple) o;
        return srcIp == fiveTuple.srcIp &&
                dstIp == fiveTuple.dstIp &&
                srcPort == fiveTuple.srcPort &&
                dstPort == fiveTuple.dstPort &&
                protocol == fiveTuple.protocol;
    }

    @Override
    public int hashCode() {
        int h = 0;
        h ^= Integer.hashCode(srcIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(srcPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(dstPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }

    @Override
    public String toString() {
        String protoStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : ("Proto(" + protocol + ")");
        return ipToString(srcIp) + ":" + srcPort + " -> " + ipToString(dstIp) + ":" + dstPort + " (" + protoStr + ")";
    }
}
