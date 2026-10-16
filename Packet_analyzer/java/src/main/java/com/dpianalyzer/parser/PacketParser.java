package com.dpianalyzer.parser;

import com.dpianalyzer.model.ParsedPacket;
import com.dpianalyzer.model.RawPacket;

/**
 * Protocol parser for Ethernet, IPv4, TCP, and UDP network packets.
 */
public class PacketParser {
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP  = 0x0806;

    public static final int PROTOCOL_ICMP = 1;
    public static final int PROTOCOL_TCP  = 6;
    public static final int PROTOCOL_UDP  = 17;

    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        if (raw == null || raw.getData() == null) return false;

        byte[] data = raw.getData();
        int len = data.length;

        parsed.setTimestampSec(raw.getHeader().getTsSec());
        parsed.setTimestampUsec(raw.getHeader().getTsUsec());
        parsed.setRawData(data);

        int offset = 0;

        // Parse Ethernet (14 bytes)
        if (len < 14) return false;

        parsed.setDestMac(macToString(data, 0));
        parsed.setSrcMac(macToString(data, 6));
        int etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        parsed.setEtherType(etherType);
        offset = 14;

        // Parse IPv4
        if (etherType == ETHERTYPE_IPV4) {
            if (len < offset + 20) return false;

            int versionIhl = data[offset] & 0xFF;
            int version = (versionIhl >> 4) & 0x0F;
            int ihl = versionIhl & 0x0F;

            if (version != 4) return false;
            int ipHeaderLen = ihl * 4;
            if (ipHeaderLen < 20 || len < offset + ipHeaderLen) return false;

            parsed.setIpVersion(4);
            parsed.setTtl(data[offset + 8] & 0xFF);
            int protocol = data[offset + 9] & 0xFF;
            parsed.setProtocol(protocol);

            // Read IPv4 addresses (stored as 32-bit int in little-endian octet order)
            int srcIp = (data[offset + 12] & 0xFF) |
                    ((data[offset + 13] & 0xFF) << 8) |
                    ((data[offset + 14] & 0xFF) << 16) |
                    ((data[offset + 15] & 0xFF) << 24);

            int dstIp = (data[offset + 16] & 0xFF) |
                    ((data[offset + 17] & 0xFF) << 8) |
                    ((data[offset + 18] & 0xFF) << 16) |
                    ((data[offset + 19] & 0xFF) << 24);

            parsed.setSrcIpInt(srcIp);
            parsed.setDestIpInt(dstIp);
            parsed.setSrcIp(ipToString(srcIp));
            parsed.setDestIp(ipToString(dstIp));
            parsed.setHasIp(true);

            offset += ipHeaderLen;

            // Transport Layer
            if (protocol == PROTOCOL_TCP) {
                if (len < offset + 20) return false;

                int srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                int dstPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
                long seq = (((long) data[offset + 4] & 0xFF) << 24) |
                           (((long) data[offset + 5] & 0xFF) << 16) |
                           (((long) data[offset + 6] & 0xFF) << 8) |
                           ((long) data[offset + 7] & 0xFF);
                long ack = (((long) data[offset + 8] & 0xFF) << 24) |
                           (((long) data[offset + 9] & 0xFF) << 16) |
                           (((long) data[offset + 10] & 0xFF) << 8) |
                           ((long) data[offset + 11] & 0xFF);

                int dataOffset = (data[offset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = dataOffset * 4;
                int flags = data[offset + 13] & 0xFF;

                if (tcpHeaderLen < 20 || len < offset + tcpHeaderLen) return false;

                parsed.setHasTcp(true);
                parsed.setSrcPort(srcPort);
                parsed.setDestPort(dstPort);
                parsed.setSeqNumber(seq);
                parsed.setAckNumber(ack);
                parsed.setTcpFlags(flags);

                offset += tcpHeaderLen;
            } else if (protocol == PROTOCOL_UDP) {
                if (len < offset + 8) return false;

                int srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                int dstPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);

                parsed.setHasUdp(true);
                parsed.setSrcPort(srcPort);
                parsed.setDestPort(dstPort);

                offset += 8;
            }
        }

        // Payload
        if (offset < len) {
            parsed.setPayloadOffset(offset);
            parsed.setPayloadLength(len - offset);
        } else {
            parsed.setPayloadOffset(len);
            parsed.setPayloadLength(0);
        }

        return true;
    }

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip & 0xFF),
                ((ip >> 8) & 0xFF),
                ((ip >> 16) & 0xFF),
                ((ip >> 24) & 0xFF));
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case PROTOCOL_ICMP: return "ICMP";
            case PROTOCOL_TCP:  return "TCP";
            case PROTOCOL_UDP:  return "UDP";
            default:            return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        String res = sb.toString().trim();
        return res.isEmpty() ? "none" : res;
    }
}
