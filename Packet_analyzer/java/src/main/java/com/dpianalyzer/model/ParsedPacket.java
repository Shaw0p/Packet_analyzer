package com.dpianalyzer.model;

/**
 * Parsed packet information across Ethernet, IP, and Transport layers.
 */
public class ParsedPacket {
    // Timestamps
    private int timestampSec;
    private int timestampUsec;

    // Ethernet layer
    private String srcMac = "";
    private String destMac = "";
    private int etherType; // 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP

    // IP layer
    private boolean hasIp = false;
    private int ipVersion = 4;
    private int srcIpInt;
    private int destIpInt;
    private String srcIp = "";
    private String destIp = "";
    private int protocol; // 6 = TCP, 17 = UDP, 1 = ICMP
    private int ttl;

    // Transport layer
    private boolean hasTcp = false;
    private boolean hasUdp = false;
    private int srcPort;
    private int destPort;

    // TCP-specific
    private int tcpFlags;
    private long seqNumber;
    private long ackNumber;

    // Payload
    private int payloadOffset;
    private int payloadLength;
    private byte[] rawData;

    public ParsedPacket() {}

    public int getTimestampSec() { return timestampSec; }
    public void setTimestampSec(int timestampSec) { this.timestampSec = timestampSec; }

    public int getTimestampUsec() { return timestampUsec; }
    public void setTimestampUsec(int timestampUsec) { this.timestampUsec = timestampUsec; }

    public String getSrcMac() { return srcMac; }
    public void setSrcMac(String srcMac) { this.srcMac = srcMac; }

    public String getDestMac() { return destMac; }
    public void setDestMac(String destMac) { this.destMac = destMac; }

    public int getEtherType() { return etherType; }
    public void setEtherType(int etherType) { this.etherType = etherType; }

    public boolean hasIp() { return hasIp; }
    public void setHasIp(boolean hasIp) { this.hasIp = hasIp; }

    public int getIpVersion() { return ipVersion; }
    public void setIpVersion(int ipVersion) { this.ipVersion = ipVersion; }

    public int getSrcIpInt() { return srcIpInt; }
    public void setSrcIpInt(int srcIpInt) { this.srcIpInt = srcIpInt; }

    public int getDestIpInt() { return destIpInt; }
    public void setDestIpInt(int destIpInt) { this.destIpInt = destIpInt; }

    public String getSrcIp() { return srcIp; }
    public void setSrcIp(String srcIp) { this.srcIp = srcIp; }

    public String getDestIp() { return destIp; }
    public void setDestIp(String destIp) { this.destIp = destIp; }

    public int getProtocol() { return protocol; }
    public void setProtocol(int protocol) { this.protocol = protocol; }

    public int getTtl() { return ttl; }
    public void setTtl(int ttl) { this.ttl = ttl; }

    public boolean hasTcp() { return hasTcp; }
    public void setHasTcp(boolean hasTcp) { this.hasTcp = hasTcp; }

    public boolean hasUdp() { return hasUdp; }
    public void setHasUdp(boolean hasUdp) { this.hasUdp = hasUdp; }

    public int getSrcPort() { return srcPort; }
    public void setSrcPort(int srcPort) { this.srcPort = srcPort; }

    public int getDestPort() { return destPort; }
    public void setDestPort(int destPort) { this.destPort = destPort; }

    public int getTcpFlags() { return tcpFlags; }
    public void setTcpFlags(int tcpFlags) { this.tcpFlags = tcpFlags; }

    public long getSeqNumber() { return seqNumber; }
    public void setSeqNumber(long seqNumber) { this.seqNumber = seqNumber; }

    public long getAckNumber() { return ackNumber; }
    public void setAckNumber(long ackNumber) { this.ackNumber = ackNumber; }

    public int getPayloadOffset() { return payloadOffset; }
    public void setPayloadOffset(int payloadOffset) { this.payloadOffset = payloadOffset; }

    public int getPayloadLength() { return payloadLength; }
    public void setPayloadLength(int payloadLength) { this.payloadLength = payloadLength; }

    public byte[] getRawData() { return rawData; }
    public void setRawData(byte[] rawData) { this.rawData = rawData; }

    public FiveTuple toFiveTuple() {
        return new FiveTuple(srcIpInt, destIpInt, srcPort, destPort, protocol);
    }
}
