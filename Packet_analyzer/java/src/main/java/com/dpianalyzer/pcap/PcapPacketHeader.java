package com.dpianalyzer.pcap;

/**
 * PCAP Packet Header (16 bytes).
 * Precedes each captured packet payload in the .pcap file.
 */
public class PcapPacketHeader {
    public static final int HEADER_SIZE = 16;

    private int tsSec;    // Timestamp seconds
    private int tsUsec;   // Timestamp microseconds
    private int inclLen;  // Captured length in file
    private int origLen;  // Actual length of packet on wire

    public PcapPacketHeader() {}

    public PcapPacketHeader(int tsSec, int tsUsec, int inclLen, int origLen) {
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
    }

    public int getTsSec() { return tsSec; }
    public void setTsSec(int tsSec) { this.tsSec = tsSec; }

    public int getTsUsec() { return tsUsec; }
    public void setTsUsec(int tsUsec) { this.tsUsec = tsUsec; }

    public int getInclLen() { return inclLen; }
    public void setInclLen(int inclLen) { this.inclLen = inclLen; }

    public int getOrigLen() { return origLen; }
    public void setOrigLen(int origLen) { this.origLen = origLen; }
}
