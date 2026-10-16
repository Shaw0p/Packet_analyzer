package com.dpianalyzer.model;

/**
 * Self-contained packet unit passed through queues between Reader, Load Balancers, and Fast Path workers.
 */
public class PacketJob {
    private final int id;
    private final int tsSec;
    private final int tsUsec;
    private final FiveTuple tuple;
    private final byte[] data;
    private final int tcpFlags;
    private final int payloadOffset;
    private final int payloadLength;

    public PacketJob(int id, int tsSec, int tsUsec, FiveTuple tuple, byte[] data,
                     int tcpFlags, int payloadOffset, int payloadLength) {
        this.id = id;
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.tuple = tuple;
        this.data = data;
        this.tcpFlags = tcpFlags;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
    }

    public int getId() { return id; }
    public int getTsSec() { return tsSec; }
    public int getTsUsec() { return tsUsec; }
    public FiveTuple getTuple() { return tuple; }
    public byte[] getData() { return data; }
    public int getTcpFlags() { return tcpFlags; }
    public int getPayloadOffset() { return payloadOffset; }
    public int getPayloadLength() { return payloadLength; }
}
