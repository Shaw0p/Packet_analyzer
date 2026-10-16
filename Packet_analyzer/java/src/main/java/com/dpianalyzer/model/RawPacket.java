package com.dpianalyzer.model;

import com.dpianalyzer.pcap.PcapPacketHeader;

/**
 * Represents a single captured packet with its header and raw bytes.
 */
public class RawPacket {
    private PcapPacketHeader header;
    private byte[] data;

    public RawPacket() {}

    public RawPacket(PcapPacketHeader header, byte[] data) {
        this.header = header;
        this.data = data;
    }

    public PcapPacketHeader getHeader() {
        return header;
    }

    public void setHeader(PcapPacketHeader header) {
        this.header = header;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }
}
