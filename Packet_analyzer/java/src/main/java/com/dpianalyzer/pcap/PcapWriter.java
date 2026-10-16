package com.dpianalyzer.pcap;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes packets to a .pcap file in standard binary PCAP format.
 */
public class PcapWriter implements AutoCloseable {
    private final OutputStream outputStream;
    private final ByteOrder byteOrder;
    private boolean closed = false;

    public PcapWriter(String filename, PcapGlobalHeader header, ByteOrder byteOrder) throws IOException {
        this(new File(filename), header, byteOrder);
    }

    public PcapWriter(File file, PcapGlobalHeader header, ByteOrder byteOrder) throws IOException {
        this.outputStream = new BufferedOutputStream(new FileOutputStream(file));
        this.byteOrder = byteOrder != null ? byteOrder : ByteOrder.LITTLE_ENDIAN;
        writeGlobalHeader(header != null ? header : new PcapGlobalHeader());
    }

    public PcapWriter(OutputStream os, PcapGlobalHeader header, ByteOrder byteOrder) throws IOException {
        this.outputStream = new BufferedOutputStream(os);
        this.byteOrder = byteOrder != null ? byteOrder : ByteOrder.LITTLE_ENDIAN;
        writeGlobalHeader(header != null ? header : new PcapGlobalHeader());
    }

    private void writeGlobalHeader(PcapGlobalHeader header) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(PcapGlobalHeader.HEADER_SIZE).order(byteOrder);
        buf.putInt(header.getMagicNumber());
        buf.putShort((short) header.getVersionMajor());
        buf.putShort((short) header.getVersionMinor());
        buf.putInt(header.getThisZone());
        buf.putInt(header.getSigFigs());
        buf.putInt(header.getSnapLen());
        buf.putInt(header.getNetwork());
        outputStream.write(buf.array());
    }

    public synchronized void writePacket(int tsSec, int tsUsec, byte[] packetData) throws IOException {
        if (closed || packetData == null) return;

        ByteBuffer buf = ByteBuffer.allocate(PcapPacketHeader.HEADER_SIZE).order(byteOrder);
        buf.putInt(tsSec);
        buf.putInt(tsUsec);
        buf.putInt(packetData.length);
        buf.putInt(packetData.length);

        outputStream.write(buf.array());
        outputStream.write(packetData);
    }

    public synchronized void flush() throws IOException {
        if (!closed) {
            outputStream.flush();
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (!closed) {
            closed = true;
            outputStream.flush();
            outputStream.close();
        }
    }
}
