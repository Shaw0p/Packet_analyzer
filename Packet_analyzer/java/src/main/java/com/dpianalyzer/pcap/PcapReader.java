package com.dpianalyzer.pcap;

import com.dpianalyzer.model.RawPacket;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Robust PCAP stream reader supporting both native and swapped byte order PCAP captures.
 */
public class PcapReader implements AutoCloseable {
    private final InputStream inputStream;
    private final String filename;
    private PcapGlobalHeader globalHeader;
    private ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
    private boolean open = false;

    public PcapReader(String filename) throws IOException {
        this.filename = filename;
        this.inputStream = new BufferedInputStream(new FileInputStream(filename));
        init();
    }

    public PcapReader(File file) throws IOException {
        this.filename = file.getName();
        this.inputStream = new BufferedInputStream(new FileInputStream(file));
        init();
    }

    public PcapReader(InputStream is, String name) throws IOException {
        this.filename = name;
        this.inputStream = new BufferedInputStream(is);
        init();
    }

    private void init() throws IOException {
        byte[] ghBytes = readExactly(PcapGlobalHeader.HEADER_SIZE);
        if (ghBytes == null) {
            throw new IOException("Unable to read PCAP global header from: " + filename);
        }

        ByteBuffer buf = ByteBuffer.wrap(ghBytes);
        int magicRaw = buf.getInt(); // read big-endian first to test

        if (magicRaw == 0xa1b2c3d4 || magicRaw == 0xa1b23c4d) {
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else if (magicRaw == 0xd4c3b2a1 || magicRaw == 0x4d3cb2a1) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            // Check little endian interpretation
            buf.order(ByteOrder.LITTLE_ENDIAN);
            buf.position(0);
            int magicLe = buf.getInt();
            if (magicLe == 0xa1b2c3d4 || magicLe == 0xa1b23c4d) {
                byteOrder = ByteOrder.LITTLE_ENDIAN;
            } else {
                throw new IOException(String.format("Invalid PCAP magic number: 0x%08X in %s", magicRaw, filename));
            }
        }

        buf.order(byteOrder);
        buf.position(0);
        int magic = buf.getInt();
        int vMajor = buf.getShort() & 0xFFFF;
        int vMinor = buf.getShort() & 0xFFFF;
        int thisZone = buf.getInt();
        int sigFigs = buf.getInt();
        int snapLen = buf.getInt();
        int network = buf.getInt();

        this.globalHeader = new PcapGlobalHeader(magic, vMajor, vMinor, thisZone, sigFigs, snapLen, network);
        this.open = true;

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + vMajor + "." + vMinor);
        System.out.println("  Snaplen: " + snapLen + " bytes");
        System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));
        System.out.println("  Byte order: " + byteOrder);
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public ByteOrder getByteOrder() {
        return byteOrder;
    }

    public boolean isOpen() {
        return open;
    }

    public RawPacket readNextPacket() throws IOException {
        if (!open) return null;

        byte[] phBytes = readExactly(PcapPacketHeader.HEADER_SIZE);
        if (phBytes == null) {
            return null; // EOF
        }

        ByteBuffer buf = ByteBuffer.wrap(phBytes).order(byteOrder);
        int tsSec = buf.getInt();
        int tsUsec = buf.getInt();
        int inclLen = buf.getInt();
        int origLen = buf.getInt();

        if (inclLen < 0 || inclLen > 65535 || (globalHeader.getSnapLen() > 0 && inclLen > globalHeader.getSnapLen() * 2)) {
            System.err.println("Warning: Invalid or corrupted packet length encountered: " + inclLen);
            return null;
        }

        byte[] data = readExactly(inclLen);
        if (data == null) {
            System.err.println("Warning: Unexpected EOF while reading packet payload of length: " + inclLen);
            return null;
        }

        PcapPacketHeader header = new PcapPacketHeader(tsSec, tsUsec, inclLen, origLen);
        return new RawPacket(header, data);
    }

    private byte[] readExactly(int len) throws IOException {
        byte[] buffer = new byte[len];
        int totalRead = 0;
        while (totalRead < len) {
            int read = inputStream.read(buffer, totalRead, len - totalRead);
            if (read == -1) {
                if (totalRead == 0) return null;
                throw new EOFException("Truncated PCAP data: expected " + len + " bytes, got " + totalRead);
            }
            totalRead += read;
        }
        return buffer;
    }

    @Override
    public void close() throws IOException {
        open = false;
        if (inputStream != null) {
            inputStream.close();
        }
    }
}
