package com.dpianalyzer.pcap;

/**
 * PCAP Global Header (24 bytes).
 * Appears at the beginning of every .pcap capture file.
 */
public class PcapGlobalHeader {
    public static final int MAGIC_NATIVE = 0xa1b2c3d4;
    public static final int MAGIC_SWAPPED = 0xd4c3b2a1;
    public static final int HEADER_SIZE = 24;

    private int magicNumber;
    private int versionMajor; // 2
    private int versionMinor; // 4
    private int thisZone;     // GMT offset (usually 0)
    private int sigFigs;      // Timestamp accuracy (usually 0)
    private int snapLen;      // Max capture length
    private int network;      // Data link type (1 = Ethernet)

    public PcapGlobalHeader() {
        this.magicNumber = MAGIC_NATIVE;
        this.versionMajor = 2;
        this.versionMinor = 4;
        this.thisZone = 0;
        this.sigFigs = 0;
        this.snapLen = 65535;
        this.network = 1; // Ethernet
    }

    public PcapGlobalHeader(int magicNumber, int versionMajor, int versionMinor,
                            int thisZone, int sigFigs, int snapLen, int network) {
        this.magicNumber = magicNumber;
        this.versionMajor = versionMajor;
        this.versionMinor = versionMinor;
        this.thisZone = thisZone;
        this.sigFigs = sigFigs;
        this.snapLen = snapLen;
        this.network = network;
    }

    public int getMagicNumber() { return magicNumber; }
    public void setMagicNumber(int magicNumber) { this.magicNumber = magicNumber; }

    public int getVersionMajor() { return versionMajor; }
    public void setVersionMajor(int versionMajor) { this.versionMajor = versionMajor; }

    public int getVersionMinor() { return versionMinor; }
    public void setVersionMinor(int versionMinor) { this.versionMinor = versionMinor; }

    public int getThisZone() { return thisZone; }
    public void setThisZone(int thisZone) { this.thisZone = thisZone; }

    public int getSigFigs() { return sigFigs; }
    public void setSigFigs(int sigFigs) { this.sigFigs = sigFigs; }

    public int getSnapLen() { return snapLen; }
    public void setSnapLen(int snapLen) { this.snapLen = snapLen; }

    public int getNetwork() { return network; }
    public void setNetwork(int network) { this.network = network; }
}
