package com.dpianalyzer.model;

/**
 * Tracks the state and metrics of an active flow/connection.
 */
public class Connection {
    private final FiveTuple tuple;
    private ConnectionState state = ConnectionState.NEW;
    private AppType appType = AppType.UNKNOWN;
    private String sni = "";

    private long packetsIn = 0;
    private long packetsOut = 0;
    private long bytesIn = 0;
    private long bytesOut = 0;

    private long firstSeenMs;
    private long lastSeenMs;

    private PacketAction action = PacketAction.FORWARD;

    // TCP state tracking
    private boolean synSeen = false;
    private boolean synAckSeen = false;
    private boolean finSeen = false;

    public Connection(FiveTuple tuple) {
        this.tuple = tuple;
        long now = System.currentTimeMillis();
        this.firstSeenMs = now;
        this.lastSeenMs = now;
        this.state = ConnectionState.NEW;
    }

    public FiveTuple getTuple() {
        return tuple;
    }

    public ConnectionState getState() {
        return state;
    }

    public void setState(ConnectionState state) {
        this.state = state;
    }

    public AppType getAppType() {
        return appType;
    }

    public void setAppType(AppType appType) {
        this.appType = appType;
    }

    public String getSni() {
        return sni;
    }

    public void setSni(String sni) {
        this.sni = sni != null ? sni : "";
    }

    public long getPacketsIn() {
        return packetsIn;
    }

    public long getPacketsOut() {
        return packetsOut;
    }

    public long getBytesIn() {
        return bytesIn;
    }

    public long getBytesOut() {
        return bytesOut;
    }

    public long getTotalPackets() {
        return packetsIn + packetsOut;
    }

    public long getTotalBytes() {
        return bytesIn + bytesOut;
    }

    public long getFirstSeenMs() {
        return firstSeenMs;
    }

    public long getLastSeenMs() {
        return lastSeenMs;
    }

    public void update(long packetSize, boolean isOutbound) {
        this.lastSeenMs = System.currentTimeMillis();
        if (isOutbound) {
            packetsOut++;
            bytesOut += packetSize;
        } else {
            packetsIn++;
            bytesIn += packetSize;
        }
    }

    public PacketAction getAction() {
        return action;
    }

    public void setAction(PacketAction action) {
        this.action = action;
    }

    public boolean isSynSeen() {
        return synSeen;
    }

    public void setSynSeen(boolean synSeen) {
        this.synSeen = synSeen;
    }

    public boolean isSynAckSeen() {
        return synAckSeen;
    }

    public void setSynAckSeen(boolean synAckSeen) {
        this.synAckSeen = synAckSeen;
    }

    public boolean isFinSeen() {
        return finSeen;
    }

    public void setFinSeen(boolean finSeen) {
        this.finSeen = finSeen;
    }
}
