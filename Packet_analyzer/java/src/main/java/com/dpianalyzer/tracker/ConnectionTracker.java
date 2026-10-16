package com.dpianalyzer.tracker;

import com.dpianalyzer.model.AppType;
import com.dpianalyzer.model.Connection;
import com.dpianalyzer.model.ConnectionState;
import com.dpianalyzer.model.FiveTuple;
import com.dpianalyzer.model.PacketAction;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Tracks active network flows/connections and maintains bidirectional flow state.
 */
public class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections = new ConcurrentHashMap<>();

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public synchronized Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        // Check reverse tuple for existing bidirectional flow
        FiveTuple reverse = tuple.reverse();
        Connection revConn = connections.get(reverse);
        if (revConn != null) {
            return revConn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection(tuple);
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) return conn;
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn == null) return;
        conn.update(packetSize, isOutbound);
    }

    public synchronized void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;
        if (conn.getState() != ConnectionState.CLASSIFIED) {
            conn.setAppType(app);
            conn.setSni(sni);
            conn.setState(ConnectionState.CLASSIFIED);
            classifiedCount++;
        }
    }

    public synchronized void blockConnection(Connection conn) {
        if (conn == null) return;
        conn.setState(ConnectionState.BLOCKED);
        conn.setAction(PacketAction.DROP);
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = getConnection(tuple);
        if (conn != null) {
            conn.setState(ConnectionState.CLOSED);
        }
    }

    public synchronized int cleanupStale(long timeoutMs) {
        long now = System.currentTimeMillis();
        int removed = 0;
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Connection conn = it.next().getValue();
            if (now - conn.getLastSeenMs() > timeoutMs || conn.getState() == ConnectionState.CLOSED) {
                it.remove();
                removed++;
            }
        }
        return removed;
    }

    private void evictOldest() {
        FiveTuple oldestKey = null;
        long oldestTime = Long.MAX_VALUE;
        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().getLastSeenMs() < oldestTime) {
                oldestTime = entry.getValue().getLastSeenMs();
                oldestKey = entry.getKey();
            }
        }
        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public long getTotalSeen() {
        return totalSeen;
    }

    public long getClassifiedCount() {
        return classifiedCount;
    }

    public long getBlockedCount() {
        return blockedCount;
    }

    public void forEach(Consumer<Connection> consumer) {
        connections.values().forEach(consumer);
    }

    public void clear() {
        connections.clear();
    }
}
