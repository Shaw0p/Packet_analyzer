package com.dpianalyzer.engine;

import com.dpianalyzer.model.*;
import com.dpianalyzer.parser.DnsExtractor;
import com.dpianalyzer.parser.HttpHostExtractor;
import com.dpianalyzer.parser.SniExtractor;
import com.dpianalyzer.rules.RuleManager;
import com.dpianalyzer.tracker.ConnectionTracker;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Fast Path Processor thread responsible for flow tracking, deep packet payload inspection, and rule filtering.
 */
public class FastPathProcessor implements Runnable {
    private final int fpId;
    private final BlockingQueue<PacketJob> inputQueue = new LinkedBlockingQueue<>(10000);
    private final ConnectionTracker tracker;
    private final RuleManager ruleManager;
    private final Consumer<PacketJob> outputConsumer;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread workerThread;

    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);

    public FastPathProcessor(int fpId, RuleManager ruleManager, Consumer<PacketJob> outputConsumer) {
        this.fpId = fpId;
        this.tracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputConsumer = outputConsumer;
    }

    public void start() {
        if (running.compareAndSet(false, true)) {
            workerThread = new Thread(this, "FastPath-" + fpId);
            workerThread.start();
            System.out.println("[FP" + fpId + "] Started");
        }
    }

    public void stop() {
        if (running.compareAndSet(true, false)) {
            if (workerThread != null) {
                try {
                    workerThread.join(2000);
                } catch (InterruptedException ignored) {}
            }
            System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
        }
    }

    public BlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getTracker() {
        return tracker;
    }

    public long getPacketsProcessed() { return packetsProcessed.get(); }
    public long getPacketsForwarded() { return packetsForwarded.get(); }
    public long getPacketsDropped() { return packetsDropped.get(); }
    public long getSniExtractions() { return sniExtractions.get(); }

    @Override
    public void run() {
        while (running.get() || !inputQueue.isEmpty()) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) {
                    tracker.cleanupStale(300_000); // 5 min timeout
                    continue;
                }

                packetsProcessed.incrementAndGet();
                PacketAction action = processPacket(job);

                if (action == PacketAction.DROP) {
                    packetsDropped.incrementAndGet();
                } else {
                    packetsForwarded.incrementAndGet();
                    if (outputConsumer != null) {
                        outputConsumer.accept(job);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                System.err.println("[FP" + fpId + "] Error processing packet: " + e.getMessage());
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = tracker.getOrCreateConnection(job.getTuple());

        // Update traffic counters
        tracker.updateConnection(conn, job.getData().length, true);

        // Update TCP flags
        if (job.getTuple().getProtocol() == 6) {
            updateTcpFlags(conn, job.getTcpFlags());
        }

        // If flow is already blocked, drop immediately
        if (conn.getState() == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        // Inspect payload if not yet classified
        if (conn.getState() != ConnectionState.CLASSIFIED && job.getPayloadLength() > 0) {
            inspectPayload(job, conn);
        }

        // Evaluate blocking rules
        if (ruleManager != null) {
            RuleManager.BlockReason reason = ruleManager.shouldBlock(
                    job.getTuple().getSrcIp(),
                    job.getTuple().getDstPort(),
                    conn.getAppType(),
                    conn.getSni()
            );

            if (reason != null) {
                System.out.println("[FP" + fpId + "] BLOCKED packet: " + reason);
                tracker.blockConnection(conn);
                return PacketAction.DROP;
            }
        }

        return PacketAction.FORWARD;
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        byte[] data = job.getData();
        int offset = job.getPayloadOffset();
        int len = job.getPayloadLength();

        if (len <= 0 || offset >= data.length) return;

        // 1. Try TLS SNI extraction (HTTPS port 443 or TLS payload)
        if (job.getTuple().getDstPort() == 443 || len >= 9) {
            String sni = SniExtractor.extract(data, offset, len);
            if (sni != null && !sni.isEmpty()) {
                sniExtractions.incrementAndGet();
                AppType app = AppType.fromSni(sni);
                tracker.classifyConnection(conn, app, sni);
                return;
            }
        }

        // 2. Try HTTP Host header extraction (port 80 or HTTP request)
        if (job.getTuple().getDstPort() == 80 || HttpHostExtractor.isHttpRequest(data, offset, len)) {
            String host = HttpHostExtractor.extract(data, offset, len);
            if (host != null && !host.isEmpty()) {
                AppType app = AppType.fromSni(host);
                tracker.classifyConnection(conn, app, host);
                return;
            }
        }

        // 3. DNS (port 53)
        if (job.getTuple().getDstPort() == 53 || job.getTuple().getSrcPort() == 53) {
            String dnsQuery = DnsExtractor.extractQuery(data, offset, len);
            if (dnsQuery != null) {
                tracker.classifyConnection(conn, AppType.DNS, dnsQuery);
                return;
            }
        }

        // Port-based fallback
        if (job.getTuple().getDstPort() == 443) {
            conn.setAppType(AppType.HTTPS);
        } else if (job.getTuple().getDstPort() == 80) {
            conn.setAppType(AppType.HTTP);
        }
    }

    private void updateTcpFlags(Connection conn, int flags) {
        int syn = 0x02;
        int ack = 0x10;
        int fin = 0x01;
        int rst = 0x04;

        if ((flags & syn) != 0) {
            if ((flags & ack) != 0) {
                conn.setSynAckSeen(true);
            } else {
                conn.setSynSeen(true);
            }
        }

        if (conn.isSynSeen() && conn.isSynAckSeen() && (flags & ack) != 0) {
            if (conn.getState() == ConnectionState.NEW) {
                conn.setState(ConnectionState.ESTABLISHED);
            }
        }

        if ((flags & fin) != 0) {
            conn.setFinSeen(true);
        }

        if ((flags & rst) != 0 || (conn.isFinSeen() && (flags & ack) != 0)) {
            conn.setState(ConnectionState.CLOSED);
        }
    }
}
