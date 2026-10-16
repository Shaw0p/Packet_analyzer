package com.dpianalyzer.engine;

import com.dpianalyzer.model.*;
import com.dpianalyzer.parser.PacketParser;
import com.dpianalyzer.pcap.PcapReader;
import com.dpianalyzer.pcap.PcapWriter;
import com.dpianalyzer.rules.RuleManager;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Multi-threaded Deep Packet Inspection Engine.
 * Coordinates Reader, Load Balancers, Fast Path workers, and asynchronous PCAP output writer.
 */
public class DpiEngine {

    public static class Config {
        public int numLbs = 2;
        public int fpsPerLb = 2;

        public Config() {}

        public Config(int numLbs, int fpsPerLb) {
            this.numLbs = Math.max(1, numLbs);
            this.fpsPerLb = Math.max(1, fpsPerLb);
        }
    }

    private final Config config;
    private final RuleManager ruleManager = new RuleManager();

    private final List<FastPathProcessor> fps = new ArrayList<>();
    private final List<LoadBalancer> lbs = new ArrayList<>();
    private final BlockingQueue<PacketJob> outputQueue = new LinkedBlockingQueue<>(20000);

    // Global Statistics
    private final AtomicLong totalPackets = new AtomicLong(0);
    private final AtomicLong totalBytes = new AtomicLong(0);
    private final AtomicLong tcpPackets = new AtomicLong(0);
    private final AtomicLong udpPackets = new AtomicLong(0);
    private final AtomicLong otherPackets = new AtomicLong(0);

    public DpiEngine() {
        this(new Config());
    }

    public DpiEngine(Config config) {
        this.config = config;
        int totalFps = config.numLbs * config.fpsPerLb;

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║              DPI ENGINE v2.0 (Java Edition)                  ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println(String.format("║ Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     ║",
                config.numLbs, config.fpsPerLb, totalFps));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        // 1. Create FP threads
        for (int i = 0; i < totalFps; i++) {
            FastPathProcessor fp = new FastPathProcessor(i, ruleManager, outputQueue::offer);
            fps.add(fp);
        }

        // 2. Create LB threads
        for (int lb = 0; lb < config.numLbs; lb++) {
            List<FastPathProcessor> lbFps = new ArrayList<>();
            int start = lb * config.fpsPerLb;
            for (int i = 0; i < config.fpsPerLb; i++) {
                lbFps.add(fps.get(start + i));
            }
            lbs.add(new LoadBalancer(lb, lbFps));
        }
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    public void blockIp(String ip) { ruleManager.blockIp(ip); }
    public void blockApp(String app) { ruleManager.blockApp(app); }
    public void blockDomain(String domain) { ruleManager.blockDomain(domain); }
    public void blockPort(int port) { ruleManager.blockPort(port); }

    public boolean process(String inputPcapPath, String outputPcapPath) {
        File inputFile = new File(inputPcapPath);
        if (!inputFile.exists()) {
            System.err.println("Input file not found: " + inputPcapPath);
            return false;
        }

        try (PcapReader reader = new PcapReader(inputFile)) {
            // Start output writer thread
            AtomicBoolean outputRunning = new AtomicBoolean(true);
            Thread outputWriterThread = new Thread(() -> {
                try (PcapWriter writer = new PcapWriter(outputPcapPath, reader.getGlobalHeader(), reader.getByteOrder())) {
                    while (outputRunning.get() || !outputQueue.isEmpty()) {
                        PacketJob job = outputQueue.poll(50, TimeUnit.MILLISECONDS);
                        if (job != null) {
                            writer.writePacket(job.getTsSec(), job.getTsUsec(), job.getData());
                        }
                    }
                    writer.flush();
                } catch (Exception e) {
                    System.err.println("Error writing to output PCAP: " + e.getMessage());
                }
            }, "PcapOutputWriter");

            outputWriterThread.start();

            // Start all FP and LB threads
            for (FastPathProcessor fp : fps) fp.start();
            for (LoadBalancer lb : lbs) lb.start();

            System.out.println("[Reader] Processing packets...");
            RawPacket raw;
            ParsedPacket parsed = new ParsedPacket();
            int pktId = 0;

            while ((raw = reader.readNextPacket()) != null) {
                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }
                if (!parsed.hasIp() || (!parsed.hasTcp() && !parsed.hasUdp())) {
                    continue;
                }

                pktId++;
                FiveTuple tuple = parsed.toFiveTuple();

                PacketJob job = new PacketJob(
                        pktId,
                        raw.getHeader().getTsSec(),
                        raw.getHeader().getTsUsec(),
                        tuple,
                        raw.getData(),
                        parsed.getTcpFlags(),
                        parsed.getPayloadOffset(),
                        parsed.getPayloadLength()
                );

                totalPackets.incrementAndGet();
                totalBytes.addAndGet(raw.getData().length);
                if (parsed.hasTcp()) tcpPackets.incrementAndGet();
                else if (parsed.hasUdp()) udpPackets.incrementAndGet();
                else otherPackets.incrementAndGet();

                // Dispatch to LB using 5-tuple hash
                int hash = tuple.hashCode() & 0x7FFFFFFF;
                int lbIndex = hash % lbs.size();
                lbs.get(lbIndex).getInputQueue().put(job);
            }

            System.out.println("[Reader] Done reading " + pktId + " packets");

            // Allow queues to drain
            Thread.sleep(600);

            // Stop LBs and FPs
            for (LoadBalancer lb : lbs) lb.stop();
            for (FastPathProcessor fp : fps) fp.stop();

            // Stop writer
            outputRunning.set(false);
            outputWriterThread.join();

            // Print report
            printReport();
            System.out.println("\nFiltered output successfully written to: " + outputPcapPath);
            return true;

        } catch (Exception e) {
            System.err.println("Failed to process PCAP: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private void printReport() {
        long forwarded = 0;
        long dropped = 0;
        Map<AppType, Long> appDistribution = new EnumMap<>(AppType.class);
        Map<String, AppType> detectedSnis = new TreeMap<>();

        for (FastPathProcessor fp : fps) {
            forwarded += fp.getPacketsForwarded();
            dropped += fp.getPacketsDropped();
            fp.getTracker().forEach(conn -> {
                appDistribution.merge(conn.getAppType(), conn.getTotalPackets(), Long::sum);
                if (!conn.getSni().isEmpty()) {
                    AppType app = conn.getAppType();
                    if (app == AppType.DNS || app == AppType.HTTPS || app == AppType.HTTP || app == AppType.UNKNOWN) {
                        AppType detected = AppType.fromSni(conn.getSni());
                        if (detected != AppType.UNKNOWN && detected != AppType.HTTPS) {
                            app = detected;
                        }
                    }
                    detectedSnis.put(conn.getSni(), app);
                }
            });
        }

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println(String.format("║ Total Packets:      %12d                           ║", totalPackets.get()));
        System.out.println(String.format("║ Total Bytes:        %12d                           ║", totalBytes.get()));
        System.out.println(String.format("║ TCP Packets:        %12d                           ║", tcpPackets.get()));
        System.out.println(String.format("║ UDP Packets:        %12d                           ║", udpPackets.get()));
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println(String.format("║ Forwarded:          %12d                           ║", forwarded));
        System.out.println(String.format("║ Dropped:            %12d                           ║", dropped));

        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ THREAD STATISTICS                                             ║");
        for (int i = 0; i < lbs.size(); i++) {
            System.out.println(String.format("║   LB%d dispatched:   %12d                           ║",
                    i, lbs.get(i).getDispatched()));
        }
        for (int i = 0; i < fps.size(); i++) {
            System.out.println(String.format("║   FP%d processed:    %12d                           ║",
                    i, fps.get(i).getPacketsProcessed()));
        }

        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                   APPLICATION BREAKDOWN                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        long total = totalPackets.get();
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appDistribution.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0.0;
            int barLen = (int) (pct / 5.0);
            StringBuilder bar = new StringBuilder();
            for (int b = 0; b < barLen; b++) bar.append('#');

            System.out.println(String.format("║ %-15s %8d  %5.1f%% %-20s  ║",
                    entry.getKey().getDisplayName(), entry.getValue(), pct, bar.toString()));
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        if (!detectedSnis.isEmpty()) {
            System.out.println("\n[Detected Domains / SNIs]");
            for (Map.Entry<String, AppType> entry : detectedSnis.entrySet()) {
                System.out.println("  • " + entry.getKey() + " -> " + entry.getValue().getDisplayName());
            }
        }
    }
}
