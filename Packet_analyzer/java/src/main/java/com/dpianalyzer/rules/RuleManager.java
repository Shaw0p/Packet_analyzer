package com.dpianalyzer.rules;

import com.dpianalyzer.model.AppType;
import com.dpianalyzer.model.FiveTuple;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe Rule Manager for IP, Application, Domain, and Port filtering rules.
 */
public class RuleManager {

    public enum ReasonType {
        IP,
        APP,
        DOMAIN,
        PORT
    }

    public static class BlockReason {
        private final ReasonType type;
        private final String detail;

        public BlockReason(ReasonType type, String detail) {
            this.type = type;
            this.detail = detail;
        }

        public ReasonType getType() { return type; }
        public String getDetail() { return detail; }

        @Override
        public String toString() {
            return type + " (" + detail + ")";
        }
    }

    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private final List<String> domainPatterns = new CopyOnWriteArrayList<>();
    private final Set<Integer> blockedPorts = ConcurrentHashMap.newKeySet();

    public RuleManager() {}

    // IP Rules
    public void blockIp(int ip) {
        blockedIps.add(ip);
        System.out.println("[RuleManager] Blocked IP: " + FiveTuple.ipToString(ip));
    }

    public void blockIp(String ipStr) {
        blockIp(FiveTuple.parseIp(ipStr));
    }

    public void unblockIp(int ip) {
        blockedIps.remove(ip);
        System.out.println("[RuleManager] Unblocked IP: " + FiveTuple.ipToString(ip));
    }

    public void unblockIp(String ipStr) {
        unblockIp(FiveTuple.parseIp(ipStr));
    }

    public boolean isIpBlocked(int ip) {
        return blockedIps.contains(ip);
    }

    public List<String> getBlockedIps() {
        List<String> list = new ArrayList<>();
        for (int ip : blockedIps) {
            list.add(FiveTuple.ipToString(ip));
        }
        return list;
    }

    // App Rules
    public void blockApp(AppType app) {
        if (app != null && app != AppType.UNKNOWN) {
            blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + app.getDisplayName());
        }
    }

    public void blockApp(String appName) {
        AppType app = AppType.fromName(appName);
        if (app != AppType.UNKNOWN) {
            blockApp(app);
        } else {
            System.err.println("[RuleManager] Unknown application to block: " + appName);
        }
    }

    public void unblockApp(AppType app) {
        if (app != null) {
            blockedApps.remove(app);
            System.out.println("[RuleManager] Unblocked app: " + app.getDisplayName());
        }
    }

    public boolean isAppBlocked(AppType app) {
        return app != null && blockedApps.contains(app);
    }

    public List<AppType> getBlockedApps() {
        return new ArrayList<>(blockedApps);
    }

    // Domain Rules
    public void blockDomain(String domain) {
        if (domain == null || domain.trim().isEmpty()) return;
        String d = domain.trim().toLowerCase(Locale.ROOT);
        if (d.contains("*")) {
            domainPatterns.add(d);
        } else {
            blockedDomains.add(d);
        }
        System.out.println("[RuleManager] Blocked domain: " + domain);
    }

    public void unblockDomain(String domain) {
        if (domain == null) return;
        String d = domain.trim().toLowerCase(Locale.ROOT);
        blockedDomains.remove(d);
        domainPatterns.remove(d);
        System.out.println("[RuleManager] Unblocked domain: " + domain);
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String lower = domain.toLowerCase(Locale.ROOT);

        if (blockedDomains.contains(lower)) {
            return true;
        }

        for (String pattern : domainPatterns) {
            if (domainMatches(lower, pattern)) {
                return true;
            }
        }

        // Substring fallback if configured
        for (String bd : blockedDomains) {
            if (lower.contains(bd)) {
                return true;
            }
        }

        return false;
    }

    private static boolean domainMatches(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // .example.com
            if (domain.endsWith(suffix) || domain.equals(pattern.substring(2))) {
                return true;
            }
        }
        return domain.contains(pattern.replace("*", ""));
    }

    public List<String> getBlockedDomains() {
        List<String> result = new ArrayList<>(blockedDomains);
        result.addAll(domainPatterns);
        return result;
    }

    // Port Rules
    public void blockPort(int port) {
        blockedPorts.add(port & 0xFFFF);
        System.out.println("[RuleManager] Blocked port: " + port);
    }

    public void unblockPort(int port) {
        blockedPorts.remove(port & 0xFFFF);
    }

    public boolean isPortBlocked(int port) {
        return blockedPorts.contains(port & 0xFFFF);
    }

    // Comprehensive Check
    public BlockReason shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIpBlocked(srcIp)) {
            return new BlockReason(ReasonType.IP, FiveTuple.ipToString(srcIp));
        }

        if (isPortBlocked(dstPort)) {
            return new BlockReason(ReasonType.PORT, String.valueOf(dstPort));
        }

        if (app != null && isAppBlocked(app)) {
            return new BlockReason(ReasonType.APP, app.getDisplayName());
        }

        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return new BlockReason(ReasonType.DOMAIN, domain);
        }

        return null;
    }

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
        domainPatterns.clear();
        blockedPorts.clear();
        System.out.println("[RuleManager] All rules cleared");
    }

    // Persistence
    public boolean saveRules(String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIps()) {
                writer.println(ip);
            }

            writer.println("\n[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) {
                writer.println(app.getDisplayName());
            }

            writer.println("\n[BLOCKED_DOMAINS]");
            for (String domain : getBlockedDomains()) {
                writer.println(domain);
            }

            writer.println("\n[BLOCKED_PORTS]");
            for (int port : blockedPorts) {
                writer.println(port);
            }
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to save rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        File file = new File(filename);
        if (!file.exists()) return false;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            String section = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;

                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line;
                    continue;
                }

                switch (section) {
                    case "[BLOCKED_IPS]":
                        blockIp(line);
                        break;
                    case "[BLOCKED_APPS]":
                        blockApp(line);
                        break;
                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;
                    case "[BLOCKED_PORTS]":
                        try {
                            blockPort(Integer.parseInt(line));
                        } catch (NumberFormatException ignored) {}
                        break;
                }
            }
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Failed to load rules: " + e.getMessage());
            return false;
        }
    }
}
