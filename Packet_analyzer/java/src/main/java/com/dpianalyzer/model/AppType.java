package com.dpianalyzer.model;

import java.util.Locale;

/**
 * Supported Application Classifications detected via Deep Packet Inspection (SNI / HTTP Host / Port).
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Parse domain / SNI to AppType based on domain signatures.
     */
    public static AppType fromSni(String sni) {
        if (sni == null || sni.trim().isEmpty()) {
            return UNKNOWN;
        }

        String lower = sni.toLowerCase(Locale.ROOT);

        // Google / YouTube
        if (lower.contains("youtube") || lower.contains("ytimg") ||
            lower.contains("youtu.be") || lower.contains("yt3.ggpht")) {
            return YOUTUBE;
        }
        if (lower.contains("google") || lower.contains("gstatic") ||
            lower.contains("googleapis") || lower.contains("ggpht") || lower.contains("gvt1")) {
            return GOOGLE;
        }

        // Facebook / Instagram / WhatsApp (Meta)
        if (lower.contains("facebook") || lower.contains("fbcdn") ||
            lower.contains("fb.com") || lower.contains("fbsbx") || lower.contains("meta.com")) {
            return FACEBOOK;
        }
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return INSTAGRAM;
        }
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return WHATSAPP;
        }

        // Netflix
        if (lower.contains("netflix") || lower.contains("nflxvideo") || lower.contains("nflximg")) {
            return NETFLIX;
        }

        // Microsoft
        if (lower.contains("microsoft") || lower.contains("msn.com") ||
            lower.contains("office") || lower.contains("azure") ||
            lower.contains("live.com") || lower.contains("outlook") || lower.contains("bing")) {
            return MICROSOFT;
        }

        // Twitter / X
        if (lower.contains("twitter") || lower.contains("twimg") ||
            matchesDomain(lower, "x.com") || matchesDomain(lower, "t.co")) {
            return TWITTER;
        }

        // Amazon
        if (lower.contains("amazon") || lower.contains("amazonaws") ||
            lower.contains("cloudfront") || lower.contains("aws")) {
            return AMAZON;
        }

        // Apple
        if (lower.contains("apple") || lower.contains("icloud") ||
            lower.contains("mzstatic") || lower.contains("itunes")) {
            return APPLE;
        }

        // Telegram
        if (lower.contains("telegram") || matchesDomain(lower, "t.me")) {
            return TELEGRAM;
        }

        // TikTok
        if (lower.contains("tiktok") || lower.contains("tiktokcdn") ||
            lower.contains("musical.ly") || lower.contains("bytedance")) {
            return TIKTOK;
        }

        // Spotify
        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return SPOTIFY;
        }

        // Zoom
        if (lower.contains("zoom")) {
            return ZOOM;
        }

        // Discord
        if (lower.contains("discord") || lower.contains("discordapp")) {
            return DISCORD;
        }

        // GitHub
        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return GITHUB;
        }

        // Cloudflare
        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return CLOUDFLARE;
        }

        return HTTPS;
    }

    private static boolean matchesDomain(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain) || host.contains(domain + ":");
    }

    public static AppType fromName(String name) {
        if (name == null) return UNKNOWN;
        for (AppType app : values()) {
            if (app.name().equalsIgnoreCase(name) || app.displayName.equalsIgnoreCase(name)) {
                return app;
            }
        }
        return UNKNOWN;
    }
}
