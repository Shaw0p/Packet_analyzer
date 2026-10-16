package com.dpianalyzer.parser;

import java.nio.charset.StandardCharsets;

/**
 * Extracts Host header from unencrypted HTTP traffic.
 */
public class HttpHostExtractor {
    private static final String[] HTTP_METHODS = {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS "
    };

    public static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (payload == null || length < 4 || offset + length > payload.length) {
            return false;
        }

        String start = new String(payload, offset, Math.min(length, 10), StandardCharsets.US_ASCII);
        for (String method : HTTP_METHODS) {
            if (start.startsWith(method)) {
                return true;
            }
        }
        return false;
    }

    public static String extract(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) {
            return null;
        }

        int end = offset + length;
        for (int i = offset; i + 6 < end; i++) {
            // Case-insensitive "Host:" check
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i + 1] == 'o' || payload[i + 1] == 'O') &&
                (payload[i + 2] == 's' || payload[i + 2] == 'S') &&
                (payload[i + 3] == 't' || payload[i + 3] == 'T') &&
                payload[i + 4] == ':') {

                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n') {
                    lineEnd++;
                }

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start, StandardCharsets.US_ASCII).trim();
                    // Strip optional port
                    int colon = host.indexOf(':');
                    if (colon > 0) {
                        host = host.substring(0, colon);
                    }
                    return host;
                }
            }
        }

        return null;
    }
}
