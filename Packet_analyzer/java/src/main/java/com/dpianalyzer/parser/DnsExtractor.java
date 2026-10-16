package com.dpianalyzer.parser;

import java.nio.charset.StandardCharsets;

/**
 * Extracts queried domain name from DNS request packets (UDP/TCP port 53).
 */
public class DnsExtractor {

    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (payload == null || length < 12 || offset + length > payload.length) {
            return false;
        }

        // Check QR bit in Flags (byte 2, bit 7: 0 = Query, 1 = Response)
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0) {
            return false;
        }

        // Check QDCOUNT (bytes 4-5) > 0
        int qdCount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdCount > 0;
    }

    public static String extractQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) {
            return null;
        }

        // DNS query section begins at offset 12
        int curr = offset + 12;
        int end = offset + length;
        StringBuilder domain = new StringBuilder();

        while (curr < end) {
            int labelLen = payload[curr] & 0xFF;
            if (labelLen == 0) {
                break; // End of domain labels
            }
            if (labelLen > 63 || curr + 1 + labelLen > end) {
                // Compression pointer or corrupted
                break;
            }

            curr++;
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, curr, labelLen, StandardCharsets.US_ASCII));
            curr += labelLen;
        }

        return domain.length() > 0 ? domain.toString() : null;
    }
}
