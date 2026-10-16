package com.dpianalyzer.parser;

import java.nio.charset.StandardCharsets;

/**
 * Extracts Server Name Indication (SNI) from TLS Client Hello packets.
 */
public class SniExtractor {
    public static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    public static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    public static final int EXTENSION_SNI = 0x0000;
    public static final int SNI_TYPE_HOSTNAME = 0x00;

    public static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (payload == null || length < 9 || offset + length > payload.length) {
            return false;
        }

        // Byte 0: Content Type (0x16 = Handshake)
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) {
            return false;
        }

        // Bytes 1-2: TLS Version (0x0300 SSL 3.0 through 0x0304 TLS 1.3)
        int version = ((payload[offset + 1] & 0xFF) << 8) | (payload[offset + 2] & 0xFF);
        if (version < 0x0300 || version > 0x0304) {
            return false;
        }

        // Bytes 3-4: Record length
        int recordLen = ((payload[offset + 3] & 0xFF) << 8) | (payload[offset + 4] & 0xFF);
        if (recordLen > length - 5) {
            return false;
        }

        // Handshake layer (starts at byte 5): Type must be 0x01 (Client Hello)
        return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    public static String extract(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length)) {
            return null;
        }

        int curr = offset + 5; // skip 5-byte TLS record header

        // Handshake header:
        // Byte 0: Handshake type (already verified)
        // Bytes 1-3: Handshake length (24-bit uint)
        curr += 4;

        // Client Hello body:
        // Client version (2 bytes)
        curr += 2;

        // Random (32 bytes)
        curr += 32;

        // Session ID
        if (curr >= offset + length) return null;
        int sessionIdLen = payload[curr] & 0xFF;
        curr += 1 + sessionIdLen;

        // Cipher suites
        if (curr + 2 > offset + length) return null;
        int cipherSuitesLen = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
        curr += 2 + cipherSuitesLen;

        // Compression methods
        if (curr >= offset + length) return null;
        int compressionLen = payload[curr] & 0xFF;
        curr += 1 + compressionLen;

        // Extensions
        if (curr + 2 > offset + length) return null;
        int extensionsLen = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
        curr += 2;

        int extensionsEnd = Math.min(curr + extensionsLen, offset + length);

        while (curr + 4 <= extensionsEnd) {
            int extType = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
            int extLen = ((payload[curr + 2] & 0xFF) << 8) | (payload[curr + 3] & 0xFF);
            curr += 4;

            if (curr + extLen > extensionsEnd) {
                break;
            }

            if (extType == EXTENSION_SNI) {
                if (extLen < 5) break;

                int sniListLen = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
                if (sniListLen < 3) break;

                int sniType = payload[curr + 2] & 0xFF;
                int sniLen = ((payload[curr + 3] & 0xFF) << 8) | (payload[curr + 4] & 0xFF);

                if (sniType == SNI_TYPE_HOSTNAME && sniLen <= extLen - 5 && curr + 5 + sniLen <= payload.length) {
                    return new String(payload, curr + 5, sniLen, StandardCharsets.US_ASCII);
                }
            }

            curr += extLen;
        }

        return null;
    }
}
