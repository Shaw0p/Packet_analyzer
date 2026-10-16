// Client-Side PCAP Parser & Deep Packet Inspection (DPI) Engine
// Zero external dependencies - parses binary PCAP files directly in the browser

export const APP_TYPES = {
  UNKNOWN: { name: 'Unknown', color: '#64748b' },
  HTTP: { name: 'HTTP', color: '#38bdf8' },
  HTTPS: { name: 'HTTPS', color: '#0ea5e9' },
  DNS: { name: 'DNS', color: '#a855f7' },
  GOOGLE: { name: 'Google', color: '#ea4335' },
  YOUTUBE: { name: 'YouTube', color: '#ff0000' },
  FACEBOOK: { name: 'Facebook', color: '#1877f2' },
  INSTAGRAM: { name: 'Instagram', color: '#e1306c' },
  WHATSAPP: { name: 'WhatsApp', color: '#25d366' },
  TWITTER: { name: 'Twitter/X', color: '#1da1f2' },
  NETFLIX: { name: 'Netflix', color: '#e50914' },
  AMAZON: { name: 'Amazon', color: '#ff9900' },
  MICROSOFT: { name: 'Microsoft', color: '#00a4ef' },
  APPLE: { name: 'Apple', color: '#a2aaad' },
  TELEGRAM: { name: 'Telegram', color: '#229ed9' },
  TIKTOK: { name: 'TikTok', color: '#fe2c55' },
  SPOTIFY: { name: 'Spotify', color: '#1db954' },
  ZOOM: { name: 'Zoom', color: '#2d8cff' },
  DISCORD: { name: 'Discord', color: '#5865f2' },
  GITHUB: { name: 'GitHub', color: '#f0f6fc' },
  CLOUDFLARE: { name: 'Cloudflare', color: '#f38020' },
};

export function classifySni(sni) {
  if (!sni) return APP_TYPES.UNKNOWN;
  const s = sni.toLowerCase();

  if (s.includes('youtube') || s.includes('ytimg') || s.includes('youtu.be') || s.includes('yt3.ggpht')) return APP_TYPES.YOUTUBE;
  if (s.includes('google') || s.includes('gstatic') || s.includes('googleapis') || s.includes('ggpht') || s.includes('gvt1')) return APP_TYPES.GOOGLE;
  if (s.includes('facebook') || s.includes('fbcdn') || s.includes('fb.com') || s.includes('meta.com')) return APP_TYPES.FACEBOOK;
  if (s.includes('instagram') || s.includes('cdninstagram')) return APP_TYPES.INSTAGRAM;
  if (s.includes('whatsapp') || s.includes('wa.me')) return APP_TYPES.WHATSAPP;
  if (s.includes('netflix') || s.includes('nflxvideo') || s.includes('nflximg')) return APP_TYPES.NETFLIX;
  if (s.includes('microsoft') || s.includes('msn.com') || s.includes('office') || s.includes('azure') || s.includes('live.com') || s.includes('outlook') || s.includes('bing')) return APP_TYPES.MICROSOFT;
  if (s.includes('twitter') || s.includes('twimg') || s.includes('x.com') || s.includes('t.co')) return APP_TYPES.TWITTER;
  if (s.includes('amazon') || s.includes('amazonaws') || s.includes('cloudfront') || s.includes('aws')) return APP_TYPES.AMAZON;
  if (s.includes('apple') || s.includes('icloud') || s.includes('mzstatic') || s.includes('itunes')) return APP_TYPES.APPLE;
  if (s.includes('telegram') || s.includes('t.me')) return APP_TYPES.TELEGRAM;
  if (s.includes('tiktok') || s.includes('tiktokcdn') || s.includes('bytedance')) return APP_TYPES.TIKTOK;
  if (s.includes('spotify') || s.includes('scdn.co')) return APP_TYPES.SPOTIFY;
  if (s.includes('zoom')) return APP_TYPES.ZOOM;
  if (s.includes('discord') || s.includes('discordapp')) return APP_TYPES.DISCORD;
  if (s.includes('github') || s.includes('githubusercontent')) return APP_TYPES.GITHUB;
  if (s.includes('cloudflare') || s.includes('cf-')) return APP_TYPES.CLOUDFLARE;

  return APP_TYPES.HTTPS;
}

export function parsePcapArrayBuffer(arrayBuffer) {
  const dataView = new DataView(arrayBuffer);
  const uint8 = new Uint8Array(arrayBuffer);
  const totalLength = arrayBuffer.byteLength;

  if (totalLength < 24) {
    throw new Error('File too small to be a valid PCAP (under 24 bytes).');
  }

  // Check magic number
  let littleEndian = true;
  const magicRaw = dataView.getUint32(0, false);
  if (magicRaw === 0xa1b2c3d4 || magicRaw === 0xa1b23c4d) {
    littleEndian = false;
  } else if (magicRaw === 0xd4c3b2a1 || magicRaw === 0x4d3cb2a1) {
    littleEndian = true;
  } else {
    // Check little endian
    const magicLe = dataView.getUint32(0, true);
    if (magicLe === 0xa1b2c3d4 || magicLe === 0xa1b23c4d) {
      littleEndian = true;
    } else {
      throw new Error(`Invalid PCAP magic number: 0x${magicRaw.toString(16)}`);
    }
  }

  const globalHeader = {
    magicNumber: dataView.getUint32(0, littleEndian),
    versionMajor: dataView.getUint16(4, littleEndian),
    versionMinor: dataView.getUint16(6, littleEndian),
    thisZone: dataView.getInt32(8, littleEndian),
    sigFigs: dataView.getUint32(12, littleEndian),
    snapLen: dataView.getUint32(16, littleEndian),
    network: dataView.getUint32(20, littleEndian),
    littleEndian,
  };

  const packets = [];
  let offset = 24;
  let packetId = 0;

  while (offset + 16 <= totalLength) {
    packetId++;
    const tsSec = dataView.getUint32(offset, littleEndian);
    const tsUsec = dataView.getUint32(offset + 4, littleEndian);
    const inclLen = dataView.getUint32(offset + 8, littleEndian);
    const origLen = dataView.getUint32(offset + 12, littleEndian);
    offset += 16;

    if (inclLen > 65535 || offset + inclLen > totalLength) {
      break;
    }

    const packetBytes = uint8.slice(offset, offset + inclLen);
    const parsed = parseSinglePacket(packetBytes, packetId, tsSec, tsUsec, origLen);
    packets.push(parsed);

    offset += inclLen;
  }

  return { globalHeader, packets };
}

function parseSinglePacket(bytes, id, tsSec, tsUsec, origLen) {
  const len = bytes.length;
  let offset = 0;

  const result = {
    id,
    tsSec,
    tsUsec,
    timestampFormatted: formatTimestamp(tsSec, tsUsec),
    length: len,
    origLen,
    rawBytes: bytes,
    ethernet: null,
    ip: null,
    transport: null,
    dpi: null,
    protocol: 'Other',
    appType: APP_TYPES.UNKNOWN,
    srcSummary: '-',
    dstSummary: '-',
    sniOrHost: '',
    action: 'FORWARD', // Default action, updated by firewall
    blockReason: null,
  };

  // Ethernet (14 bytes)
  if (len >= 14) {
    const dstMac = formatMac(bytes, 0);
    const srcMac = formatMac(bytes, 6);
    const etherType = (bytes[12] << 8) | bytes[13];
    result.ethernet = {
      dstMac,
      srcMac,
      etherType,
      etherTypeHex: `0x${etherType.toString(16).padStart(4, '0')}`,
    };
    offset = 14;

    // IPv4 (0x0800)
    if (etherType === 0x0800 && len >= offset + 20) {
      const verIhl = bytes[offset];
      const version = (verIhl >> 4) & 0x0f;
      const ihl = verIhl & 0x0f;
      const ipHeaderLen = ihl * 4;

      if (version === 4 && ipHeaderLen >= 20 && len >= offset + ipHeaderLen) {
        const totalLength = (bytes[offset + 2] << 8) | bytes[offset + 3];
        const ttl = bytes[offset + 8];
        const protocolNum = bytes[offset + 9];
        const srcIp = `${bytes[offset + 12]}.${bytes[offset + 13]}.${bytes[offset + 14]}.${bytes[offset + 15]}`;
        const dstIp = `${bytes[offset + 16]}.${bytes[offset + 17]}.${bytes[offset + 18]}.${bytes[offset + 19]}`;

        result.ip = {
          version: 4,
          ihl,
          headerLength: ipHeaderLen,
          totalLength,
          ttl,
          protocolNum,
          protocolName: protocolNum === 6 ? 'TCP' : protocolNum === 17 ? 'UDP' : protocolNum === 1 ? 'ICMP' : `Proto(${protocolNum})`,
          srcIp,
          dstIp,
        };
        result.protocol = result.ip.protocolName;
        result.srcSummary = srcIp;
        result.dstSummary = dstIp;

        offset += ipHeaderLen;

        // Transport layer
        if (protocolNum === 6 && len >= offset + 20) {
          // TCP
          const srcPort = (bytes[offset] << 8) | bytes[offset + 1];
          const dstPort = (bytes[offset + 2] << 8) | bytes[offset + 3];
          const seq = ((bytes[offset + 4] << 24) | (bytes[offset + 5] << 16) | (bytes[offset + 6] << 8) | bytes[offset + 7]) >>> 0;
          const ack = ((bytes[offset + 8] << 24) | (bytes[offset + 9] << 16) | (bytes[offset + 10] << 8) | bytes[offset + 11]) >>> 0;
          const dataOffset = (bytes[offset + 12] >> 4) & 0x0f;
          const tcpHeaderLen = dataOffset * 4;
          const flags = bytes[offset + 13];

          result.transport = {
            type: 'TCP',
            srcPort,
            dstPort,
            seq,
            ack,
            headerLength: tcpHeaderLen,
            flags,
            flagsString: formatTcpFlags(flags),
          };
          result.srcSummary = `${srcIp}:${srcPort}`;
          result.dstSummary = `${dstIp}:${dstPort}`;

          offset += tcpHeaderLen;

          // Layer 7 DPI
          if (offset < len) {
            const payload = bytes.slice(offset);
            inspectPayload(payload, result);
          }
        } else if (protocolNum === 17 && len >= offset + 8) {
          // UDP
          const srcPort = (bytes[offset] << 8) | bytes[offset + 1];
          const dstPort = (bytes[offset + 2] << 8) | bytes[offset + 3];
          const udpLen = (bytes[offset + 4] << 8) | bytes[offset + 5];

          result.transport = {
            type: 'UDP',
            srcPort,
            dstPort,
            length: udpLen,
          };
          result.srcSummary = `${srcIp}:${srcPort}`;
          result.dstSummary = `${dstIp}:${dstPort}`;

          offset += 8;

          // Layer 7 DPI (DNS on port 53)
          if (offset < len) {
            const payload = bytes.slice(offset);
            inspectPayload(payload, result);
          }
        }
      }
    }
  }

  // Fallback port classification if not classified
  if (result.appType === APP_TYPES.UNKNOWN && result.transport) {
    if (result.transport.dstPort === 443 || result.transport.srcPort === 443) {
      result.appType = APP_TYPES.HTTPS;
    } else if (result.transport.dstPort === 80 || result.transport.srcPort === 80) {
      result.appType = APP_TYPES.HTTP;
    } else if (result.transport.dstPort === 53 || result.transport.srcPort === 53) {
      result.appType = APP_TYPES.DNS;
    }
  }

  return result;
}

function inspectPayload(payload, result) {
  const len = payload.length;
  if (len < 4) return;

  // 1. TLS SNI Extraction
  if (payload[0] === 0x16 && payload.length >= 9) {
    // Content type 0x16 = Handshake
    const version = (payload[1] << 8) | payload[2];
    if (version >= 0x0300 && version <= 0x0304) {
      if (payload[5] === 0x01) {
        // Handshake type 0x01 = Client Hello
        const sni = extractTlsSni(payload);
        if (sni) {
          result.sniOrHost = sni;
          result.appType = classifySni(sni);
          result.dpi = {
            protocol: 'TLS',
            handshake: 'Client Hello',
            sni,
            app: result.appType.name,
          };
          return;
        }
      }
    }
  }

  // 2. HTTP Host extraction
  const asciiHeader = bytesToAscii(payload.slice(0, Math.min(len, 1024)));
  if (/^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s/i.test(asciiHeader)) {
    const hostMatch = asciiHeader.match(/Host:\s*([^\r\n:]+)/i);
    if (hostMatch && hostMatch[1]) {
      const host = hostMatch[1].trim();
      result.sniOrHost = host;
      result.appType = classifySni(host);
      result.dpi = {
        protocol: 'HTTP',
        host,
        method: asciiHeader.split(' ')[0],
        app: result.appType.name,
      };
      return;
    }
  }

  // 3. DNS Query extraction (port 53)
  if (result.transport && (result.transport.dstPort === 53 || result.transport.srcPort === 53)) {
    if (len >= 12) {
      const isQuery = (payload[2] & 0x80) === 0;
      const qdCount = (payload[4] << 8) | payload[5];
      if (qdCount > 0) {
        const query = extractDnsQuery(payload, 12);
        if (query) {
          result.sniOrHost = query;
          const detected = classifySni(query);
          result.appType = (detected !== APP_TYPES.HTTPS && detected !== APP_TYPES.UNKNOWN) ? detected : APP_TYPES.DNS;
          result.dpi = {
            protocol: 'DNS',
            type: isQuery ? 'Query' : 'Response',
            domain: query,
            app: result.appType.name,
          };
          return;
        }
      }
    }
  }
}

function extractTlsSni(payload) {
  try {
    let curr = 5; // Skip TLS record header
    curr += 4; // Skip Handshake header (type + 3 bytes length)
    curr += 2; // Client version
    curr += 32; // Random

    if (curr >= payload.length) return null;
    const sessionIdLen = payload[curr];
    curr += 1 + sessionIdLen;

    if (curr + 2 > payload.length) return null;
    const cipherSuitesLen = (payload[curr] << 8) | payload[curr + 1];
    curr += 2 + cipherSuitesLen;

    if (curr >= payload.length) return null;
    const compressionLen = payload[curr];
    curr += 1 + compressionLen;

    if (curr + 2 > payload.length) return null;
    const extensionsLen = (payload[curr] << 8) | payload[curr + 1];
    curr += 2;

    const end = Math.min(curr + extensionsLen, payload.length);
    while (curr + 4 <= end) {
      const extType = (payload[curr] << 8) | payload[curr + 1];
      const extLen = (payload[curr + 2] << 8) | payload[curr + 3];
      curr += 4;

      if (curr + extLen > end) break;

      if (extType === 0x0000) {
        // SNI Extension
        if (extLen < 5) break;
        const sniListLen = (payload[curr] << 8) | payload[curr + 1];
        const sniType = payload[curr + 2];
        const sniLen = (payload[curr + 3] << 8) | payload[curr + 4];

        if (sniType === 0x00 && sniLen <= extLen - 5 && curr + 5 + sniLen <= payload.length) {
          return bytesToAscii(payload.slice(curr + 5, curr + 5 + sniLen));
        }
      }
      curr += extLen;
    }
  } catch (e) {
    return null;
  }
  return null;
}

function extractDnsQuery(payload, offset) {
  try {
    let curr = offset;
    const parts = [];
    while (curr < payload.length) {
      const labelLen = payload[curr];
      if (labelLen === 0) break;
      if (labelLen > 63 || curr + 1 + labelLen > payload.length) break;
      curr++;
      parts.push(bytesToAscii(payload.slice(curr, curr + labelLen)));
      curr += labelLen;
    }
    return parts.length > 0 ? parts.join('.') : null;
  } catch (e) {
    return null;
  }
}

function formatMac(bytes, offset) {
  const parts = [];
  for (let i = 0; i < 6; i++) {
    parts.push(bytes[offset + i].toString(16).padStart(2, '0'));
  }
  return parts.join(':');
}

function formatTcpFlags(flags) {
  const names = [];
  if (flags & 0x02) names.push('SYN');
  if (flags & 0x10) names.push('ACK');
  if (flags & 0x01) names.push('FIN');
  if (flags & 0x04) names.push('RST');
  if (flags & 0x08) names.push('PSH');
  if (flags & 0x20) names.push('URG');
  return names.length > 0 ? names.join(' ') : 'none';
}

function formatTimestamp(sec, usec) {
  const d = new Date(sec * 1000);
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${d.getHours()}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(usec, 6)}`;
}

function bytesToAscii(bytes) {
  let str = '';
  for (let i = 0; i < bytes.length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}
