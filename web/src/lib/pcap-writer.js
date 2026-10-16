// Binary PCAP Exporter - generates downloadable .pcap files in browser

export function exportFilteredPcap(packets, globalHeader) {
  // Calculate total buffer size
  let totalSize = 24; // Global header
  const forwardedPackets = packets.filter(p => p.action === 'FORWARD');

  for (const pkt of forwardedPackets) {
    totalSize += 16 + pkt.rawBytes.length;
  }

  const buffer = new ArrayBuffer(totalSize);
  const dataView = new DataView(buffer);
  const uint8 = new Uint8Array(buffer);

  // Write Global Header (24 bytes)
  const le = globalHeader?.littleEndian ?? true;
  dataView.setUint32(0, 0xa1b2c3d4, le);
  dataView.setUint16(4, 2, le);
  dataView.setUint16(6, 4, le);
  dataView.setInt32(8, 0, le);
  dataView.setUint32(12, 0, le);
  dataView.setUint32(16, 65535, le);
  dataView.setUint32(20, 1, le); // Ethernet

  let offset = 24;
  for (const pkt of forwardedPackets) {
    const rawLen = pkt.rawBytes.length;
    dataView.setUint32(offset, pkt.tsSec, le);
    dataView.setUint32(offset + 4, pkt.tsUsec, le);
    dataView.setUint32(offset + 8, rawLen, le);
    dataView.setUint32(offset + 12, rawLen, le);
    offset += 16;

    uint8.set(pkt.rawBytes, offset);
    offset += rawLen;
  }

  const blob = new Blob([buffer], { type: 'application/vnd.tcpdump.pcap' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `filtered_capture_${Date.now()}.pcap`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
