'use client';

import React, { useState, useMemo } from 'react';
import { Search, Filter, ShieldAlert, ChevronRight, ChevronDown, Binary, Eye } from 'lucide-react';

export default function PacketViewer({ packets, selectedPacket, setSelectedPacket }) {
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [expandedSections, setExpandedSections] = useState({
    frame: true,
    ethernet: true,
    ip: true,
    transport: true,
    dpi: true,
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  // Filtered packets
  const filteredPackets = useMemo(() => {
    return packets.filter(p => {
      // Protocol filter
      if (protocolFilter !== 'ALL') {
        if (protocolFilter === 'TLS' && p.dpi?.protocol !== 'TLS') return false;
        if (protocolFilter === 'DNS' && p.dpi?.protocol !== 'DNS' && p.protocol !== 'DNS') return false;
        if (protocolFilter === 'HTTP' && p.dpi?.protocol !== 'HTTP' && p.protocol !== 'HTTP') return false;
        if (protocolFilter === 'TCP' && p.protocol !== 'TCP') return false;
        if (protocolFilter === 'UDP' && p.protocol !== 'UDP') return false;
      }

      // Action filter
      if (actionFilter !== 'ALL' && p.action !== actionFilter) return false;

      // Search term
      if (search.trim()) {
        const q = search.toLowerCase();
        const inSrc = p.srcSummary.toLowerCase().includes(q);
        const inDst = p.dstSummary.toLowerCase().includes(q);
        const inSni = (p.sniOrHost || '').toLowerCase().includes(q);
        const inApp = (p.appType?.name || '').toLowerCase().includes(q);
        const inProto = p.protocol.toLowerCase().includes(q);
        if (!inSrc && !inDst && !inSni && !inApp && !inProto) return false;
      }

      return true;
    });
  }, [packets, search, protocolFilter, actionFilter]);

  // Format Hex Dump
  const hexDump = useMemo(() => {
    if (!selectedPacket || !selectedPacket.rawBytes) return [];
    const bytes = selectedPacket.rawBytes;
    const rows = [];

    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.slice(i, i + 16);
      const offsetHex = i.toString(16).padStart(4, '0');

      const hexParts = [];
      const asciiParts = [];

      for (let j = 0; j < 16; j++) {
        if (j < slice.length) {
          const b = slice[j];
          hexParts.push(b.toString(16).padStart(2, '0'));
          // Printable ASCII (32 to 126)
          asciiParts.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : '·');
        } else {
          hexParts.push('  ');
          asciiParts.push(' ');
        }
      }

      rows.push({
        offset: offsetHex,
        hex1: hexParts.slice(0, 8).join(' '),
        hex2: hexParts.slice(8, 16).join(' '),
        ascii: asciiParts.join(''),
      });
    }

    return rows;
  }, [selectedPacket]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Top Filter Bar */}
      <div className="glass-panel" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
        {/* Search Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(0, 0, 0, 0.3)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '6px 12px', flex: '1', minWidth: '240px' }}>
          <Search size={16} color="var(--text-dim)" />
          <input
            type="text"
            placeholder="Filter by IP, domain, SNI, app (e.g. youtube, 192.168.1, SYN)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--text-main)',
              fontSize: '0.85rem',
              width: '100%',
              fontFamily: 'var(--font-mono)',
            }}
          />
          {search && (
            <button onClick={() => setSearch('')} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: '0.8rem' }}>✕</button>
          )}
        </div>

        {/* Quick Protocol Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
          {['ALL', 'TLS', 'DNS', 'HTTP', 'TCP', 'UDP'].map((proto) => (
            <button
              key={proto}
              onClick={() => setProtocolFilter(proto)}
              style={{
                padding: '4px 10px',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer',
                background: protocolFilter === proto ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.05)',
                color: protocolFilter === proto ? '#07090e' : 'var(--text-muted)',
                border: '1px solid ' + (protocolFilter === proto ? 'var(--accent-cyan)' : 'var(--border-subtle)'),
                transition: 'all 0.15s ease',
              }}
            >
              {proto}
            </button>
          ))}
        </div>

        {/* Action filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          {['ALL', 'FORWARD', 'DROP'].map((act) => (
            <button
              key={act}
              onClick={() => setActionFilter(act)}
              style={{
                padding: '4px 10px',
                borderRadius: '6px',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer',
                background: actionFilter === act ? (act === 'DROP' ? 'var(--accent-red)' : 'var(--accent-green)') : 'rgba(255, 255, 255, 0.05)',
                color: actionFilter === act ? '#fff' : 'var(--text-muted)',
                border: '1px solid ' + (actionFilter === act ? (act === 'DROP' ? 'var(--accent-red)' : 'var(--accent-green)') : 'var(--border-subtle)'),
              }}
            >
              {act === 'ALL' ? 'All Status' : act === 'FORWARD' ? 'Forwarded' : 'Blocked'}
            </button>
          ))}
        </div>
      </div>

      {/* Pane 1: Wireshark Packet List */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div style={{
          maxHeight: '340px',
          overflowY: 'auto',
          position: 'relative',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            <thead style={{ position: 'sticky', top: 0, background: '#0e131f', zIndex: 10, borderBottom: '1px solid var(--border-subtle)' }}>
              <tr style={{ color: 'var(--text-muted)' }}>
                <th style={{ padding: '10px 14px', width: '60px' }}>No.</th>
                <th style={{ padding: '10px 14px', width: '110px' }}>Time</th>
                <th style={{ padding: '10px 14px' }}>Source</th>
                <th style={{ padding: '10px 14px' }}>Destination</th>
                <th style={{ padding: '10px 14px', width: '90px' }}>Proto</th>
                <th style={{ padding: '10px 14px', width: '70px' }}>Len</th>
                <th style={{ padding: '10px 14px' }}>L7 App / Domain (DPI)</th>
                <th style={{ padding: '10px 14px', width: '100px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan="8" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)' }}>
                    No packets match current filter. Click "Load Demo Capture" or upload a PCAP.
                  </td>
                </tr>
              ) : (
                filteredPackets.map((pkt) => {
                  const isSelected = selectedPacket?.id === pkt.id;
                  const isBlocked = pkt.action === 'DROP';

                  return (
                    <tr
                      key={pkt.id}
                      onClick={() => setSelectedPacket(pkt)}
                      style={{
                        cursor: 'pointer',
                        background: isSelected
                          ? 'rgba(0, 242, 254, 0.15)'
                          : isBlocked
                          ? 'rgba(239, 68, 68, 0.08)'
                          : 'transparent',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                        color: isBlocked ? '#fca5a5' : 'var(--text-main)',
                        transition: 'background 0.15s ease',
                      }}
                      onMouseOver={(e) => {
                        if (!isSelected) {
                          e.currentTarget.style.background = isBlocked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(255, 255, 255, 0.03)';
                        }
                      }}
                      onMouseOut={(e) => {
                        if (!isSelected) {
                          e.currentTarget.style.background = isBlocked ? 'rgba(239, 68, 68, 0.08)' : 'transparent';
                        }
                      }}
                    >
                      <td style={{ padding: '8px 14px', color: 'var(--text-dim)' }}>{pkt.id}</td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-muted)' }}>{pkt.timestampFormatted}</td>
                      <td style={{ padding: '8px 14px' }}>{pkt.srcSummary}</td>
                      <td style={{ padding: '8px 14px' }}>{pkt.dstSummary}</td>
                      <td style={{ padding: '8px 14px' }}>
                        <span style={{
                          padding: '2px 6px',
                          borderRadius: '4px',
                          fontSize: '0.7rem',
                          fontWeight: 600,
                          background: pkt.protocol === 'TCP' ? 'rgba(59, 130, 246, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                          color: pkt.protocol === 'TCP' ? '#60a5fa' : '#c084fc',
                        }}>
                          {pkt.protocol}
                        </span>
                      </td>
                      <td style={{ padding: '8px 14px', color: 'var(--text-dim)' }}>{pkt.length} B</td>
                      <td style={{ padding: '8px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {pkt.appType?.name && pkt.appType.name !== 'Unknown' && (
                            <span style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              fontSize: '0.7rem',
                              fontWeight: 600,
                              background: `${pkt.appType.color}22`,
                              color: pkt.appType.color,
                              border: `1px solid ${pkt.appType.color}44`,
                            }}>
                              {pkt.appType.name}
                            </span>
                          )}
                          <span style={{ color: pkt.sniOrHost ? 'var(--text-main)' : 'var(--text-dim)' }}>
                            {pkt.sniOrHost || (pkt.transport?.flagsString ? `[${pkt.transport.flagsString}]` : '-')}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: '8px 14px' }}>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '999px',
                          background: isBlocked ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.15)',
                          color: isBlocked ? '#ef4444' : '#10b981',
                          border: isBlocked ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(16, 185, 129, 0.3)',
                        }}>
                          {isBlocked ? 'BLOCKED' : 'FORWARD'}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom 2-Pane: Protocol Dissection Tree & Hex Dump */}
      {selectedPacket && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
          {/* Pane 2: Protocol Tree */}
          <div className="glass-panel" style={{ padding: '16px', maxHeight: '420px', overflowY: 'auto' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <Eye size={18} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-main)' }}>
                Protocol Tree Dissection (Packet #{selectedPacket.id})
              </h3>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
              {/* Frame Section */}
              <div>
                <div
                  onClick={() => toggleSection('frame')}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', color: 'var(--accent-cyan)', fontWeight: 600 }}
                >
                  {expandedSections.frame ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  <span>Frame {selectedPacket.id}: {selectedPacket.length} bytes on wire</span>
                </div>
                {expandedSections.frame && (
                  <div style={{ marginLeft: '20px', marginTop: '4px', color: 'var(--text-muted)' }}>
                    <div>Arrival Time: {selectedPacket.timestampFormatted} ({selectedPacket.tsSec}.{selectedPacket.tsUsec})</div>
                    <div>Frame Length: {selectedPacket.length} bytes ({selectedPacket.length * 8} bits)</div>
                    <div>Capture Status: {selectedPacket.action === 'DROP' ? 'DROPPED BY FIREWALL' : 'FORWARDED'}</div>
                  </div>
                )}
              </div>

              {/* Ethernet II */}
              {selectedPacket.ethernet && (
                <div>
                  <div
                    onClick={() => toggleSection('ethernet')}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', color: '#60a5fa', fontWeight: 600 }}
                  >
                    {expandedSections.ethernet ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    <span>Ethernet II, Src: {selectedPacket.ethernet.srcMac}, Dst: {selectedPacket.ethernet.dstMac}</span>
                  </div>
                  {expandedSections.ethernet && (
                    <div style={{ marginLeft: '20px', marginTop: '4px', color: 'var(--text-muted)' }}>
                      <div>Destination MAC: {selectedPacket.ethernet.dstMac}</div>
                      <div>Source MAC: {selectedPacket.ethernet.srcMac}</div>
                      <div>Type: IPv4 ({selectedPacket.ethernet.etherTypeHex})</div>
                    </div>
                  )}
                </div>
              )}

              {/* IPv4 */}
              {selectedPacket.ip && (
                <div>
                  <div
                    onClick={() => toggleSection('ip')}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', color: '#38bdf8', fontWeight: 600 }}
                  >
                    {expandedSections.ip ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    <span>Internet Protocol Version 4, Src: {selectedPacket.ip.srcIp}, Dst: {selectedPacket.ip.dstIp}</span>
                  </div>
                  {expandedSections.ip && (
                    <div style={{ marginLeft: '20px', marginTop: '4px', color: 'var(--text-muted)' }}>
                      <div>Version: {selectedPacket.ip.version}</div>
                      <div>Header Length: {selectedPacket.ip.headerLength} bytes ({selectedPacket.ip.ihl} words)</div>
                      <div>Total Length: {selectedPacket.ip.totalLength} bytes</div>
                      <div>Time to Live: {selectedPacket.ip.ttl} hops</div>
                      <div>Protocol: {selectedPacket.ip.protocolName} ({selectedPacket.ip.protocolNum})</div>
                      <div>Source IP: {selectedPacket.ip.srcIp}</div>
                      <div>Destination IP: {selectedPacket.ip.dstIp}</div>
                    </div>
                  )}
                </div>
              )}

              {/* Transport (TCP/UDP) */}
              {selectedPacket.transport && (
                <div>
                  <div
                    onClick={() => toggleSection('transport')}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', color: '#c084fc', fontWeight: 600 }}
                  >
                    {expandedSections.transport ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    <span>
                      {selectedPacket.transport.type}: Src Port: {selectedPacket.transport.srcPort}, Dst Port: {selectedPacket.transport.dstPort}
                    </span>
                  </div>
                  {expandedSections.transport && (
                    <div style={{ marginLeft: '20px', marginTop: '4px', color: 'var(--text-muted)' }}>
                      <div>Source Port: {selectedPacket.transport.srcPort}</div>
                      <div>Destination Port: {selectedPacket.transport.dstPort}</div>
                      {selectedPacket.transport.type === 'TCP' && (
                        <>
                          <div>Sequence Number: {selectedPacket.transport.seq}</div>
                          <div>Acknowledgment Number: {selectedPacket.transport.ack}</div>
                          <div>Header Length: {selectedPacket.transport.headerLength} bytes</div>
                          <div>Flags: 0x{selectedPacket.transport.flags.toString(16).padStart(2, '0')} ({selectedPacket.transport.flagsString})</div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Layer 7 Deep Packet Inspection (DPI) */}
              {selectedPacket.dpi && (
                <div style={{ background: 'rgba(0, 242, 254, 0.05)', border: '1px solid rgba(0, 242, 254, 0.2)', borderRadius: '6px', padding: '8px' }}>
                  <div
                    onClick={() => toggleSection('dpi')}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer', color: 'var(--accent-cyan)', fontWeight: 700 }}
                  >
                    {expandedSections.dpi ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    <span>Layer 7 Deep Packet Inspection ({selectedPacket.dpi.protocol})</span>
                  </div>
                  {expandedSections.dpi && (
                    <div style={{ marginLeft: '20px', marginTop: '6px', color: '#e2e8f0' }}>
                      {selectedPacket.dpi.handshake && <div>Handshake Type: {selectedPacket.dpi.handshake}</div>}
                      {selectedPacket.dpi.sni && <div>Server Name Indication (SNI): <strong style={{ color: 'var(--accent-cyan)' }}>{selectedPacket.dpi.sni}</strong></div>}
                      {selectedPacket.dpi.host && <div>HTTP Host Header: <strong style={{ color: 'var(--accent-cyan)' }}>{selectedPacket.dpi.host}</strong></div>}
                      {selectedPacket.dpi.domain && <div>Queried Domain: <strong style={{ color: 'var(--accent-purple)' }}>{selectedPacket.dpi.domain}</strong></div>}
                      <div style={{ marginTop: '4px' }}>
                        Application Identified: <span style={{ padding: '2px 8px', borderRadius: '4px', background: `${selectedPacket.appType?.color}22`, color: selectedPacket.appType?.color, fontWeight: 700 }}>{selectedPacket.dpi.app}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Pane 3: Hex & ASCII Dump Viewer */}
          <div className="glass-panel" style={{ padding: '16px', maxHeight: '420px', overflowY: 'auto' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <Binary size={18} color="var(--accent-purple)" />
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-main)' }}>
                Hex & ASCII Payload Dump ({selectedPacket.length} bytes)
              </h3>
            </div>

            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              lineHeight: '1.6',
              whiteSpace: 'pre',
              overflowX: 'auto',
              color: 'var(--text-muted)',
              background: 'rgba(0, 0, 0, 0.4)',
              padding: '12px',
              borderRadius: '8px',
              border: '1px solid rgba(255, 255, 255, 0.05)',
            }}>
              {hexDump.map((row, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '16px' }}>
                  <span style={{ color: 'var(--accent-cyan)', userSelect: 'none' }}>{row.offset}</span>
                  <span style={{ color: '#cbd5e1' }}>{row.hex1}  {row.hex2}</span>
                  <span style={{ color: 'var(--accent-amber)', borderLeft: '1px solid rgba(255, 255, 255, 0.1)', paddingLeft: '12px' }}>
                    {row.ascii}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
