'use client';

import React, { useState } from 'react';
import { FileText, Copy, Check, Award, Server, Shield, Zap, GitBranch } from 'lucide-react';

export default function ResumePortfolio() {
  const [copiedIndex, setCopiedIndex] = useState(null);

  const bulletPoints = [
    {
      role: 'Backend / Systems Software Engineer',
      points: [
        'Engineered a multi-threaded Deep Packet Inspection (DPI) & Traffic Analyzer in Java/C++ capable of parsing binary PCAP network captures and classifying Layer 7 protocols with sub-millisecond latency.',
        'Designed a high-throughput pipeline utilizing consistent 5-tuple hashing to distribute network flows across parallel Fast Path worker threads without mutex contention.',
        'Implemented zero-copy binary parsers for Ethernet II, IPv4, TCP, and UDP headers, accurately tracking bidirectional flow state and TCP flag handshakes (SYN, ACK, FIN, RST).',
        'Built an L7 inspection engine extracting TLS Server Name Indication (SNI), HTTP Host headers, and DNS queries to categorize traffic across 20+ major enterprise applications.',
        'Developed an interactive Next.js web application deployed to Vercel featuring Wireshark-grade 3-pane packet dissection, live hex dump viewer, and an in-browser PCAP exporter.',
      ],
    },
    {
      role: 'Cybersecurity / Network Security Engineer',
      points: [
        'Architected a DPI firewall rule engine supporting real-time traffic quarantine by Source IP, Application signature, Destination Port, and wildcard domain patterns (*.domain.com).',
        'Implemented proactive SNI extraction to identify and enforce security policies on encrypted HTTPS traffic without terminating or decrypting TLS sessions.',
        'Built binary PCAP export capabilities allowing security analysts to inspect, filter, and download sanitized capture files directly compatible with Wireshark and Snort/Suricata.',
      ],
    },
  ];

  const handleCopy = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Banner */}
      <div className="glass-panel" style={{ padding: '24px', background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.08), rgba(139, 92, 246, 0.08))' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
          <Award size={26} color="var(--accent-cyan)" />
          <h2 style={{ fontSize: '1.3rem', fontWeight: 700 }}>Resume & Interview Portfolio Showcase</h2>
        </div>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', lineHeight: '1.6', maxWidth: '900px' }}>
          This project demonstrates production-grade systems engineering, network protocol dissection, concurrent architecture, and full-stack web delivery. Copy the tailored resume bullets below directly onto your CV.
        </p>
      </div>

      {/* Bullet Points Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        {bulletPoints.map((section, sIdx) => {
          const allText = section.points.map(p => `• ${p}`).join('\n');
          return (
            <div key={sIdx} className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Server size={18} color="var(--accent-purple)" />
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#fff' }}>{section.role}</h3>
                  </div>
                  <button
                    onClick={() => handleCopy(allText, sIdx)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      background: copiedIndex === sIdx ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid ' + (copiedIndex === sIdx ? 'var(--accent-green)' : 'var(--border-subtle)'),
                      color: copiedIndex === sIdx ? '#10b981' : 'var(--text-main)',
                      padding: '4px 10px',
                      borderRadius: '6px',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    {copiedIndex === sIdx ? <Check size={14} /> : <Copy size={14} />}
                    <span>{copiedIndex === sIdx ? 'Copied!' : 'Copy All'}</span>
                  </button>
                </div>

                <ul style={{ display: 'flex', flexDirection: 'column', gap: '10px', paddingLeft: '18px', color: '#cbd5e1', fontSize: '0.82rem', lineHeight: '1.55' }}>
                  {section.points.map((pt, pIdx) => (
                    <li key={pIdx}>
                      {pt}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          );
        })}
      </div>

      {/* Technical Highlights Grid for Interview Questions */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '14px', color: 'var(--accent-cyan)' }}>
          Technical Interview Talking Points (Key System Design Concepts)
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#38bdf8', fontWeight: 700, fontSize: '0.85rem', marginBottom: '6px' }}>
              <Zap size={16} />
              <span>Q: How does SNI extraction inspect encrypted HTTPS?</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: '1.5' }}>
              In TLS 1.2 and 1.3 handshakes, the initial <code>Client Hello</code> message is transmitted in plaintext before cryptographic key exchange finishes. The engine parses TLS Extension type <code>0x0000</code> to identify the requested hostname without requiring private keys or MITM proxies.
            </p>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#c084fc', fontWeight: 700, fontSize: '0.85rem', marginBottom: '6px' }}>
              <Server size={16} />
              <span>Q: How is thread safety achieved without lock contention?</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: '1.5' }}>
              We apply consistent hashing on the 5-tuple <code>(src_ip, dst_ip, src_port, dst_port, proto)</code>. Both directions of a connection map to the exact same Fast Path worker thread, ensuring each connection tracker operates independently without shared mutex bottlenecks.
            </p>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#34d399', fontWeight: 700, fontSize: '0.85rem', marginBottom: '6px' }}>
              <Shield size={16} />
              <span>Q: How does the in-browser PCAP parser handle endianness?</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: '1.5' }}>
              The first 4 bytes of any PCAP file specify the magic number: <code>0xa1b2c3d4</code> (native endian) or <code>0xd4c3b2a1</code> (swapped endian). Our binary parser automatically detects the byte order and adjusts all integer reads accordingly using <code>DataView</code>.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
