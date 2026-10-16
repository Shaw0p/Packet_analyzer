'use client';

import React from 'react';
import { BarChart3, Globe, Shield, Ban, ExternalLink } from 'lucide-react';

export default function DpiAnalytics({ packets, onAddRule }) {
  // Aggregate app distribution
  const appMap = {};
  const domainMap = {};
  let totalClassifiedPackets = 0;

  packets.forEach(p => {
    const app = p.appType?.name || 'Unknown';
    appMap[app] = (appMap[app] || { count: 0, bytes: 0, color: p.appType?.color || '#64748b' });
    appMap[app].count++;
    appMap[app].bytes += p.length;

    if (p.sniOrHost) {
      domainMap[p.sniOrHost] = (domainMap[p.sniOrHost] || { count: 0, app: p.appType?.name || 'Unknown', color: p.appType?.color });
      domainMap[p.sniOrHost].count++;
    }

    if (app !== 'Unknown') {
      totalClassifiedPackets++;
    }
  });

  const sortedApps = Object.entries(appMap).sort((a, b) => b[1].count - a[1].count);
  const sortedDomains = Object.entries(domainMap).sort((a, b) => b[1].count - a[1].count);
  const totalPackets = packets.length || 1;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
      {/* App Breakdown Panel */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <BarChart3 size={18} color="var(--accent-cyan)" />
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Application Layer Distribution</h3>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: '4px' }}>
            {sortedApps.length} Distinct Categories
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {sortedApps.map(([appName, data]) => {
            const pct = ((data.count / totalPackets) * 100).toFixed(1);
            return (
              <div key={appName}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: data.color }}></span>
                    <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{appName}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--text-muted)' }}>
                    <span>{data.count} pkts</span>
                    <span style={{ width: '45px', textAlign: 'right', fontWeight: 600, color: data.color }}>{pct}%</span>
                  </div>
                </div>
                {/* Progress bar */}
                <div style={{ width: '100%', height: '6px', background: 'rgba(255, 255, 255, 0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${pct}%`,
                    height: '100%',
                    background: data.color,
                    borderRadius: '3px',
                    transition: 'width 0.4s ease',
                  }}></div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detected Domains & SNI Table */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Globe size={18} color="var(--accent-purple)" />
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Detected Domains & SNIs (TLS/HTTP/DNS)</h3>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: '4px' }}>
            {sortedDomains.length} Extracted
          </span>
        </div>

        <div style={{ maxHeight: '360px', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            <thead style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
              <tr>
                <th style={{ padding: '8px 10px' }}>Extracted Domain</th>
                <th style={{ padding: '8px 10px' }}>App</th>
                <th style={{ padding: '8px 10px' }}>Traffic</th>
                <th style={{ padding: '8px 10px', textAlign: 'right' }}>Quick Block</th>
              </tr>
            </thead>
            <tbody>
              {sortedDomains.length === 0 ? (
                <tr>
                  <td colSpan="4" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)' }}>
                    No SNIs detected yet. Load a capture to analyze TLS handshakes.
                  </td>
                </tr>
              ) : (
                sortedDomains.map(([domain, info]) => (
                  <tr key={domain} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <td style={{ padding: '8px 10px', color: 'var(--text-main)', fontWeight: 500 }}>{domain}</td>
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '0.7rem',
                        fontWeight: 600,
                        background: `${info.color || '#64748b'}22`,
                        color: info.color || '#64748b',
                      }}>
                        {info.app}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', color: 'var(--text-muted)' }}>{info.count} pkts</td>
                    <td style={{ padding: '8px 10px', textAlign: 'right' }}>
                      <button
                        onClick={() => onAddRule({ type: 'DOMAIN', value: domain })}
                        style={{
                          background: 'rgba(239, 68, 68, 0.1)',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          color: '#ef4444',
                          padding: '3px 8px',
                          borderRadius: '4px',
                          fontSize: '0.7rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '4px',
                        }}
                      >
                        <Ban size={12} />
                        Block
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
