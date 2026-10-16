'use client';

import React, { useRef } from 'react';
import { Activity, Upload, Play, ShieldAlert, Cpu, BarChart2, FileText, CheckCircle2 } from 'lucide-react';

export default function Header({
  activeTab,
  setActiveTab,
  onLoadDemo,
  onFileUpload,
  packetCount,
  isLoading,
  fileName,
}) {
  const fileInputRef = useRef(null);

  return (
    <header style={{
      borderBottom: '1px solid var(--border-subtle)',
      background: 'rgba(7, 9, 14, 0.85)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '12px 24px',
    }}>
      <div style={{
        maxWidth: '1600px',
        margin: '0 auto',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px',
      }}>
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-purple))',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(0, 242, 254, 0.3)',
          }}>
            <Activity size={22} color="#07090e" strokeWidth={2.5} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '1.25rem', fontWeight: 700, letterSpacing: '-0.02em', background: 'linear-gradient(90deg, #fff, #cbd5e1)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                DPI Engine & Network Packet Analyzer
              </h1>
              <span style={{
                fontSize: '0.7rem',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '999px',
                background: 'rgba(0, 242, 254, 0.1)',
                color: 'var(--accent-cyan)',
                border: '1px solid rgba(0, 242, 254, 0.25)',
              }}>
                v2.0 Dual Core
              </span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
              <span className="live-dot"></span>
              {fileName ? `Active Capture: ${fileName} (${packetCount} packets)` : 'Ready to inspect network traffic'}
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <input
            type="file"
            accept=".pcap,.cap"
            ref={fileInputRef}
            onChange={onFileUpload}
            style={{ display: 'none' }}
          />

          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={isLoading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              color: 'var(--text-main)',
              fontSize: '0.85rem',
              fontWeight: 500,
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
            onMouseOver={(e) => { e.currentTarget.style.background = 'rgba(255, 255, 255, 0.1)'; }}
            onMouseOut={(e) => { e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)'; }}
          >
            <Upload size={16} />
            <span>Upload PCAP</span>
          </button>

          <button
            onClick={onLoadDemo}
            disabled={isLoading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.2), rgba(139, 92, 246, 0.2))',
              border: '1px solid var(--border-accent)',
              borderRadius: '8px',
              color: '#fff',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: '0 0 14px rgba(0, 242, 254, 0.15)',
              transition: 'all 0.2s ease',
            }}
            onMouseOver={(e) => { e.currentTarget.style.boxShadow = '0 0 20px rgba(0, 242, 254, 0.35)'; }}
            onMouseOut={(e) => { e.currentTarget.style.boxShadow = '0 0 14px rgba(0, 242, 254, 0.15)'; }}
          >
            <Play size={16} fill="var(--accent-cyan)" color="var(--accent-cyan)" />
            <span>{isLoading ? 'Analyzing...' : 'Load Demo Capture'}</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{
        maxWidth: '1600px',
        margin: '12px auto 0 auto',
        display: 'flex',
        gap: '6px',
        borderTop: '1px solid rgba(255, 255, 255, 0.05)',
        paddingTop: '10px',
        overflowX: 'auto',
      }}>
        {[
          { id: 'dissector', label: 'Wireshark Packet Dissector', icon: Activity },
          { id: 'analytics', label: 'DPI & Application Analytics', icon: BarChart2 },
          { id: 'firewall', label: 'Firewall & Rule Filtering', icon: ShieldAlert },
          { id: 'threads', label: 'Multi-Core Engine Pipeline', icon: Cpu },
          { id: 'resume', label: 'Resume & Architecture Showcase', icon: FileText },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                borderRadius: '8px',
                background: isActive ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                border: isActive ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
                fontSize: '0.85rem',
                fontWeight: isActive ? 600 : 500,
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.15s ease',
              }}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
}
