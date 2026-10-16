'use client';

import React, { useState } from 'react';
import { Shield, ShieldAlert, Plus, Trash2, Download, Check, AlertCircle } from 'lucide-react';
import { exportFilteredPcap } from '../lib/pcap-writer';

export default function FirewallRules({ rules, onAddRule, onRemoveRule, onClearRules, packets, globalHeader }) {
  const [ruleType, setRuleType] = useState('APP');
  const [ruleValue, setRuleValue] = useState('YouTube');

  const appsList = [
    'YouTube', 'Facebook', 'Instagram', 'Twitter/X', 'Netflix',
    'TikTok', 'Amazon', 'Spotify', 'Discord', 'Telegram', 'Google', 'Apple'
  ];

  const handleAdd = (e) => {
    e.preventDefault();
    if (!ruleValue.trim()) return;
    onAddRule({ type: ruleType, value: ruleValue.trim() });
    if (ruleType !== 'APP') {
      setRuleValue('');
    }
  };

  const droppedPackets = packets.filter(p => p.action === 'DROP');
  const forwardedPackets = packets.filter(p => p.action === 'FORWARD');

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
      {/* Rule Creator */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldAlert size={18} color="var(--accent-red)" />
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Firewall Rule Enforcement</h3>
          </div>
          {rules.length > 0 && (
            <button
              onClick={onClearRules}
              style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#ef4444',
                padding: '4px 8px',
                borderRadius: '6px',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              Clear All Rules
            </button>
          )}
        </div>

        {/* Add Form */}
        <form onSubmit={handleAdd} style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '20px' }}>
          <div style={{ display: 'flex', gap: '10px' }}>
            <select
              value={ruleType}
              onChange={(e) => {
                setRuleType(e.target.value);
                if (e.target.value === 'APP') setRuleValue('YouTube');
                else setRuleValue('');
              }}
              style={{
                background: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                padding: '8px 12px',
                borderRadius: '8px',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            >
              <option value="APP">Block Application</option>
              <option value="DOMAIN">Block Domain Wildcard</option>
              <option value="IP">Block Source IP</option>
              <option value="PORT">Block Port</option>
            </select>

            {ruleType === 'APP' ? (
              <select
                value={ruleValue}
                onChange={(e) => setRuleValue(e.target.value)}
                style={{
                  flex: 1,
                  background: 'rgba(0, 0, 0, 0.4)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  borderRadius: '8px',
                  fontSize: '0.85rem',
                  outline: 'none',
                }}
              >
                {appsList.map(a => (
                  <option key={a} value={a}>{a}</option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                placeholder={ruleType === 'IP' ? 'e.g. 192.168.1.100' : ruleType === 'PORT' ? 'e.g. 443' : 'e.g. *.tiktok.com'}
                value={ruleValue}
                onChange={(e) => setRuleValue(e.target.value)}
                style={{
                  flex: 1,
                  background: 'rgba(0, 0, 0, 0.4)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  borderRadius: '8px',
                  fontSize: '0.85rem',
                  outline: 'none',
                  fontFamily: 'var(--font-mono)',
                }}
              />
            )}

            <button
              type="submit"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'var(--accent-red)',
                border: 'none',
                color: '#fff',
                padding: '8px 14px',
                borderRadius: '8px',
                fontWeight: 600,
                fontSize: '0.85rem',
                cursor: 'pointer',
              }}
            >
              <Plus size={16} />
              <span>Enforce</span>
            </button>
          </div>
        </form>

        {/* Active Rules List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '240px', overflowY: 'auto' }}>
          {rules.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-dim)', border: '1px dashed var(--border-subtle)', borderRadius: '8px' }}>
              No active blocking rules. All traffic is being forwarded.
            </div>
          ) : (
            rules.map((r, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  background: 'rgba(239, 68, 68, 0.08)',
                  border: '1px solid rgba(239, 68, 68, 0.25)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444' }}>
                    {r.type}
                  </span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-main)', fontWeight: 600 }}>
                    {r.value}
                  </span>
                </div>
                <button
                  onClick={() => onRemoveRule(i)}
                  style={{ background: 'none', border: 'none', color: '#fca5a5', cursor: 'pointer' }}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Live Impact & PCAP Exporter */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
            <Shield size={18} color="var(--accent-green)" />
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Real-Time Policy Impact</h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '20px' }}>
            <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.25)', borderRadius: '8px', padding: '14px' }}>
              <div style={{ fontSize: '0.75rem', color: '#34d399', fontWeight: 600, marginBottom: '4px' }}>FORWARDED PACKETS</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#10b981' }}>{forwardedPackets.length}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '2px' }}>Sanitized traffic saved in output</div>
            </div>

            <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: '8px', padding: '14px' }}>
              <div style={{ fontSize: '0.75rem', color: '#f87171', fontWeight: 600, marginBottom: '4px' }}>DROPPED PACKETS</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#ef4444' }}>{droppedPackets.length}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '2px' }}>Filtered by active rules</div>
            </div>
          </div>

          {droppedPackets.length > 0 && (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', background: 'rgba(0,0,0,0.3)', padding: '10px 14px', borderRadius: '6px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertCircle size={16} color="var(--accent-red)" />
              <span>
                Matching flows were immediately quarantined and dropped from downstream transmission.
              </span>
            </div>
          )}
        </div>

        {/* Export Button */}
        <div>
          <button
            onClick={() => exportFilteredPcap(packets, globalHeader)}
            disabled={packets.length === 0}
            style={{
              width: '100%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              padding: '12px',
              background: 'linear-gradient(135deg, var(--accent-cyan), var(--accent-blue))',
              border: 'none',
              borderRadius: '8px',
              color: '#07090e',
              fontSize: '0.95rem',
              fontWeight: 700,
              cursor: packets.length === 0 ? 'not-allowed' : 'pointer',
              opacity: packets.length === 0 ? 0.5 : 1,
              boxShadow: '0 0 16px rgba(0, 242, 254, 0.25)',
              transition: 'all 0.2s ease',
            }}
          >
            <Download size={18} />
            <span>Export Filtered PCAP File ({forwardedPackets.length} pkts)</span>
          </button>
          <p style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '8px' }}>
            Generates standard binary .pcap compatible with Wireshark and network appliances.
          </p>
        </div>
      </div>
    </div>
  );
}
