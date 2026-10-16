'use client';

import React from 'react';
import { Layers, HardDrive, CheckCircle, ShieldX, Globe2, Radio } from 'lucide-react';

export default function StatsCards({ packets, rules }) {
  const total = packets.length;
  const forwarded = packets.filter(p => p.action === 'FORWARD').length;
  const dropped = packets.filter(p => p.action === 'DROP').length;
  const totalBytes = packets.reduce((acc, p) => acc + (p.length || 0), 0);

  // Unique applications detected
  const apps = new Set(packets.map(p => p.appType?.name).filter(name => name && name !== 'Unknown' && name !== 'HTTPS' && name !== 'HTTP'));
  const classifiedCount = packets.filter(p => p.appType?.name && p.appType.name !== 'Unknown').length;
  const accuracy = total > 0 ? Math.round((classifiedCount / total) * 100) : 0;

  // Active flows (unique 5-tuples)
  const flows = new Set(packets.map(p => `${p.srcSummary}->${p.dstSummary}/${p.protocol}`));

  const formatBytes = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const cards = [
    {
      title: 'TOTAL PACKETS',
      value: total.toLocaleString(),
      sub: `${flows.size} Active 5-Tuple Flows`,
      icon: Layers,
      color: 'var(--accent-cyan)',
      bg: 'rgba(0, 242, 254, 0.08)',
    },
    {
      title: 'TOTAL BANDWIDTH',
      value: formatBytes(totalBytes),
      sub: `${total > 0 ? (totalBytes / total).toFixed(0) : 0} bytes avg packet`,
      icon: HardDrive,
      color: 'var(--accent-purple)',
      bg: 'rgba(139, 92, 246, 0.08)',
    },
    {
      title: 'FORWARDED TRAFFIC',
      value: forwarded.toLocaleString(),
      sub: `${total > 0 ? ((forwarded / total) * 100).toFixed(1) : 100}% permitted`,
      icon: CheckCircle,
      color: 'var(--accent-green)',
      bg: 'rgba(16, 185, 129, 0.08)',
    },
    {
      title: 'DROPPED / BLOCKED',
      value: dropped.toLocaleString(),
      sub: `${rules.length} active firewall rules`,
      icon: ShieldX,
      color: dropped > 0 ? 'var(--accent-red)' : 'var(--text-dim)',
      bg: dropped > 0 ? 'rgba(239, 68, 68, 0.12)' : 'rgba(255, 255, 255, 0.03)',
      glow: dropped > 0 ? 'glow-red' : '',
    },
    {
      title: 'DPI CLASSIFIED',
      value: `${accuracy}%`,
      sub: `${apps.size} distinct apps identified`,
      icon: Globe2,
      color: 'var(--accent-amber)',
      bg: 'rgba(245, 158, 11, 0.08)',
    },
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
      gap: '14px',
      marginBottom: '20px',
    }}>
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={i}
            className={`glass-panel ${card.glow || ''}`}
            style={{
              padding: '16px 18px',
              border: `1px solid ${card.dropped && card.dropped > 0 ? 'rgba(239, 68, 68, 0.3)' : 'var(--border-subtle)'}`,
              transition: 'transform 0.2s ease, border-color 0.2s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '0.7rem', fontWeight: 600, letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
                {card.title}
              </span>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: card.bg,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                <Icon size={17} color={card.color} />
              </div>
            </div>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, letterSpacing: '-0.02em', color: card.color, marginBottom: '4px' }}>
              {card.value}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
              {card.sub}
            </div>
          </div>
        );
      })}
    </div>
  );
}
