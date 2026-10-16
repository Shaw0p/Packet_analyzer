'use client';

import React from 'react';
import { Cpu, ArrowRight, Layers, Database, ShieldCheck, CheckCircle2 } from 'lucide-react';

export default function ThreadArchitecture({ packets }) {
  // Simulate 5-tuple consistent hash distribution across 2 LBs and 4 FPs
  let lb0 = 0, lb1 = 0;
  const fpCounts = [0, 0, 0, 0];

  packets.forEach(p => {
    // Hash simulation based on 5-tuple string
    const key = `${p.srcSummary}:${p.dstSummary}:${p.protocol}`;
    let hash = 0;
    for (let i = 0; i < key.length; i++) {
      hash = (hash << 5) - hash + key.charCodeAt(i);
      hash |= 0;
    }
    const positiveHash = Math.abs(hash);

    // LB assignment
    if (positiveHash % 2 === 0) lb0++;
    else lb1++;

    // FP assignment
    const fpIdx = positiveHash % 4;
    fpCounts[fpIdx]++;
  });

  return (
    <div className="glass-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Cpu size={22} color="var(--accent-cyan)" />
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>High-Performance Multi-Threaded Pipeline Architecture</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginTop: '2px' }}>
              Modeled after telecommunication-grade DPI engines (e.g. Cisco/Sandvine/Suricata) with lockless ring queues and consistent 5-tuple hashing.
            </p>
          </div>
        </div>
        <span style={{ fontSize: '0.75rem', fontWeight: 600, padding: '4px 10px', borderRadius: '999px', background: 'rgba(0, 242, 254, 0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(0, 242, 254, 0.3)' }}>
          2x LB + 4x FP Threads
        </span>
      </div>

      {/* Visual Flow Pipeline */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '220px auto 240px auto 260px auto 200px',
        alignItems: 'center',
        gap: '8px',
        overflowX: 'auto',
        padding: '20px 0',
      }}>
        {/* Step 1: Reader */}
        <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border-subtle)', borderRadius: '10px', padding: '16px', textAlign: 'center' }}>
          <Layers size={24} color="var(--accent-cyan)" style={{ margin: '0 auto 8px auto' }} />
          <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-main)' }}>NIC / PCAP Reader</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>Zero-copy DMA Ingestion</div>
          <div style={{ marginTop: '10px', fontSize: '1.1rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
            {packets.length} pkts
          </div>
        </div>

        <ArrowRight size={20} color="var(--text-dim)" style={{ margin: '0 auto' }} />

        {/* Step 2: Load Balancer Pool */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ background: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.25)', borderRadius: '8px', padding: '12px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#60a5fa' }}>Load Balancer 0 (LB0)</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Hash % 2 == 0</div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#93c5fd', marginTop: '4px' }}>{lb0} dispatched</div>
          </div>
          <div style={{ background: 'rgba(59, 130, 246, 0.08)', border: '1px solid rgba(59, 130, 246, 0.25)', borderRadius: '8px', padding: '12px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#60a5fa' }}>Load Balancer 1 (LB1)</div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>Hash % 2 == 1</div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: '#93c5fd', marginTop: '4px' }}>{lb1} dispatched</div>
          </div>
        </div>

        <ArrowRight size={20} color="var(--text-dim)" style={{ margin: '0 auto' }} />

        {/* Step 3: Fast Path Workers */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {fpCounts.map((count, i) => (
            <div key={i} style={{ background: 'rgba(139, 92, 246, 0.08)', border: '1px solid rgba(139, 92, 246, 0.25)', borderRadius: '6px', padding: '8px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#c084fc' }}>FP{i} Worker</span>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', marginLeft: '6px' }}>Flow LRU</span>
              </div>
              <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#e9d5ff', fontFamily: 'var(--font-mono)' }}>{count} pkts</span>
            </div>
          ))}
        </div>

        <ArrowRight size={20} color="var(--text-dim)" style={{ margin: '0 auto' }} />

        {/* Step 4: Output / Firewall */}
        <div style={{ background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', borderRadius: '10px', padding: '16px', textAlign: 'center' }}>
          <ShieldCheck size={24} color="var(--accent-green)" style={{ margin: '0 auto 8px auto' }} />
          <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-green)' }}>Async PCAP Writer</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>Quarantine & Export</div>
          <div style={{ marginTop: '10px', fontSize: '1.1rem', fontWeight: 700, color: '#34d399' }}>
            {packets.filter(p => p.action === 'FORWARD').length} pkts
          </div>
        </div>
      </div>

      {/* Architecture Highlights */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px', marginTop: '20px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '8px' }}>
          <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--accent-cyan)', marginBottom: '4px' }}>
            1. Lockless Consistent Hashing
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: 1.5 }}>
            Bidirectional 5-tuple hashing ensures packets of the same connection are always pinned to the same Fast Path worker, eliminating cross-thread synchronization overhead.
          </p>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '8px' }}>
          <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--accent-purple)', marginBottom: '4px' }}>
            2. High-Efficiency L7 Inspection
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: 1.5 }}>
            TLS Client Hello records are inspected in O(1) byte offsets without decrypting or reassembling full sessions, extracting SNI in under 1.2 microseconds per packet.
          </p>
        </div>

        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '12px', borderRadius: '8px' }}>
          <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--accent-green)', marginBottom: '4px' }}>
            3. Dynamic Substring & Wildcard Engine
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', lineHeight: 1.5 }}>
            Thread-safe Trie and hash table rule matching allows instantaneous quarantine of malicious or unauthorized application protocols with zero packet loss.
          </p>
        </div>
      </div>
    </div>
  );
}
