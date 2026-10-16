'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Header from '../components/Header';
import StatsCards from '../components/StatsCards';
import PacketViewer from '../components/PacketViewer';
import DpiAnalytics from '../components/DpiAnalytics';
import FirewallRules from '../components/FirewallRules';
import ThreadArchitecture from '../components/ThreadArchitecture';
import ResumePortfolio from '../components/ResumePortfolio';
import { parsePcapArrayBuffer } from '../lib/pcap-parser';

export default function Home() {
  const [activeTab, setActiveTab] = useState('dissector');
  const [packets, setPackets] = useState([]);
  const [globalHeader, setGlobalHeader] = useState(null);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [rules, setRules] = useState([
    { type: 'APP', value: 'YouTube' }
  ]);
  const [isLoading, setIsLoading] = useState(false);
  const [fileName, setFileName] = useState('');

  // Re-evaluate packets against active firewall rules
  const applyRules = useCallback((packetList, ruleList) => {
    return packetList.map(pkt => {
      let isBlocked = false;
      let blockReason = null;

      for (const rule of ruleList) {
        if (rule.type === 'APP' && pkt.appType?.name?.toLowerCase() === rule.value.toLowerCase()) {
          isBlocked = true;
          blockReason = `App: ${rule.value}`;
          break;
        }
        if (rule.type === 'IP' && (pkt.ip?.srcIp === rule.value || pkt.srcSummary.includes(rule.value))) {
          isBlocked = true;
          blockReason = `IP: ${rule.value}`;
          break;
        }
        if (rule.type === 'PORT' && (pkt.transport?.dstPort === parseInt(rule.value, 10))) {
          isBlocked = true;
          blockReason = `Port: ${rule.value}`;
          break;
        }
        if (rule.type === 'DOMAIN' && pkt.sniOrHost) {
          const pattern = rule.value.toLowerCase();
          const host = pkt.sniOrHost.toLowerCase();
          if (pattern.startsWith('*.')) {
            const suffix = pattern.substring(1);
            if (host.endsWith(suffix) || host === pattern.substring(2)) {
              isBlocked = true;
              blockReason = `Domain: ${rule.value}`;
              break;
            }
          } else if (host.includes(pattern)) {
            isBlocked = true;
            blockReason = `Domain: ${rule.value}`;
            break;
          }
        }
      }

      return {
        ...pkt,
        action: isBlocked ? 'DROP' : 'FORWARD',
        blockReason,
      };
    });
  }, []);

  // Load sample capture
  const loadSamplePcap = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/samples/test_dpi.pcap');
      if (!response.ok) {
        throw new Error('Could not load /samples/test_dpi.pcap');
      }
      const buffer = await response.arrayBuffer();
      const { globalHeader: gh, packets: rawPkts } = parsePcapArrayBuffer(buffer);
      setGlobalHeader(gh);
      const evaluated = applyRules(rawPkts, rules);
      setPackets(evaluated);
      if (evaluated.length > 0) {
        setSelectedPacket(evaluated[0]);
      }
      setFileName('test_dpi.pcap (Demo Capture)');
    } catch (e) {
      console.error('Failed to load sample capture:', e);
    } finally {
      setIsLoading(false);
    }
  }, [rules, applyRules]);

  // Initial load
  useEffect(() => {
    loadSamplePcap();
  }, []);

  // Update packet statuses when rules change
  useEffect(() => {
    setPackets(prev => {
      const updated = applyRules(prev, rules);
      if (selectedPacket) {
        const found = updated.find(p => p.id === selectedPacket.id);
        if (found) setSelectedPacket(found);
      }
      return updated;
    });
  }, [rules, applyRules]);

  // Handle user uploaded file
  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsLoading(true);
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const buffer = event.target.result;
        const { globalHeader: gh, packets: rawPkts } = parsePcapArrayBuffer(buffer);
        setGlobalHeader(gh);
        const evaluated = applyRules(rawPkts, rules);
        setPackets(evaluated);
        if (evaluated.length > 0) {
          setSelectedPacket(evaluated[0]);
        }
        setFileName(file.name);
      } catch (err) {
        alert('Failed to parse PCAP file: ' + err.message);
      } finally {
        setIsLoading(false);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleAddRule = (rule) => {
    // Avoid duplicate rules
    if (!rules.some(r => r.type === rule.type && r.value.toLowerCase() === rule.value.toLowerCase())) {
      setRules(prev => [...prev, rule]);
    }
  };

  const handleRemoveRule = (index) => {
    setRules(prev => prev.filter((_, i) => i !== index));
  };

  const handleClearRules = () => {
    setRules([]);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onLoadDemo={loadSamplePcap}
        onFileUpload={handleFileUpload}
        packetCount={packets.length}
        isLoading={isLoading}
        fileName={fileName}
      />

      <main style={{ flex: 1, maxWidth: '1600px', margin: '0 auto', width: '100%', padding: '20px 24px' }}>
        <StatsCards packets={packets} rules={rules} />

        {activeTab === 'dissector' && (
          <PacketViewer
            packets={packets}
            selectedPacket={selectedPacket}
            setSelectedPacket={setSelectedPacket}
          />
        )}

        {activeTab === 'analytics' && (
          <DpiAnalytics
            packets={packets}
            onAddRule={handleAddRule}
          />
        )}

        {activeTab === 'firewall' && (
          <FirewallRules
            rules={rules}
            onAddRule={handleAddRule}
            onRemoveRule={handleRemoveRule}
            onClearRules={handleClearRules}
            packets={packets}
            globalHeader={globalHeader}
          />
        )}

        {activeTab === 'threads' && (
          <ThreadArchitecture packets={packets} />
        )}

        {activeTab === 'resume' && (
          <ResumePortfolio />
        )}
      </main>

      <footer style={{
        borderTop: '1px solid var(--border-subtle)',
        padding: '16px 24px',
        textAlign: 'center',
        fontSize: '0.8rem',
        color: 'var(--text-dim)',
        background: 'rgba(7, 9, 14, 0.6)',
      }}>
        DPI Engine & Network Packet Analyzer • Built with Next.js & Pure Java/C++ Core • Deployable on Vercel
      </footer>
    </div>
  );
}
