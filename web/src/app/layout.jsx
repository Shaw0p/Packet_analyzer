import './globals.css';

export const metadata = {
  title: 'DPI Engine & Network Packet Analyzer | Deep Packet Inspection',
  description: 'High-performance Deep Packet Inspection (DPI) & Packet Analyzer with multi-threading, TLS SNI extraction, and firewall rule engine.',
  keywords: ['DPI', 'Deep Packet Inspection', 'Wireshark', 'PCAP', 'Network Analyzer', 'TLS SNI', 'Java', 'Next.js'],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2300f2fe' stroke-width='2'><polygon points='12 2 2 7 12 12 22 7 12 2'/><polyline points='2 17 12 22 22 17'/><polyline points='2 12 12 17 22 12'/></svg>" />
      </head>
      <body>{children}</body>
    </html>
  );
}
