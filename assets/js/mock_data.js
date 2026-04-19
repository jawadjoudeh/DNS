const mockDNSLogs = [
  { id: 1, timestamp: "2023-11-20 10:15:22", source_ip: "192.168.1.45", domain: "google.com", verdict: "Benign", attack_type: "-", action: "Allowed", confidence: 99 },
  { id: 2, timestamp: "2023-11-20 10:15:25", source_ip: "192.168.1.102", domain: "secure-login-update.info", verdict: "Malicious", attack_type: "Phishing", action: "Blocked", confidence: 95 },
  { id: 3, timestamp: "2023-11-20 10:16:01", source_ip: "192.168.1.12", domain: "api.github.com", verdict: "Benign", attack_type: "-", action: "Allowed", confidence: 98 },
  { id: 4, timestamp: "2023-11-20 10:17:33", source_ip: "192.168.1.50", domain: "x1.xyz-dns-tunnel.com", verdict: "Malicious", attack_type: "DNS Tunneling", action: "Blocked", confidence: 92 },
  { id: 5, timestamp: "2023-11-20 10:18:10", source_ip: "192.168.1.50", domain: "x2.xyz-dns-tunnel.com", verdict: "Malicious", attack_type: "DNS Tunneling", action: "Blocked", confidence: 93 },
  { id: 6, timestamp: "2023-11-20 10:20:05", source_ip: "192.168.1.105", domain: "unknown-analytics.io", verdict: "Suspicious", attack_type: "DGA", action: "Allowed", confidence: 65 },
  { id: 7, timestamp: "2023-11-20 10:22:45", source_ip: "192.168.1.45", domain: "cloudflare.com", verdict: "Benign", attack_type: "-", action: "Allowed", confidence: 99 },
  { id: 8, timestamp: "2023-11-20 10:25:12", source_ip: "192.168.1.110", domain: "malware-download-site.net", verdict: "Malicious", attack_type: "Malware", action: "Blocked", confidence: 97 },
  { id: 9, timestamp: "2023-11-20 10:26:00", source_ip: "192.168.1.12", domain: "stackoverflow.com", verdict: "Benign", attack_type: "-", action: "Allowed", confidence: 99 },
  { id: 10, timestamp: "2023-11-20 10:30:15", source_ip: "192.168.1.201", domain: "1a2b3c4d5e.com", verdict: "Suspicious", attack_type: "DGA", action: "Blocked", confidence: 82 }
];

const mockStats = {
  totalQueries: 14520,
  safeQueries: 13950,
  blockedThreats: 425,
  tunnelingAttempts: 145
};

const topMaliciousDomains = [
  { domain: "xyz-dns-tunnel.com", hits: 145 },
  { domain: "secure-login-update.info", hits: 82 },
  { domain: "malware-download-site.net", hits: 45 },
  { domain: "1a2b3c4d5e.com", hits: 38 },
  { domain: "crypto-miner.cn", hits: 29 }
];
