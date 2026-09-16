import {
  Radar,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Globe,
  Server,
  Lock,
  Network,
  Bug,
  KeyRound,
  FileSearch,
  Activity,
  Fingerprint,
  Zap,
  Eye,
  type LucideIcon,
} from 'lucide-react';

export type ToolDef = {
  id: string;
  name: string;
  category: string;
  description: string;
  icon: LucideIcon;
  color: string;
  available: boolean;
  capabilities: string[];
};

export const TOOLS: ToolDef[] = [
  {
    id: 'nmap',
    name: 'Nmap',
    category: 'Network Discovery',
    description: 'Discovers devices, open ports, and running services on a target',
    icon: Radar,
    color: '#3b82f6',
    available: true,
    capabilities: ['Port scanning', 'Service detection', 'OS fingerprinting', 'Host discovery'],
  },
  {
    id: 'masscan',
    name: 'Masscan',
    category: 'Network Discovery',
    description: 'Ultra-fast port scanner for large-scale network discovery',
    icon: Zap,
    color: '#f59e0b',
    available: true,
    capabilities: ['Fast port scanning', 'Large-scale scanning', 'Rate control'],
  },
  {
    id: 'nuclei',
    name: 'Nuclei',
    category: 'Vulnerability Scanning',
    description: 'Template-based vulnerability scanner for known CVEs and misconfigurations',
    icon: ShieldAlert,
    color: '#ef4444',
    available: true,
    capabilities: ['CVE detection', 'Misconfiguration checks', 'Template-based scanning', 'Exposure detection'],
  },
  {
    id: 'zap',
    name: 'OWASP ZAP',
    category: 'Web App Security',
    description: 'Comprehensive web application security scanner',
    icon: ShieldX,
    color: '#8b5cf6',
    available: true,
    capabilities: ['Active scanning', 'Passive scanning', 'Spider', 'Fuzzer', 'AJAX spider'],
  },
  {
    id: 'nikto',
    name: 'Nikto',
    category: 'Web Server Audit',
    description: 'Web server scanner for dangerous files and outdated software',
    icon: Server,
    color: '#10b981',
    available: true,
    capabilities: ['Server misconfiguration', 'Outdated software detection', 'Dangerous file detection'],
  },
  {
    id: 'whatweb',
    name: 'WhatWeb',
    category: 'Reconnaissance',
    description: 'Identifies technologies, frameworks, and components of a website',
    icon: Globe,
    color: '#06b6d4',
    available: true,
    capabilities: ['Technology fingerprinting', 'CMS detection', 'Framework identification'],
  },
  {
    id: 'httpx',
    name: 'httpx',
    category: 'Reconnaissance',
    description: 'Fast HTTP probe to discover live web services and verify responses',
    icon: Activity,
    color: '#0ea5e9',
    available: true,
    capabilities: ['HTTP probing', 'Status code detection', 'Title extraction', 'Tech detection'],
  },
  {
    id: 'dns',
    name: 'DNS Tools',
    category: 'Reconnaissance',
    description: 'DNS enumeration and record lookup (dig, nslookup)',
    icon: Network,
    color: '#6366f1',
    available: true,
    capabilities: ['DNS record lookup', 'Zone transfer attempts', 'Subdomain enumeration'],
  },
  {
    id: 'sslyze',
    name: 'SSLyze',
    category: 'TLS/SSL Analysis',
    description: 'Analyzes TLS/SSL configuration and identifies weak ciphers',
    icon: Lock,
    color: '#14b8a6',
    available: true,
    capabilities: ['TLS version analysis', 'Cipher suite audit', 'Certificate validation', 'Heartbleed check'],
  },
  {
    id: 'openvas',
    name: 'OpenVAS',
    category: 'Vulnerability Scanning',
    description: 'Full-range network vulnerability scanner',
    icon: Shield,
    color: '#dc2626',
    available: false,
    capabilities: ['Network vulnerability scanning', 'CVE scanning', 'Compliance checks'],
  },
  {
    id: 'wireshark',
    name: 'Wireshark',
    category: 'Network Analysis',
    description: 'Network protocol analyzer for deep packet inspection',
    icon: Eye,
    color: '#7c3aed',
    available: false,
    capabilities: ['Packet capture', 'Protocol analysis', 'Traffic inspection'],
  },
  {
    id: 'trivy',
    name: 'Trivy',
    category: 'Container Security',
    description: 'Scans Docker images, dependencies, and filesystems for vulnerabilities',
    icon: Bug,
    color: '#f97316',
    available: true,
    capabilities: ['Container image scanning', 'Dependency scanning', 'IaC scanning', 'Secret detection'],
  },
  {
    id: 'semgrep',
    name: 'Semgrep',
    category: 'Code Analysis',
    description: 'Static code analysis for security vulnerabilities and code quality',
    icon: FileSearch,
    color: '#ec4899',
    available: true,
    capabilities: ['SAST', 'Code pattern matching', 'Custom rules', 'Language-agnostic'],
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    category: 'Secret Detection',
    description: 'Detects API keys, passwords, and secrets in source code',
    icon: KeyRound,
    color: '#f43f5e',
    available: true,
    capabilities: ['Secret scanning', 'API key detection', 'Credential exposure', 'Git history scanning'],
  },
  {
    id: 'lynis',
    name: 'Lynis',
    category: 'System Audit',
    description: 'Security auditing for Linux systems and compliance',
    icon: ShieldCheck,
    color: '#22c55e',
    available: false,
    capabilities: ['System hardening', 'Compliance auditing', 'Configuration checks'],
  },
  {
    id: 'yara',
    name: 'YARA',
    category: 'Threat Detection',
    description: 'Pattern matching for malware and suspicious file indicators',
    icon: Fingerprint,
    color: '#a855f7',
    available: true,
    capabilities: ['Malware detection', 'Pattern matching', 'Indicator scanning', 'File path to scan'],
  },
];

export function getToolById(id: string): ToolDef | undefined {
  return TOOLS.find((t) => t.id === id);
}

export function getAvailableTools(): ToolDef[] {
  return TOOLS.filter((t) => t.available);
}

export function getUnavailableTools(): ToolDef[] {
  return TOOLS.filter((t) => !t.available);
}

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', dot: 'bg-red-500' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30', dot: 'bg-orange-500' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-500' },
  low: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30', dot: 'bg-blue-500' },
  info: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30', dot: 'bg-gray-500' },
};
