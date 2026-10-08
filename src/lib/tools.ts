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

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

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
    description: 'Real TCP connect scan of common ports with live banner and service detection',
    icon: Radar,
    color: '#3b82f6',
    available: true,
    capabilities: ['TCP connect() scan', 'Banner grabbing', 'Service detection', 'Open/closed/filtered states'],
  },
  {
    id: 'masscan',
    name: 'Masscan',
    category: 'Network Discovery',
    description: 'Fast parallel TCP connect scan across the top ports',
    icon: Zap,
    color: '#f59e0b',
    available: true,
    capabilities: ['Fast connect scanning', 'Parallel probes', 'Per-port timing'],
  },
  {
    id: 'nuclei',
    name: 'Nuclei',
    category: 'Vulnerability Scanning',
    description: 'Live template checks: security headers, exposed files, admin panels',
    icon: ShieldAlert,
    color: '#ef4444',
    available: true,
    capabilities: ['Header misconfiguration checks', '.git/.env exposure detection', 'Directory listing detection', 'Soft-404 aware'],
  },
  {
    id: 'zap',
    name: 'OWASP ZAP',
    category: 'Web App Security',
    description: 'Passive analysis of the live HTTP response: cookies, headers, mixed content',
    icon: ShieldX,
    color: '#8b5cf6',
    available: true,
    capabilities: ['Passive header analysis', 'Cookie flag audit', 'Mixed content detection', 'CSRF heuristics'],
  },
  {
    id: 'nikto',
    name: 'Nikto',
    category: 'Web Server Audit',
    description: 'Web server scan for dangerous files (content-validated) and outdated software',
    icon: Server,
    color: '#10b981',
    available: true,
    capabilities: ['Dangerous file detection', 'Content-validated evidence', 'Server version audit'],
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
    description: 'Live HTTP probes with real status codes, titles, and latency',
    icon: Activity,
    color: '#0ea5e9',
    available: true,
    capabilities: ['HTTP probing', 'Status code detection', 'Title extraction', 'Latency measurement'],
  },
  {
    id: 'dns',
    name: 'DNS Tools',
    category: 'Reconnaissance',
    description: 'DNS enumeration over DNS-over-HTTPS with SPF/DMARC/CAA analysis',
    icon: Network,
    color: '#6366f1',
    available: true,
    capabilities: ['A/AAAA/MX/NS/TXT/SOA/CAA lookup', 'SPF + DMARC analysis', 'CAA + DNSSEC check'],
  },
  {
    id: 'sslyze',
    name: 'SSLyze',
    category: 'TLS/SSL Analysis',
    description: 'TLS handshake test, HSTS policy, and Certificate Transparency lookup',
    icon: Lock,
    color: '#14b8a6',
    available: true,
    capabilities: ['TLS handshake test', 'HSTS analysis', 'Certificate validation (crt.sh)', 'HTTP→HTTPS redirect check'],
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
    description: 'Scans assets served by the target for outdated, vulnerable library versions',
    icon: Bug,
    color: '#f97316',
    available: true,
    capabilities: ['Dependency version detection', 'Vulnerable JS library check', 'Script asset analysis', 'Container scans via agent'],
  },
  {
    id: 'semgrep',
    name: 'Semgrep',
    category: 'Code Analysis',
    description: 'Analyzes JavaScript served by the target for insecure patterns (eval, innerHTML)',
    icon: FileSearch,
    color: '#ec4899',
    available: true,
    capabilities: ['Inline script analysis', 'eval/innerHTML detection', 'Pattern matching', 'Repo SAST via agent'],
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    category: 'Secret Detection',
    description: 'Scans served code for leaked secrets, API keys, and privileged JWTs',
    icon: KeyRound,
    color: '#f43f5e',
    available: true,
    capabilities: ['Secret pattern detection', 'JWT role check (service_role)', 'Hardcoded credential detection', 'Git history via agent'],
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
    description: 'Pattern-matches served content for suspicious indicators; file scanning via agent',
    icon: Fingerprint,
    color: '#a855f7',
    available: true,
    capabilities: ['Indicator pattern matching', 'Suspicious API detection', 'Encoded payload detection', 'File scanning via agent'],
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
