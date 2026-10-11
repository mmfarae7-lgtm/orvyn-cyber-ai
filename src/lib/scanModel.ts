// Frontend mirror of the server scan model (supabase/functions/_shared/
// scan-core.ts). Keep in sync — the UI must describe exactly what the
// server does, never more. Labels and the 8-port-state model are the only
// things defined here; all verdicts come from the server.

export type PortState =
  | 'open'
  | 'closed'
  | 'filtered'
  | 'timeout'
  | 'unreachable'
  | 'error'
  | 'not_tested'
  | 'unknown';

export const PORT_STATES: PortState[] = [
  'open',
  'closed',
  'filtered',
  'timeout',
  'unreachable',
  'error',
  'not_tested',
  'unknown',
];

/** Short, honest description for each state (shown in the UI legend). */
export const PORT_STATE_LABEL: Record<PortState, string> = {
  open: 'Open',
  closed: 'Closed',
  filtered: 'Filtered',
  timeout: 'Timeout',
  unreachable: 'Unreachable',
  error: 'Error',
  not_tested: 'Not tested',
  unknown: 'Unknown',
};

export const PORT_STATE_CLASS: Record<PortState, string> = {
  open: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  closed: 'bg-white/[0.04] text-gray-500 border-white/[0.06]',
  filtered: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  timeout: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  unreachable: 'bg-red-500/10 text-red-400 border-red-500/20',
  error: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  not_tested: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  unknown: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
};

export type Profile = 'quick' | 'standard' | 'comprehensive' | 'custom';

export interface ProfileDef {
  id: Profile;
  name: string;
  tagline: string;
  description: string;
  /** Whether this profile may need an online agent for full coverage. */
  needsAgent: boolean;
  phases: string;
}

export const PROFILES: ProfileDef[] = [
  {
    id: 'quick',
    name: 'Quick',
    tagline: 'Common ports · core web checks',
    description:
      'Fast check of the 10 most common ports plus DNS, host, service, HTTP and security-header analysis. Best for a first look.',
    needsAgent: false,
    phases: 'DNS, host, port (common), service, HTTP, configuration',
  },
  {
    id: 'standard',
    name: 'Standard',
    tagline: 'Top ports · full web surface',
    description:
      'The Top ports set with every web-facing phase: DNS, host, port, service, HTTP, TLS, technology and configuration analysis.',
    needsAgent: false,
    phases: 'All core + web phases',
  },
  {
    id: 'comprehensive',
    name: 'Comprehensive',
    tagline: 'Full port sweep + vuln modules',
    description:
      'Requests all 65535 TCP ports and runs vulnerability modules when the selected tool supports them. The full sweep runs on an online Orvyn Agent (nmap); without one, coverage is reported as partial — never faked.',
    needsAgent: true,
    phases: 'Everything, including vulnerability assessment',
  },
  {
    id: 'custom',
    name: 'Custom',
    tagline: 'You choose phases and ports',
    description:
      'Pick exactly which phases run and the port expression to probe. The edge runtime probes up to its budget; larger scopes are reported as not tested unless an agent runs them.',
    needsAgent: false,
    phases: 'Your selection',
  },
];

/** Phase keys the user can toggle in a custom scan (mirrors server PHASES). */
export const CUSTOM_PHASES: Array<{ key: string; name: string }> = [
  { key: 'dns_analysis', name: 'DNS Analysis' },
  { key: 'host_discovery', name: 'Host Discovery' },
  { key: 'port_discovery', name: 'TCP Port Discovery' },
  { key: 'service_detection', name: 'Service Detection' },
  { key: 'http_analysis', name: 'HTTP/HTTPS Analysis' },
  { key: 'tls_analysis', name: 'TLS/SSL Analysis' },
  { key: 'technology_identification', name: 'Technology Identification' },
  { key: 'configuration_analysis', name: 'Header & Configuration Analysis' },
  { key: 'vulnerability_assessment', name: 'Vulnerability Assessment' },
];

export const EDGE_PORT_BUDGET = 1000;

export type PhaseStatus =
  | 'pending'
  | 'running'
  | 'complete'
  | 'partial'
  | 'unavailable'
  | 'skipped'
  | 'error';

export interface PhaseState {
  phase: number;
  key: string;
  name: string;
  status: PhaseStatus;
  summary?: string;
  detail?: Record<string, unknown>;
}

export interface CoverageArea {
  phase: number;
  key: string;
  name: string;
  status: 'complete' | 'partial' | 'unavailable' | 'skipped' | 'error';
  note?: string;
}

export interface Coverage {
  areas: CoverageArea[];
  percent: number;
  comprehensive: boolean;
  limitations: string[];
}

export interface PortEntry {
  port: number;
  protocol: 'tcp' | 'udp';
  state: PortState;
  service?: string;
  banner?: string;
  elapsed_ms?: number;
  raw_state?: string;
}

export interface PortCoverage {
  requested: { expr: string; count: number };
  tested: number;
  not_tested: { expr: string; count: number; reason: string } | null;
  counts: Record<PortState, number>;
  entries: PortEntry[];
  tool: string;
  delegated?: { tool: string; task_id: string; scope: string } | null;
}

export type ScanStatus =
  | 'pending'
  | 'running'
  | 'waiting_agent'
  | 'completed'
  | 'failed'
  | 'cancelled';

export const SCAN_STATUS_CLASS: Record<string, string> = {
  completed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  running: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  pending: 'bg-white/[0.04] text-gray-400 border-white/[0.06]',
  waiting_agent: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  failed: 'bg-red-500/10 text-red-400 border-red-500/20',
  cancelled: 'bg-white/[0.04] text-gray-500 border-white/[0.06]',
};

export const PHASE_STATUS_CLASS: Record<PhaseStatus, string> = {
  pending: 'bg-white/[0.04] text-gray-500 border-white/[0.06]',
  running: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  complete: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  partial: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  unavailable: 'bg-red-500/10 text-red-400 border-red-500/20',
  skipped: 'bg-white/[0.04] text-gray-500 border-white/[0.06]',
  error: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
};
