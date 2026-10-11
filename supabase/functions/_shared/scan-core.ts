// Shared scan model for orion-scan (orchestrator) and orion-agent (result
// merge). Kept in _shared/ so both Deno functions bundle the same types.

// ---------------------------------------------------------------------------
// Port states — never conflate timeout with closed (see audit §12).
// ---------------------------------------------------------------------------
export type PortState =
  | 'open'
  | 'closed'
  | 'filtered' // nmap-style: something dropped the probe (firewall)
  | 'timeout' // our connect attempt timed out (not evidence of closed)
  | 'unreachable'
  | 'error' // runtime error (permissions, resolver, …)
  | 'not_tested' // out of requested scope for this run
  | 'unknown'; // evidence insufficient to classify

export interface PortEntry {
  port: number;
  protocol: 'tcp' | 'udp';
  state: PortState;
  service?: string;
  banner?: string;
  elapsed_ms?: number;
  /** raw tool state when it did not map 1:1 (evidence, not a verdict) */
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

export const EMPTY_PORT_COUNTS: Record<PortState, number> = {
  open: 0,
  closed: 0,
  filtered: 0,
  timeout: 0,
  unreachable: 0,
  error: 0,
  not_tested: 0,
  unknown: 0,
};

/** Map a raw tool state string into our 8-state model. Never invent "closed". */
export function mapPortState(raw: string): PortState {
  const s = raw.trim().toLowerCase();
  if (s === 'open') return 'open';
  if (s === 'closed' || s === 'reset' || s === 'refused') return 'closed';
  if (s === 'filtered' || s === 'drop' || s === 'dropped') return 'filtered';
  if (s === 'timeout' || s === 'timed out') return 'timeout';
  if (s === 'unreachable' || s === 'no-route') return 'unreachable';
  if (s === 'unchecked' || s === 'error') return 'error';
  if (s === 'not_tested' || s === 'not tested') return 'not_tested';
  return 'unknown';
}

/** Parse nmap/masscan-style lines: "22/tcp open ssh". */
export function parsePortToolOutput(raw: string): PortEntry[] {
  const entries: PortEntry[] = [];
  const re = /(\d+)\/(tcp|udp)\s+([a-z|]+)(?:\s+(\S+))?/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const rawState = m[3] ?? '';
    entries.push({
      port: parseInt(m[1], 10),
      protocol: (m[2].toLowerCase() === 'udp' ? 'udp' : 'tcp') as 'tcp' | 'udp',
      state: mapPortState(rawState),
      service: m[4] && m[4] !== '=' ? m[4] : undefined,
      raw_state: rawState !== mapPortState(rawState) ? rawState : undefined,
    });
  }
  return entries;
}

export function countStates(entries: PortEntry[]): Record<PortState, number> {
  const counts = { ...EMPTY_PORT_COUNTS };
  for (const e of entries) counts[e.state] += 1;
  return counts;
}

/**
 * Expand "1-1000,22,80,443" into sorted unique ports.
 * Returns null when the expression is malformed.
 */
export function parsePortExpression(expr: string): number[] | null {
  const out = new Set<number>();
  const parts = expr.split(',').map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return null;
  for (const part of parts) {
    if (/^\d+$/.test(part)) {
      const n = parseInt(part, 10);
      if (n < 1 || n > 65535) return null;
      out.add(n);
      continue;
    }
    const range = part.match(/^(\d+)\s*-\s*(\d+)$/);
    if (range) {
      const a = parseInt(range[1], 10);
      const b = parseInt(range[2], 10);
      if (a < 1 || b > 65535 || a > b) return null;
      if (b - a > 65534) return null;
      for (let i = a; i <= b; i++) out.add(i);
      continue;
    }
    return null;
  }
  return [...out].sort((x, y) => x - y);
}

// ---------------------------------------------------------------------------
// Scan profiles & phases
// ---------------------------------------------------------------------------
export type Profile = 'quick' | 'standard' | 'comprehensive' | 'custom';

export interface PhaseDef {
  phase: number;
  key: string;
  name: string;
}

export const PHASES: PhaseDef[] = [
  { phase: 1, key: 'target_validation', name: 'Target Validation' },
  { phase: 2, key: 'dns_analysis', name: 'DNS Analysis' },
  { phase: 3, key: 'host_discovery', name: 'Host Discovery' },
  { phase: 4, key: 'port_discovery', name: 'TCP Port Discovery' },
  { phase: 5, key: 'service_detection', name: 'Service Detection' },
  { phase: 6, key: 'http_analysis', name: 'HTTP/HTTPS Analysis' },
  { phase: 7, key: 'tls_analysis', name: 'TLS/SSL Analysis' },
  { phase: 8, key: 'technology_identification', name: 'Technology Identification' },
  { phase: 9, key: 'configuration_analysis', name: 'Security Header & Configuration Analysis' },
  { phase: 10, key: 'vulnerability_assessment', name: 'Vulnerability Assessment' },
  { phase: 11, key: 'evidence_collection', name: 'Evidence Collection' },
  { phase: 12, key: 'correlation', name: 'Correlation' },
  { phase: 13, key: 'risk_classification', name: 'Risk Classification' },
  { phase: 14, key: 'remediation', name: 'Remediation Generation' },
  { phase: 15, key: 'report', name: 'Final Report' },
];

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

/** Coverage entry for one capability area (§19 of the master prompt). */
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

const STATUS_WEIGHT: Record<CoverageArea['status'], number> = {
  complete: 1,
  partial: 0.5,
  unavailable: 0,
  skipped: 0,
  error: 0,
};

/**
 * Compute overall coverage. `comprehensive` is only true when nothing was
 * skipped, unavailable, partial or errored — the platform must never claim a
 * comprehensive assessment when capabilities were missing.
 */
export function computeCoverage(areas: CoverageArea[]): Coverage {
  if (areas.length === 0) {
    return { areas, percent: 0, comprehensive: false, limitations: ['No checks executed'] };
  }
  const total = areas.reduce((sum, a) => sum + STATUS_WEIGHT[a.status], 0);
  const percent = Math.round((total / areas.length) * 100);
  const limitations = areas
    .filter((a) => a.status !== 'complete')
    .map((a) => {
      const suffix = a.note ? `: ${a.note}` : '';
      return `${a.name} — ${a.status}${suffix}`;
    });
  const comprehensive = limitations.length === 0;
  return { areas, percent, comprehensive, limitations };
}

// ---------------------------------------------------------------------------
// Findings (evidence-first, §17–18)
// ---------------------------------------------------------------------------
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'confirmed' | 'high' | 'medium' | 'low' | 'unspecified';

export interface Finding {
  title: string;
  severity: Severity;
  description: string;
  evidence: string;
  remediation: string;
  cve?: string;
  port?: number;
  service?: string;
  /** who/what observed this — required, never fabricated */
  detection_method?: string;
  tool?: string;
  tool_version?: string;
  confidence?: Confidence;
  protocol?: string;
  refs?: string[];
}

/** Stamp required evidence fields onto a finding produced by an engine check. */
export function stampFinding(f: Finding, tool = 'orion-engine'): Finding {
  return {
    detection_method: 'engine_check',
    tool,
    confidence: f.confidence ?? 'high',
    ...f,
  };
}

export function truncate(text: string, max = 40000): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + `\n… [truncated, ${text.length - max} chars omitted]`;
}

// ---------------------------------------------------------------------------
// Profiles → port scope
// ---------------------------------------------------------------------------
export const QUICK_PORTS = [80, 443, 22, 53, 3306, 8080, 21, 25, 110, 143];

export interface PortScope {
  /** expression that was requested (may be "1-65535") */
  requestedExpr: string;
  requestedCount: number;
  /** ports the edge engine will actually probe this invocation */
  testExpr: string;
  testPorts: number[];
  reason: string;
  /** true when a full-range scan was handed to an agent */
  delegated: boolean;
}

export const EDGE_PORT_BUDGET = 1000;

export function resolvePortScope(
  profile: Profile,
  topPorts: number[],
  options: Record<string, string>,
): PortScope {
  const customExpr = (options.ports ?? '').trim();

  if (profile === 'custom' && customExpr) {
    const parsed = parsePortExpression(customExpr);
    if (parsed) {
      const test = parsed.slice(0, EDGE_PORT_BUDGET);
      return {
        requestedExpr: customExpr,
        requestedCount: parsed.length,
        testExpr: test.join(','),
        testPorts: test,
        reason:
          parsed.length > test.length
            ? `Edge runtime budget: first ${test.length} of ${parsed.length} requested ports probed here; the rest are reported as not_tested (run the agent for full ranges).`
            : 'Custom port scope as requested.',
        delegated: false,
      };
    }
  }

  if (profile === 'comprehensive') {
    return {
      requestedExpr: '1-65535',
      requestedCount: 65535,
      testExpr: topPorts.join(','),
      testPorts: topPorts,
      reason:
        'Comprehensive profile requested all 65535 TCP ports. This edge runtime probes the common set; ' +
        'the full sweep runs on an Orvyn Agent with nmap when one is online.',
      delegated: true,
    };
  }

  if (profile === 'quick') {
    return {
      requestedExpr: QUICK_PORTS.join(','),
      requestedCount: QUICK_PORTS.length,
      testExpr: QUICK_PORTS.join(','),
      testPorts: QUICK_PORTS,
      reason: 'Quick profile: common ports only.',
      delegated: false,
    };
  }

  // standard
  return {
    requestedExpr: topPorts.join(','),
    requestedCount: topPorts.length,
    testExpr: topPorts.join(','),
    testPorts: topPorts,
    reason: 'Standard profile: common/top ports.',
    delegated: false,
  };
}

// ---------------------------------------------------------------------------
// Audit log helper (never logs secrets)
// ---------------------------------------------------------------------------
export interface Auditable {
  from(arg0: string): unknown;
}

export async function audit(
  // deno-lint-ignore no-explicit-any
  supabase: any,
  userId: string,
  action: string,
  detail: Record<string, unknown>,
): Promise<void> {
  try {
    await supabase.from('audit_log').insert({ user_id: userId, action, detail });
  } catch {
    // audit must never break the scan itself
  }
}
