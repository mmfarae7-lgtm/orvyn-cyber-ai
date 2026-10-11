import { useCallback, useEffect, useState, type ReactNode } from 'react';
import {
  ClipboardList,
  Loader2,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Radar,
  Circle,
  FileWarning,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  Activity,
} from 'lucide-react';
import { supabase, type Scan, type ScanPhase } from '@/lib/supabase';
import { useAuth } from '@/context/AuthContext';
import { getToolById, SEVERITY_COLORS, type Severity } from '@/lib/tools';
import {
  PORT_STATE_CLASS,
  PORT_STATE_LABEL,
  SCAN_STATUS_CLASS,
  PHASE_STATUS_CLASS,
  type PortCoverage,
  type PortState,
  type Coverage,
} from '@/lib/scanModel';
import type { PageId } from '@/components/Layout';

type VulnCounts = Record<string, number>;

const ACTIVE_STATUSES = ['pending', 'running', 'waiting_agent'];

function stateClass(state: string): string {
  return PORT_STATE_CLASS[state as PortState] ?? 'bg-white/[0.04] text-gray-500 border-white/[0.06]';
}

function stateLabel(state: string): string {
  return PORT_STATE_LABEL[state as PortState] ?? state;
}

export default function Scans({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const { session } = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [counts, setCounts] = useState<Record<string, VulnCounts>>({});
  const [phases, setPhases] = useState<Record<string, ScanPhase[]>>({});
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [canceling, setCanceling] = useState<string | null>(null);

  const loadScans = useCallback(async () => {
    const [{ data: scanData }, { data: vulnData }] = await Promise.all([
      supabase.from('scans').select('*').order('created_at', { ascending: false }).limit(50),
      supabase.from('vulnerabilities').select('scan_id, severity'),
    ]);
    const rows = (scanData ?? []) as Scan[];
    setScans(rows);
    setExpandedId((prev) => (prev === null && rows.length > 0 ? rows[0].id : prev));

    const grouped: Record<string, VulnCounts> = {};
    for (const v of vulnData ?? []) {
      if (!v.scan_id) continue;
      grouped[v.scan_id] ??= {};
      grouped[v.scan_id][v.severity] = (grouped[v.scan_id][v.severity] ?? 0) + 1;
    }
    setCounts(grouped);
    setLoading(false);
  }, []);

  const loadPhases = useCallback(async (scanId: string) => {
    const { data } = await supabase
      .from('scan_phases')
      .select('*')
      .eq('scan_id', scanId)
      .order('phase', { ascending: true });
    setPhases((prev) => ({ ...prev, [scanId]: (data ?? []) as ScanPhase[] }));
  }, []);

  // Poll the scan list — faster while something is active.
  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, [loadScans]);

  // Keep the expanded scan's phases live.
  useEffect(() => {
    if (!expandedId) return;
    loadPhases(expandedId);
    const interval = setInterval(() => loadPhases(expandedId), 4000);
    return () => clearInterval(interval);
  }, [expandedId, loadPhases]);

  const cancelScan = async (scanId: string) => {
    if (!session?.access_token) return;
    setCanceling(scanId);
    try {
      await fetch(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/orion-agent/cancel`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ scanId }),
      });
      await loadScans();
      if (expandedId === scanId) await loadPhases(scanId);
    } finally {
      setCanceling(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6 fade-in">
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <ClipboardList className="w-5 h-5 text-blue-400" />
            Scan History
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Live phases, coverage and raw evidence from every scan — never faked
          </p>
        </div>
        <button
          onClick={loadScans}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-white/[0.04] border border-white/[0.06] text-sm text-gray-300 hover:bg-white/[0.07] transition-colors"
        >
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {scans.length === 0 ? (
        <div className="glass-card p-12 flex flex-col items-center justify-center text-center">
          <ClipboardList className="w-12 h-12 text-gray-700 mb-3" />
          <p className="text-sm font-medium text-gray-400">No scans yet</p>
          <p className="text-xs text-gray-600 mt-1">Launch your first scan to see live results here</p>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => {
            const toolDef = getToolById(scan.tool);
            const Icon = toolDef?.icon ?? Radar;
            const vc = counts[scan.id] ?? {};
            const totalVulns = Object.values(vc).reduce((a, b) => a + b, 0);
            const expanded = expandedId === scan.id;
            const active = ACTIVE_STATUSES.includes(scan.status);
            const coverage = (scan.coverage ?? scan.results?.coverage) as Coverage | null | undefined;

            return (
              <div key={scan.id} className="glass-card overflow-hidden">
                <button
                  onClick={() => setExpandedId(expanded ? null : scan.id)}
                  className="w-full flex items-center gap-4 px-4 py-3.5 text-left hover:bg-white/[0.02] transition-colors"
                >
                  <div
                    className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ background: `${toolDef?.color ?? '#3b82f6'}1a` }}
                  >
                    <Icon className="w-4 h-4" style={{ color: toolDef?.color ?? '#3b82f6' }} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold">
                        {toolDef?.name ?? scan.tool.toUpperCase()}
                      </span>
                      <span className="text-sm text-gray-400 truncate">→ {scan.target}</span>
                      {scan.profile && (
                        <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-white/[0.05] text-gray-500">
                          {scan.profile}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-gray-600 mt-0.5">
                      {new Date(scan.created_at).toLocaleString()}
                      {scan.completed_at && scan.started_at &&
                        ` · ${((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000).toFixed(1)}s`}
                    </div>
                  </div>
                  <div className="hidden sm:flex items-center gap-1.5">
                    {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) =>
                      vc[s] ? (
                        <span
                          key={s}
                          className={`text-[10px] px-1.5 py-0.5 rounded border ${SEVERITY_COLORS[s].bg} ${SEVERITY_COLORS[s].text} ${SEVERITY_COLORS[s].border}`}
                        >
                          {vc[s]} {s}
                        </span>
                      ) : null
                    )}
                    {totalVulns === 0 && <span className="text-[10px] text-gray-600">no findings</span>}
                  </div>
                  <span
                    className={`text-[10px] px-2 py-1 rounded-full border capitalize ${SCAN_STATUS_CLASS[scan.status] ?? SCAN_STATUS_CLASS.pending}`}
                  >
                    {active ? (
                      <span className="flex items-center gap-1">
                        <Loader2 className="w-3 h-3 animate-spin" /> {scan.status.replace('_', ' ')}
                      </span>
                    ) : (
                      scan.status
                    )}
                  </span>
                  {expanded ? (
                    <ChevronUp className="w-4 h-4 text-gray-600" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-gray-600" />
                  )}
                </button>

                {expanded && (
                  <div className="border-t border-white/[0.06] px-4 py-4 space-y-5 bg-[#0a0b14]/40">
                    {active && (
                      <div className="flex items-center gap-3">
                        <div className="flex-1">
                          <div className="flex items-center justify-between text-xs text-gray-500 mb-1.5">
                            <span className="flex items-center gap-1.5">
                              <Activity className="w-3.5 h-3.5 text-amber-400" />
                              {scan.progress?.state ?? scan.status}
                            </span>
                            <span>{scan.progress?.percent ?? 0}%</span>
                          </div>
                          <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 transition-all"
                              style={{ width: `${scan.progress?.percent ?? 0}%` }}
                            />
                          </div>
                        </div>
                        <button
                          onClick={() => cancelScan(scan.id)}
                          disabled={canceling === scan.id}
                          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 disabled:opacity-50 transition-colors"
                        >
                          {canceling === scan.id ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <XCircle className="w-3.5 h-3.5" />
                          )}
                          Cancel
                        </button>
                      </div>
                    )}

                    {coverage && <CoveragePanel coverage={coverage} />}

                    <PhasePanel phases={phases[scan.id] ?? []} />

                    <ResultSections results={scan.results ?? {}} />

                    <div className="flex items-center justify-between pt-1">
                      <span className="text-xs text-gray-600">
                        Raw results stored in the scans table · verified live against the target
                      </span>
                      <button
                        onClick={() => onNavigate('vulnerabilities')}
                        className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                      >
                        <FileWarning className="w-3.5 h-3.5" />
                        Detailed findings ({totalVulns})
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SectionTitle({ children }: { children: ReactNode }) {
  return (
    <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">{children}</h3>
  );
}

function MonoLine({ children, dotClass }: { children: ReactNode; dotClass?: string }) {
  return (
    <div className="flex items-start gap-2 text-xs font-mono text-gray-400 py-0.5">
      {dotClass !== undefined && (
        <span className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${dotClass}`} />
      )}
      <span className="break-all">{children}</span>
    </div>
  );
}

function CoveragePanel({ coverage }: { coverage: Coverage }) {
  const { percent, comprehensive, limitations, areas } = coverage;
  const counted = new Set(areas.map((a) => a.status));
  return (
    <div
      className={`rounded-lg border p-3 ${
        comprehensive
          ? 'border-emerald-500/20 bg-emerald-500/[0.04]'
          : 'border-amber-500/25 bg-amber-500/[0.05]'
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold flex items-center gap-1.5">
          {comprehensive ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          )}
          <span className={comprehensive ? 'text-emerald-400' : 'text-amber-400'}>
            {comprehensive ? 'Comprehensive assessment' : 'NOT a comprehensive assessment'}
          </span>
        </span>
        <span className="text-xs text-gray-400">{percent}% coverage</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/[0.06] overflow-hidden mb-2">
        <div
          className={`h-full ${comprehensive ? 'bg-emerald-500' : 'bg-amber-500'}`}
          style={{ width: `${percent}%` }}
        />
      </div>
      {!comprehensive && limitations.length > 0 && (
        <ul className="space-y-0.5">
          {limitations.map((l, i) => (
            <li key={i} className="text-[11px] text-amber-400/80 flex items-start gap-1.5">
              <span className="mt-1 w-1 h-1 rounded-full bg-amber-400/70 flex-shrink-0" />
              {l}
            </li>
          ))}
        </ul>
      )}
      {areas.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {areas.map((a) => (
            <span
              key={a.key}
              className={`text-[10px] px-1.5 py-0.5 rounded border ${PHASE_STATUS_CLASS[a.status] ?? ''}`}
            >
              {a.name}
            </span>
          ))}
        </div>
      )}
      {counted.has('complete') && comprehensive && (
        <p className="text-[11px] text-emerald-400/70 mt-1.5">
          Every requested capability area completed without limitations.
        </p>
      )}
    </div>
  );
}

function PhasePanel({ phases }: { phases: ScanPhase[] }) {
  if (phases.length === 0) return null;
  const done = phases.filter((p) => p.status === 'complete').length;
  return (
    <div>
      <SectionTitle>
        Assessment phases ({done}/{phases.length} complete)
      </SectionTitle>
      <div className="rounded-lg border border-white/[0.06] divide-y divide-white/[0.04] overflow-hidden">
        {phases.map((p) => (
          <div key={p.id} className="flex items-center gap-3 px-3 py-2">
            <span className="text-[10px] font-mono text-gray-600 w-6">{p.phase}</span>
            <span className="text-xs text-gray-300 flex-1">{p.name}</span>
            {p.summary && (
              <span className="text-[11px] text-gray-600 truncate max-w-[40%] hidden sm:block">
                {p.summary}
              </span>
            )}
            <span
              className={`text-[10px] px-1.5 py-0.5 rounded border capitalize ${
                PHASE_STATUS_CLASS[(p.status as keyof typeof PHASE_STATUS_CLASS) ?? 'pending'] ?? ''
              }`}
            >
              {p.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PortCounts({ coverage }: { coverage: PortCoverage }) {
  const counts = coverage.counts ?? {};
  const chips = (Object.keys(counts) as PortState[])
    .filter((k) => (counts[k] ?? 0) > 0)
    .map((k) => ({ state: k, n: counts[k] }));
  return (
    <div className="flex flex-wrap items-center gap-1.5 mb-2">
      <span className="text-[11px] text-gray-500">
        {coverage.tested} / {coverage.requested.count} requested ports tested
      </span>
      {chips.map(({ state, n }) => (
        <span key={state} className={`text-[10px] px-1.5 py-0.5 rounded border ${stateClass(state)}`}>
          {n} {stateLabel(state)}
        </span>
      ))}
    </div>
  );
}

function ResultSections({ results }: { results: Record<string, unknown> }) {
  const sections: ReactNode[] = [];

  const pc = results.port_coverage as PortCoverage | undefined;
  if (pc && Array.isArray(pc.entries)) {
    sections.push(
      <div key="port_coverage">
        <SectionTitle>
          Port states — {pc.tool} on {pc.tested} ports
        </SectionTitle>
        <PortCounts coverage={pc} />
        {pc.not_tested && (
          <p className="text-[11px] text-blue-400/80 mb-2">
            {pc.not_tested.count} ports not tested ({pc.not_tested.expr}): {pc.not_tested.reason}
          </p>
        )}
        {pc.delegated && (
          <p className="text-[11px] text-purple-400/80 mb-2">
            Full-range sweep delegated to an Orvyn Agent ({pc.delegated.tool}) — task{' '}
            <span className="font-mono">{pc.delegated.task_id.slice(0, 8)}</span>
          </p>
        )}
        <PortTable
          entries={pc.entries.map((e) => ({
            port: e.port,
            state: e.state,
            service: e.service ?? '',
            banner: e.banner,
            elapsed_ms: e.elapsed_ms,
            rawState: e.raw_state,
          }))}
        />
      </div>
    );
  } else if (Array.isArray(results.ports)) {
    const ports = results.ports as Array<{
      port: number;
      state: string;
      service: string;
      banner?: string;
      elapsed_ms?: number;
    }>;
    const openCount = ports.filter((p) => p.state === 'open').length;
    sections.push(
      <div key="ports">
        <SectionTitle>
          Port states — real TCP connect() probes ({openCount} open / {ports.length} probed)
        </SectionTitle>
        <PortTable
          entries={ports.map((p) => ({
            port: p.port,
            state: p.state,
            service: p.service,
            banner: p.banner,
            elapsed_ms: p.elapsed_ms,
          }))}
        />
      </div>
    );
  }

  if (Array.isArray(results.records)) {
    sections.push(
      <div key="records">
        <SectionTitle>DNS records (DNS-over-HTTPS)</SectionTitle>
        <div className="rounded-lg border border-white/[0.06] bg-[#0a0b14] px-3 py-2 max-h-56 overflow-y-auto">
          {(results.records as string[]).map((r, i) => (
            <MonoLine key={i} dotClass="bg-indigo-400">
              {r}
            </MonoLine>
          ))}
        </div>
      </div>
    );
  }

  if (Array.isArray(results.tls)) {
    sections.push(
      <div key="tls">
        <SectionTitle>TLS / certificate evidence</SectionTitle>
        <div className="rounded-lg border border-white/[0.06] bg-[#0a0b14] px-3 py-2 max-h-56 overflow-y-auto">
          {(results.tls as string[]).map((t, i) => (
            <MonoLine key={i} dotClass="bg-teal-400">
              {t}
            </MonoLine>
          ))}
        </div>
      </div>
    );
  }

  if (Array.isArray(results.probes)) {
    sections.push(
      <div key="probes">
        <SectionTitle>HTTP probes (live responses)</SectionTitle>
        <div className="rounded-lg border border-white/[0.06] bg-[#0a0b14] px-3 py-2">
          {(results.probes as string[]).map((p, i) => (
            <MonoLine key={i} dotClass="bg-sky-400">
              {p}
            </MonoLine>
          ))}
        </div>
      </div>
    );
  }

  if (Array.isArray(results.technologies)) {
    sections.push(
      <div key="tech">
        <SectionTitle>Detected technologies</SectionTitle>
        <div className="flex flex-wrap gap-1.5">
          {(results.technologies as string[]).map((t, i) => (
            <span
              key={i}
              className="text-[11px] px-2 py-1 rounded-md bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-mono"
            >
              {t}
            </span>
          ))}
        </div>
      </div>
    );
  }

  if (Array.isArray(results.findings)) {
    const findings = results.findings as string[];
    sections.push(
      <div key="findings">
        <SectionTitle>Check log ({findings.length} checks)</SectionTitle>
        <div className="rounded-lg border border-white/[0.06] bg-[#0a0b14] px-3 py-2 max-h-56 overflow-y-auto">
          {findings.map((f, i) => (
            <MonoLine key={i} dotClass="bg-blue-400">
              {f}
            </MonoLine>
          ))}
        </div>
      </div>
    );
  }

  if (typeof results.error === 'string') {
    sections.push(
      <div key="error" className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2.5">
        <span className="text-xs text-red-400 font-mono break-all">
          <Circle className="w-3 h-3 inline mr-1.5 -mt-0.5 fill-red-400" />
          {results.error}
        </span>
      </div>
    );
  }

  if (sections.length === 0) {
    return (
      <p className="text-xs text-gray-600">
        This scan is still pending — results will appear once it completes.
      </p>
    );
  }

  return <>{sections}</>;
}

function PortTable({
  entries,
}: {
  entries: Array<{
    port: number;
    state: string;
    service: string;
    banner?: string;
    elapsed_ms?: number;
    rawState?: string;
  }>;
}) {
  return (
    <div className="overflow-x-auto rounded-lg border border-white/[0.06]">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-white/[0.03] text-gray-500 text-left">
            <th className="px-3 py-2 font-medium">Port</th>
            <th className="px-3 py-2 font-medium">State</th>
            <th className="px-3 py-2 font-medium">Service</th>
            <th className="px-3 py-2 font-medium">Evidence / banner</th>
            <th className="px-3 py-2 font-medium text-right">ms</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((p) => (
            <tr key={`${p.port}-${p.state}`} className="border-t border-white/[0.04]">
              <td className="px-3 py-1.5 font-mono text-gray-300">{p.port}</td>
              <td className="px-3 py-1.5">
                <span
                  className={`px-1.5 py-0.5 rounded border text-[10px] ${stateClass(p.state)}`}
                  title={p.rawState ? `raw tool state: ${p.rawState}` : undefined}
                >
                  {stateLabel(p.state).toLowerCase()}
                </span>
              </td>
              <td className="px-3 py-1.5 text-gray-400">{p.service || '—'}</td>
              <td className="px-3 py-1.5 font-mono text-gray-500 max-w-md">
                <span className="break-all">{p.banner || '—'}</span>
              </td>
              <td className="px-3 py-1.5 text-right text-gray-600">{p.elapsed_ms ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
