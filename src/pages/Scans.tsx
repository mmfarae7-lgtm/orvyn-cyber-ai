import { useEffect, useState, type ReactNode } from 'react';
import {
  ClipboardList,
  Loader2,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Radar,
  Circle,
  FileWarning,
} from 'lucide-react';
import { supabase, type Scan } from '@/lib/supabase';
import { getToolById, SEVERITY_COLORS, type Severity } from '@/lib/tools';
import type { PageId } from '@/components/Layout';

type VulnCounts = Record<string, number>;

const STATE_STYLES: Record<string, string> = {
  open: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  closed: 'bg-white/[0.04] text-gray-500 border-white/[0.06]',
  timeout: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  unchecked: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
};

const STATUS_STYLES: Record<string, string> = {
  completed: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  running: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  pending: 'bg-white/[0.04] text-gray-400 border-white/[0.06]',
  failed: 'bg-red-500/10 text-red-400 border-red-500/20',
};

export default function Scans({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [counts, setCounts] = useState<Record<string, VulnCounts>>({});
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    const [{ data: scanData }, { data: vulnData }] = await Promise.all([
      supabase.from('scans').select('*').order('created_at', { ascending: false }).limit(50),
      supabase.from('vulnerabilities').select('scan_id, severity'),
    ]);
    const rows = (scanData ?? []) as Scan[];
    setScans(rows);

    const grouped: Record<string, VulnCounts> = {};
    for (const v of vulnData ?? []) {
      if (!v.scan_id) continue;
      grouped[v.scan_id] ??= {};
      grouped[v.scan_id][v.severity] = (grouped[v.scan_id][v.severity] ?? 0) + 1;
    }
    setCounts(grouped);
    if (expandedId === null && rows.length > 0) setExpandedId(rows[0].id);
    setLoading(false);
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
            Full raw results from every live scan — port states, DNS records, TLS evidence
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
          <p className="text-xs text-gray-600 mt-1">Launch your first scan to see raw results here</p>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => {
            const toolDef = getToolById(scan.tool);
            const Icon = toolDef?.icon ?? Radar;
            const vc = counts[scan.id] ?? {};
            const totalVulns = Object.values(vc).reduce((a, b) => a + b, 0);
            const expanded = expandedId === scan.id;
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
                    className={`text-[10px] px-2 py-1 rounded-full border capitalize ${STATUS_STYLES[scan.status] ?? STATUS_STYLES.pending}`}
                  >
                    {scan.status === 'running' || scan.status === 'pending' ? (
                      <span className="flex items-center gap-1">
                        <Loader2 className="w-3 h-3 animate-spin" /> {scan.status}
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
                  <div className="border-t border-white/[0.06] px-4 py-4 space-y-4 bg-[#0a0b14]/40">
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

function ResultSections({ results }: { results: Record<string, unknown> }) {
  const sections: ReactNode[] = [];

  if (Array.isArray(results.ports)) {
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
              {ports.map((p) => (
                <tr key={p.port} className="border-t border-white/[0.04]">
                  <td className="px-3 py-1.5 font-mono text-gray-300">{p.port}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className={`px-1.5 py-0.5 rounded border text-[10px] capitalize ${
                        STATE_STYLES[p.state] ?? STATE_STYLES.closed
                      }`}
                    >
                      {p.state}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-gray-400">{p.service}</td>
                  <td className="px-3 py-1.5 font-mono text-gray-500 max-w-md">
                    <span className="break-all">{p.banner || '—'}</span>
                  </td>
                  <td className="px-3 py-1.5 text-right text-gray-600">{p.elapsed_ms ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
