import { useEffect, useState } from 'react';
import {
  FileWarning,
  Loader2,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  Bug,
  Shield,
  ExternalLink,
  X,
} from 'lucide-react';
import { supabase, type Vulnerability } from '@/lib/supabase';
import { SEVERITY_COLORS, SEVERITY_ORDER } from '@/lib/tools';

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  useEffect(() => {
    loadVulns();
  }, []);

  const loadVulns = async () => {
    setLoading(true);
    const { data } = await supabase
      .from('vulnerabilities')
      .select('*')
      .order('created_at', { ascending: false });
    setVulns((data ?? []) as Vulnerability[]);
    setLoading(false);
  };

  const filtered = vulns
    .filter((v) => severityFilter === 'all' || v.severity === severityFilter)
    .filter(
      (v) =>
        !search ||
        v.title.toLowerCase().includes(search.toLowerCase()) ||
        v.description.toLowerCase().includes(search.toLowerCase()) ||
        (v.cve ?? '').toLowerCase().includes(search.toLowerCase())
    )
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const counts = {
    all: vulns.length,
    critical: vulns.filter((v) => v.severity === 'critical').length,
    high: vulns.filter((v) => v.severity === 'high').length,
    medium: vulns.filter((v) => v.severity === 'medium').length,
    low: vulns.filter((v) => v.severity === 'low').length,
    info: vulns.filter((v) => v.severity === 'info').length,
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
      {/* Header */}
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <FileWarning className="w-5 h-5 text-red-400" />
            Vulnerability Report
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            {vulns.length} finding{vulns.length !== 1 ? 's' : ''} across all scans
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search vulnerabilities..."
            className="w-full bg-[#0a0b14] border border-white/[0.06] rounded-lg pl-10 pr-3 py-2.5 text-sm focus:outline-none focus:border-blue-500/50 transition-colors"
          />
        </div>
      </div>

      {/* Severity tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        <Filter className="w-4 h-4 text-gray-500 flex-shrink-0" />
        {(['all', 'critical', 'high', 'medium', 'low', 'info'] as SeverityFilter[]).map((sev) => {
          const active = severityFilter === sev;
          const colors = sev !== 'all' ? SEVERITY_COLORS[sev] : null;
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap border transition-all ${
                active
                  ? colors
                    ? `${colors.bg} ${colors.text} ${colors.border}`
                    : 'bg-blue-600/15 text-blue-400 border-blue-500/20'
                  : 'bg-white/[0.02] text-gray-500 border-white/[0.04] hover:text-gray-300'
              }`}
            >
              {sev !== 'all' && colors && <span className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} />}
              <span className="capitalize">{sev}</span>
              <span className="opacity-60">{counts[sev]}</span>
            </button>
          );
        })}
      </div>

      {/* Vulnerability list */}
      {filtered.length === 0 ? (
        <div className="glass-card p-12 flex flex-col items-center justify-center text-center">
          <Shield className="w-12 h-12 text-gray-700 mb-3" />
          <p className="text-sm font-medium text-gray-400">
            {vulns.length === 0 ? 'No vulnerabilities found yet' : 'No results match your filters'}
          </p>
          <p className="text-xs text-gray-600 mt-1">
            {vulns.length === 0 ? 'Run a scan to discover security issues' : 'Try adjusting your search or filters'}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((vuln) => {
            const colors = SEVERITY_COLORS[vuln.severity];
            const expanded = expandedId === vuln.id;
            return (
              <div key={vuln.id} className={`glass-card overflow-hidden border ${colors.border}`}>
                <button
                  onClick={() => setExpandedId(expanded ? null : vuln.id)}
                  className="w-full p-4 flex items-start gap-3 text-left hover:bg-white/[0.02] transition-colors"
                >
                  <div className={`w-10 h-10 rounded-lg ${colors.bg} flex items-center justify-center flex-shrink-0`}>
                    <Bug className={`w-5 h-5 ${colors.text}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium">{vuln.title}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full ${colors.bg} ${colors.text} capitalize`}>
                        {vuln.severity}
                      </span>
                      {vuln.cve && (
                        <span className="text-xs px-2 py-0.5 rounded-full bg-white/[0.04] text-gray-400 font-mono">
                          {vuln.cve}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 mt-1 line-clamp-2">{vuln.description}</p>
                    {(vuln.port || vuln.service) && (
                      <div className="flex items-center gap-3 mt-2 text-xs text-gray-600">
                        {vuln.port && <span>Port: {vuln.port}</span>}
                        {vuln.service && <span>Service: {vuln.service}</span>}
                      </div>
                    )}
                  </div>
                  {expanded ? (
                    <ChevronUp className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
                  )}
                </button>

                {expanded && (
                  <div className="px-4 pb-4 pl-17 space-y-3 fade-in">
                    <div className="pl-13 space-y-3">
                      <DetailSection label="Description" content={vuln.description} />
                      {vuln.evidence && <DetailSection label="Evidence" content={vuln.evidence} mono />}
                      {vuln.remediation && <DetailSection label="Remediation" content={vuln.remediation} />}
                      <button
                        onClick={() => setSelectedVuln(vuln)}
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" /> View full report
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Detail modal */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setSelectedVuln(null)} />
          <div className="relative glass-card p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <button
              onClick={() => setSelectedVuln(null)}
              className="absolute top-4 right-4 p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-start gap-3 mb-4">
              <div
                className={`w-12 h-12 rounded-lg ${SEVERITY_COLORS[selectedVuln.severity].bg} flex items-center justify-center flex-shrink-0`}
              >
                <Bug className={`w-6 h-6 ${SEVERITY_COLORS[selectedVuln.severity].text}`} />
              </div>
              <div>
                <h2 className="text-lg font-bold">{selectedVuln.title}</h2>
                <div className="flex items-center gap-2 mt-1">
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_COLORS[selectedVuln.severity].bg} ${SEVERITY_COLORS[selectedVuln.severity].text} capitalize`}
                  >
                    {selectedVuln.severity}
                  </span>
                  {selectedVuln.cve && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-white/[0.04] text-gray-400 font-mono">
                      {selectedVuln.cve}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <DetailSection label="Description" content={selectedVuln.description} />
              {selectedVuln.evidence && <DetailSection label="Evidence" content={selectedVuln.evidence} mono />}
              {selectedVuln.remediation && <DetailSection label="Remediation" content={selectedVuln.remediation} />}
              {(selectedVuln.port || selectedVuln.service) && (
                <div className="grid grid-cols-2 gap-3">
                  {selectedVuln.port && (
                    <div className="p-3 bg-white/[0.02] rounded-lg">
                      <div className="text-xs text-gray-500">Port</div>
                      <div className="text-sm font-medium mt-0.5">{selectedVuln.port}</div>
                    </div>
                  )}
                  {selectedVuln.service && (
                    <div className="p-3 bg-white/[0.02] rounded-lg">
                      <div className="text-xs text-gray-500">Service</div>
                      <div className="text-sm font-medium mt-0.5">{selectedVuln.service}</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailSection({ label, content, mono }: { label: string; content: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs font-medium text-gray-500 mb-1">{label}</div>
      <div className={`text-sm text-gray-300 ${mono ? 'font-mono text-xs bg-[#0a0b14] p-3 rounded-lg border border-white/[0.04]' : ''}`}>
        {content}
      </div>
    </div>
  );
}
