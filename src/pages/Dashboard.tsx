import { useEffect, useState } from 'react';
import {
  Rocket,
  FileWarning,
  ShieldCheck,
  Activity,
  TrendingUp,
  Clock,
  ChevronRight,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { supabase, type Scan, type Vulnerability } from '@/lib/supabase';
import { TOOLS, SEVERITY_COLORS } from '@/lib/tools';
import type { PageId } from '@/components/Layout';

export default function Dashboard({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    const [scanRes, vulnRes] = await Promise.all([
      supabase.from('scans').select('*').order('created_at', { ascending: false }).limit(10),
      supabase.from('vulnerabilities').select('*').order('created_at', { ascending: false }).limit(20),
    ]);
    setScans(scanRes.data ?? []);
    setVulns(vulnRes.data ?? []);
    setLoading(false);
  };

  const stats = {
    totalScans: scans.length,
    completedScans: scans.filter((s) => s.status === 'completed').length,
    runningScans: scans.filter((s) => s.status === 'running').length,
    totalVulns: vulns.length,
    critical: vulns.filter((v) => v.severity === 'critical').length,
    high: vulns.filter((v) => v.severity === 'high').length,
    medium: vulns.filter((v) => v.severity === 'medium').length,
    low: vulns.filter((v) => v.severity === 'low').length,
    info: vulns.filter((v) => v.severity === 'info').length,
  };

  const availableTools = TOOLS.filter((t) => t.available).length;
  const unavailableTools = TOOLS.filter((t) => !t.available).length;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6 fade-in">
      {/* Welcome banner */}
      <div className="glass-card p-6">
        <h1 className="text-lg font-semibold mb-1">Security Overview</h1>
        <p className="text-gray-500 text-sm">
          Monitor your scans, vulnerabilities, and tool status at a glance
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Rocket}
          label="Total Scans"
          value={stats.totalScans}
          subtext={`${stats.completedScans} completed`}
          color="blue"
        />
        <StatCard
          icon={FileWarning}
          label="Vulnerabilities"
          value={stats.totalVulns}
          subtext={`${stats.critical} critical`}
          color="red"
        />
        <StatCard
          icon={Activity}
          label="Running Scans"
          value={stats.runningScans}
          subtext={stats.runningScans > 0 ? 'In progress' : 'All idle'}
          color="yellow"
        />
        <StatCard
          icon={ShieldCheck}
          label="Tools Available"
          value={`${availableTools}/${TOOLS.length}`}
          subtext={`${unavailableTools} not installed`}
          color="green"
        />
      </div>

      {/* Tool availability notification */}
      {unavailableTools > 0 && (
        <div className="glass-card p-4 border-yellow-500/20 bg-yellow-500/[0.03]">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-yellow-400 mb-1">
                {unavailableTools} tool{unavailableTools > 1 ? 's' : ''} not available
              </h3>
              <p className="text-xs text-gray-500">
                The following tools are not installed on this system:{' '}
                {TOOLS.filter((t) => !t.available).map((t, i) => (
                  <span key={t.id}>
                    <span className="text-yellow-400/80">{t.name}</span>
                    {i < unavailableTools - 1 ? ', ' : ''}
                  </span>
                ))}
                . You can still use the {availableTools} available tools for scanning.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Recent scans */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              Recent Scans
            </h3>
            <button
              onClick={() => onNavigate('scan')}
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
            >
              New Scan <ChevronRight className="w-3 h-3" />
            </button>
          </div>
          {scans.length === 0 ? (
            <EmptyState
              icon={Rocket}
              text="No scans yet"
              subtext="Launch your first scan to see results here"
              action={() => onNavigate('scan')}
              actionLabel="Start Scanning"
            />
          ) : (
            <div className="space-y-2">
              {scans.slice(0, 5).map((scan) => {
                const tool = TOOLS.find((t) => t.id === scan.tool);
                return (
                  <div
                    key={scan.id}
                    className="flex items-center gap-3 p-3 rounded-lg bg-white/[0.02] hover:bg-white/[0.04] transition-colors cursor-pointer"
                    onClick={() => onNavigate('vulnerabilities')}
                  >
                    <div
                      className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: `${tool?.color}15` }}
                    >
                      {tool && <tool.icon className="w-4 h-4" style={{ color: tool.color }} />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium truncate">{scan.target}</div>
                      <div className="text-xs text-gray-500">{tool?.name ?? scan.tool}</div>
                    </div>
                    <StatusBadge status={scan.status} />
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Vulnerability breakdown */}
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-orange-400" />
              Vulnerability Breakdown
            </h3>
            <button
              onClick={() => onNavigate('vulnerabilities')}
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors"
            >
              View All <ChevronRight className="w-3 h-3" />
            </button>
          </div>
          {vulns.length === 0 ? (
            <EmptyState
              icon={ShieldCheck}
              text="No vulnerabilities found"
              subtext="Run a scan to discover security issues"
            />
          ) : (
            <div className="space-y-3">
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                const count = stats[sev];
                if (count === 0) return null;
                const colors = SEVERITY_COLORS[sev];
                const pct = (count / stats.totalVulns) * 100;
                return (
                  <div key={sev}>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${colors.dot}`} />
                        <span className="text-sm capitalize text-gray-300">{sev}</span>
                      </div>
                      <span className="text-sm font-medium text-gray-400">{count}</span>
                    </div>
                    <div className="h-2 bg-white/[0.04] rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${colors.dot} transition-all duration-500`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Tool status grid */}
      <div className="glass-card p-5">
        <h3 className="font-semibold mb-4 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-green-400" />
          Tool Status
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {TOOLS.map((tool) => (
            <div
              key={tool.id}
              className={`p-3 rounded-lg border transition-all ${
                tool.available
                  ? 'bg-white/[0.02] border-white/[0.06]'
                  : 'bg-yellow-500/[0.03] border-yellow-500/15'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <tool.icon className="w-4 h-4 flex-shrink-0" style={{ color: tool.color }} />
                <span className="text-sm font-medium truncate">{tool.name}</span>
              </div>
              <div className="flex items-center gap-1.5">
                {tool.available ? (
                  <>
                    <CheckCircle2 className="w-3 h-3 text-green-500" />
                    <span className="text-xs text-green-400">Available</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-3 h-3 text-yellow-500/60" />
                    <span className="text-xs text-yellow-500/60">Not installed</span>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  subtext,
  color,
}: {
  icon: typeof Rocket;
  label: string;
  value: number | string;
  subtext: string;
  color: 'blue' | 'red' | 'yellow' | 'green';
}) {
  const colors = {
    blue: { bg: 'bg-blue-500/10', text: 'text-blue-400' },
    red: { bg: 'bg-red-500/10', text: 'text-red-400' },
    yellow: { bg: 'bg-yellow-500/10', text: 'text-yellow-400' },
    green: { bg: 'bg-green-500/10', text: 'text-green-400' },
  };
  const c = colors[color];
  return (
    <div className="glass-card p-4">
      <div className="flex items-start justify-between mb-2">
        <div className={`w-9 h-9 rounded-lg ${c.bg} flex items-center justify-center`}>
          <Icon className={`w-4 h-4 ${c.text}`} />
        </div>
      </div>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-sm text-gray-400 mt-0.5">{label}</div>
      <div className="text-xs text-gray-600 mt-1">{subtext}</div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: 'bg-green-500/10 text-green-400 border-green-500/20',
    running: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    pending: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    failed: 'bg-red-500/10 text-red-400 border-red-500/20',
  };
  return (
    <span className={`text-xs px-2 py-1 rounded-full border ${styles[status] ?? styles.pending} capitalize`}>
      {status}
    </span>
  );
}

function EmptyState({
  icon: Icon,
  text,
  subtext,
  action,
  actionLabel,
}: {
  icon: typeof Rocket;
  text: string;
  subtext: string;
  action?: () => void;
  actionLabel?: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-8 text-center">
      <Icon className="w-10 h-10 text-gray-700 mb-3" />
      <p className="text-sm font-medium text-gray-400">{text}</p>
      <p className="text-xs text-gray-600 mt-1">{subtext}</p>
      {action && actionLabel && (
        <button
          onClick={action}
          className="mt-4 text-xs px-3 py-1.5 rounded-lg bg-blue-600/15 text-blue-400 border border-blue-500/20 hover:bg-blue-600/25 transition-all"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
