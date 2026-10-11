import { useMemo, useState } from 'react';
import {
  Rocket,
  Loader2,
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
  Target,
  Zap,
  ShieldCheck,
  Layers,
  ClipboardList,
} from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { useAuth } from '@/context/AuthContext';
import { TOOLS, type ToolDef } from '@/lib/tools';
import {
  PROFILES,
  CUSTOM_PHASES,
  EDGE_PORT_BUDGET,
  type Profile,
} from '@/lib/scanModel';
import type { PageId } from '@/components/Layout';

type ScanStep = 'tool' | 'target' | 'profile' | 'confirm';

const QUICK_PORT_EXAMPLES = ['22,80,443,8080', '1-1024', '1-65535'];

export default function ScanLaunch({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const { session } = useAuth();
  const [step, setStep] = useState<ScanStep>('tool');
  const [selectedTool, setSelectedTool] = useState<ToolDef | null>(null);
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState<Profile>('standard');
  const [customPhases, setCustomPhases] = useState<string[]>(CUSTOM_PHASES.map((p) => p.key));
  const [customPorts, setCustomPorts] = useState('');
  const [agreed, setAgreed] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const availableTools = TOOLS.filter((t) => t.available);
  const unavailableTools = TOOLS.filter((t) => !t.available);

  const selectedProfile = useMemo(() => PROFILES.find((p) => p.id === profile)!, [profile]);
  const customPortsWarn = useMemo(() => {
    if (profile !== 'custom' || !customPorts.trim()) return null;
    // Best-effort size estimate for the honest "not tested" note.
    const parts = customPorts.split(',').map((p) => p.trim()).filter(Boolean);
    let count = 0;
    for (const part of parts) {
      const range = part.match(/^(\d+)\s*-\s*(\d+)$/);
      if (range) {
        const a = parseInt(range[1], 10);
        const b = parseInt(range[2], 10);
        if (Number.isFinite(a) && Number.isFinite(b) && b >= a) count += b - a + 1;
      } else if (/^\d+$/.test(part)) {
        count += 1;
      }
    }
    if (count > EDGE_PORT_BUDGET) {
      return `This scope requests ${count.toLocaleString()} ports. The edge runtime probes the first ${EDGE_PORT_BUDGET}; the remainder are reported as "not tested" unless an online Orvyn Agent runs the full sweep.`;
    }
    return null;
  }, [profile, customPorts]);

  const buildOptions = (): Record<string, string> => {
    if (profile === 'custom') {
      const opts: Record<string, string> = {};
      if (customPhases.length > 0) opts.phases = customPhases.join(',');
      if (customPorts.trim()) opts.ports = customPorts.trim();
      return opts;
    }
    return {};
  };

  const handleLaunch = async () => {
    if (!selectedTool || !target.trim() || !agreed) return;
    setLaunching(true);
    setError(null);

    const options = buildOptions();
    const cleanTarget = target.trim();

    try {
      // 1. Record the scan + the user's authorization assertion.
      const { data: inserted, error: insertError } = await supabase
        .from('scans')
        .insert({
          target: cleanTarget,
          tool: selectedTool.id,
          status: 'pending',
          options,
          profile,
          authorization: {
            confirmed: true,
            method: 'user_assertion',
            statement: 'I confirm I am authorized to scan this target.',
            at: new Date().toISOString(),
          },
        })
        .select('id')
        .single();

      if (insertError) throw insertError;
      const scanId = inserted?.id as string | undefined;
      if (!scanId) throw new Error('Could not create the scan record');

      // 2. Kick off the orchestrator and go straight to live results.
      //    The request keeps running after navigation; failures are written
      //    back to the scan row and surface on the Scans page.
      const scanUrl = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/orion-scan`;
      const request = fetch(scanUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session?.access_token ?? ''}`,
        },
        body: JSON.stringify({
          scanId,
          tool: selectedTool.id,
          target: cleanTarget,
          options,
          profile,
        }),
      });

      onNavigate('scans');

      void request
        .then(async (response) => {
          if (response.ok) return;
          let reason = `Scan request failed (${response.status})`;
          try {
            const body = await response.json();
            if (body?.message) reason = String(body.message);
            else if (body?.error) reason = String(body.error);
          } catch {
            /* keep the status-based message */
          }
          await supabase
            .from('scans')
            .update({
              status: 'failed',
              results: { error: reason },
              progress: { percent: 0, state: 'failed', updated_at: new Date().toISOString() },
              completed_at: new Date().toISOString(),
            })
            .eq('id', scanId);
        })
        .catch(async (err: unknown) => {
          await supabase
            .from('scans')
            .update({
              status: 'failed',
              results: { error: err instanceof Error ? err.message : 'Network error' },
              completed_at: new Date().toISOString(),
            })
            .eq('id', scanId);
        });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to launch scan');
      setLaunching(false);
    }
  };

  const steps: ScanStep[] = ['tool', 'target', 'profile', 'confirm'];

  return (
    <div className="max-w-3xl mx-auto space-y-6 fade-in">
      {/* Progress steps */}
      <div className="flex items-center justify-center gap-2 mb-2">
        {steps.map((s, i) => {
          const isActive = step === s;
          const isPast = steps.indexOf(step) > i;
          return (
            <div key={s} className="flex items-center">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium border transition-all ${
                  isActive
                    ? 'bg-blue-600 text-white border-blue-500'
                    : isPast
                    ? 'bg-blue-600/20 text-blue-400 border-blue-500/30'
                    : 'bg-white/[0.03] text-gray-600 border-white/[0.06]'
                }`}
              >
                {isPast ? <CheckCircle2 className="w-4 h-4" /> : i + 1}
              </div>
              {i < steps.length - 1 && (
                <div className={`w-12 h-px ${isPast ? 'bg-blue-500/30' : 'bg-white/[0.06]'}`} />
              )}
            </div>
          );
        })}
      </div>

      {/* Step: Tool selection */}
      {step === 'tool' && (
        <div className="glass-card p-6">
          <h3 className="font-semibold mb-1 flex items-center gap-2">
            <Zap className="w-4 h-4 text-blue-400" />
            Select a Scanning Tool
          </h3>
          <p className="text-sm text-gray-500 mb-4">
            The tool that produces primary evidence for this scan. Tools marked unavailable need to be
            installed on an Orvyn Agent (see the Lab).
          </p>

          <div className="grid sm:grid-cols-2 gap-3">
            {availableTools.map((tool) => (
              <button
                key={tool.id}
                onClick={() => {
                  setSelectedTool(tool);
                  setStep('target');
                }}
                className="glass-card-hover p-4 text-left group"
              >
                <div className="flex items-start gap-3">
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: `${tool.color}15` }}
                  >
                    <tool.icon className="w-5 h-5" style={{ color: tool.color }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-sm flex items-center gap-2">
                      {tool.name}
                      <ChevronRight className="w-3 h-3 text-gray-600 group-hover:text-blue-400 transition-colors" />
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5">{tool.category}</div>
                    <div className="text-xs text-gray-600 mt-1.5 line-clamp-2">{tool.description}</div>
                  </div>
                </div>
              </button>
            ))}
          </div>

          {unavailableTools.length > 0 && (
            <div className="mt-6">
              <div className="flex items-center gap-2 mb-3 text-xs text-yellow-500/70">
                <AlertCircle className="w-4 h-4" />
                <span>{unavailableTools.length} tools not available on the edge runtime</span>
              </div>
              <div className="grid sm:grid-cols-2 gap-3 opacity-40">
                {unavailableTools.map((tool) => (
                  <div key={tool.id} className="glass-card p-4 cursor-not-allowed">
                    <div className="flex items-start gap-3">
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                        style={{ backgroundColor: `${tool.color}10` }}
                      >
                        <tool.icon className="w-5 h-5" style={{ color: tool.color }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-sm">{tool.name}</div>
                        <div className="text-xs text-gray-500 mt-0.5">{tool.category}</div>
                        <div className="text-xs text-yellow-500/50 mt-1.5">
                          Run it on an Orvyn Agent
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Step: Target input */}
      {step === 'target' && selectedTool && (
        <div className="glass-card p-6">
          <h3 className="font-semibold mb-1 flex items-center gap-2">
            <Target className="w-4 h-4 text-blue-400" />
            Enter Your Target
          </h3>
          <p className="text-sm text-gray-500 mb-4">
            Using <span className="text-blue-400 font-medium">{selectedTool.name}</span> — specify the
            target URL, hostname or IP address
          </p>

          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com or 192.168.1.1"
            className="w-full bg-[#0a0b14] border border-white/[0.06] rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-blue-500/50 transition-colors"
            autoFocus
          />

          <div className="mt-3 p-3 bg-blue-500/[0.05] border border-blue-500/15 rounded-lg">
            <p className="text-xs text-blue-400/80">
              Only scan targets you own or have explicit permission to test. Unauthorized scanning is
              illegal.
            </p>
          </div>

          <div className="flex items-center justify-between mt-6">
            <button
              onClick={() => setStep('tool')}
              className="flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" /> Back
            </button>
            <button
              onClick={() => target.trim() && setStep('profile')}
              disabled={!target.trim()}
              className="flex items-center gap-1 text-sm px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white transition-colors"
            >
              Continue <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Step: Profile */}
      {step === 'profile' && selectedTool && (
        <div className="glass-card p-6">
          <h3 className="font-semibold mb-1 flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            Choose a Scan Profile
          </h3>
          <p className="text-sm text-gray-500 mb-4">
            The profile decides which phases run and how many ports are probed. Coverage is always
            reported honestly.
          </p>

          <div className="space-y-3">
            {PROFILES.map((p) => (
              <button
                key={p.id}
                onClick={() => setProfile(p.id)}
                className={`w-full text-left p-4 rounded-lg border transition-all ${
                  profile === p.id
                    ? 'bg-blue-600/10 border-blue-500/40'
                    : 'bg-white/[0.02] border-white/[0.06] hover:border-white/[0.12]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-sm flex items-center gap-2">
                    {p.name}
                    <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-white/[0.05] text-gray-400">
                      {p.tagline}
                    </span>
                  </span>
                  {profile === p.id && <CheckCircle2 className="w-4 h-4 text-blue-400" />}
                </div>
                <p className="text-xs text-gray-500 mt-1.5">{p.description}</p>
                <p className="text-[11px] text-gray-600 mt-1">Phases: {p.phases}</p>
                {p.needsAgent && (
                  <p className="text-[11px] text-purple-400/80 mt-1.5 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3" /> Full 65535-port sweep and vulnerability
                    modules require an online Orvyn Agent.
                  </p>
                )}
              </button>
            ))}
          </div>

          {profile === 'custom' && (
            <div className="mt-4 space-y-4 border-t border-white/[0.06] pt-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-2">
                  Phases to run
                </label>
                <div className="grid sm:grid-cols-2 gap-2">
                  {CUSTOM_PHASES.map((ph) => {
                    const on = customPhases.includes(ph.key);
                    return (
                      <button
                        key={ph.key}
                        onClick={() =>
                          setCustomPhases((prev) =>
                            prev.includes(ph.key)
                              ? prev.filter((k) => k !== ph.key)
                              : [...prev, ph.key]
                          )
                        }
                        className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs text-left transition-all ${
                          on
                            ? 'bg-blue-600/10 border-blue-500/30 text-blue-300'
                            : 'bg-white/[0.02] border-white/[0.06] text-gray-500'
                        }`}
                      >
                        <span
                          className={`w-3.5 h-3.5 rounded border flex items-center justify-center ${
                            on ? 'bg-blue-500 border-blue-500' : 'border-white/20'
                          }`}
                        >
                          {on && <CheckCircle2 className="w-3 h-3 text-white" />}
                        </span>
                        {ph.name}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-400 mb-2">
                  Port expression (optional)
                </label>
                <input
                  type="text"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  placeholder="e.g. 22,80,443 or 1-1024"
                  className="w-full bg-[#0a0b14] border border-white/[0.06] rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-blue-500/50 transition-colors"
                />
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {QUICK_PORT_EXAMPLES.map((ex) => (
                    <button
                      key={ex}
                      onClick={() => setCustomPorts(ex)}
                      className="text-[11px] font-mono px-2 py-0.5 rounded bg-white/[0.04] text-gray-400 hover:text-gray-200 border border-white/[0.06]"
                    >
                      {ex}
                    </button>
                  ))}
                </div>
                {customPortsWarn && (
                  <div className="mt-2 p-2.5 bg-amber-500/[0.08] border border-amber-500/20 rounded-lg text-[11px] text-amber-400/90">
                    {customPortsWarn}
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="flex items-center justify-between mt-6">
            <button
              onClick={() => setStep('target')}
              className="flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" /> Back
            </button>
            <button
              onClick={() => setStep('confirm')}
              className="flex items-center gap-1 text-sm px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
            >
              Continue <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Step: Confirm */}
      {step === 'confirm' && selectedTool && (
        <div className="glass-card p-6">
          <h3 className="font-semibold mb-1 flex items-center gap-2">
            <Rocket className="w-4 h-4 text-blue-400" />
            Review &amp; Launch
          </h3>
          <p className="text-sm text-gray-500 mb-4">
            Confirm your configuration and record your authorization.
          </p>

          <div className="space-y-3 mb-5">
            <ConfirmRow label="Tool" value={selectedTool.name} />
            <ConfirmRow label="Target" value={target.trim()} />
            <ConfirmRow label="Profile" value={selectedProfile.name} />
            <ConfirmRow
              label="Scope"
              value={
                profile === 'custom'
                  ? `Phases: ${customPhases.length || 'none'} · Ports: ${customPorts.trim() || 'default'}`
                  : selectedProfile.phases
              }
            />
          </div>

          {profile === 'comprehensive' && (
            <div className="flex items-start gap-2 p-3 bg-purple-500/[0.06] border border-purple-500/20 rounded-lg text-xs text-purple-300/90 mb-4">
              <ShieldCheck className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>
                Comprehensive requests all 65535 ports. The full sweep runs on an online Orvyn Agent
                (nmap); without one, port coverage is reported as partial — never as a complete
                result.
              </span>
            </div>
          )}

          <label className="flex items-start gap-3 p-3 bg-white/[0.02] border border-white/[0.06] rounded-lg cursor-pointer mb-5">
            <input
              type="checkbox"
              checked={agreed}
              onChange={(e) => setAgreed(e.target.checked)}
              className="mt-0.5 w-4 h-4 accent-blue-500"
            />
            <span className="text-xs text-gray-400">
              I confirm I am authorized to scan <span className="font-medium text-gray-200">{target.trim()}</span>{' '}
              and I accept responsibility for this scan. This authorization is recorded with the scan.
            </span>
          </label>

          {error && (
            <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400 mb-4">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center justify-between">
            <button
              onClick={() => setStep('profile')}
              className="flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" /> Back
            </button>
            <button
              onClick={handleLaunch}
              disabled={launching || !agreed}
              className="flex items-center gap-2 text-sm px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium transition-colors"
            >
              {launching ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> Launching…
                </>
              ) : (
                <>
                  <Rocket className="w-4 h-4" /> Launch Scan
                </>
              )}
            </button>
          </div>
        </div>
      )}

      <div className="flex items-center justify-center gap-2 text-[11px] text-gray-600">
        <ClipboardList className="w-3.5 h-3.5" />
        Live phases, coverage and raw port states appear on the Scan History page.
      </div>
    </div>
  );
}

function ConfirmRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between p-3 bg-white/[0.02] rounded-lg">
      <span className="text-sm text-gray-500">{label}</span>
      <span className="text-sm font-medium text-right max-w-[60%]">{value}</span>
    </div>
  );
}
