import { useState } from 'react';
import {
  Rocket,
  Loader2,
  AlertCircle,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
  Target,
  Settings,
  Zap,
} from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { useAuth } from '@/context/AuthContext';
import { TOOLS, type ToolDef } from '@/lib/tools';
import type { PageId } from '@/components/Layout';

type ScanStep = 'tool' | 'target' | 'options' | 'confirm';

export default function ScanLaunch({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const { session } = useAuth();
  const [step, setStep] = useState<ScanStep>('tool');
  const [selectedTool, setSelectedTool] = useState<ToolDef | null>(null);
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState<Record<string, string>>({});
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const availableTools = TOOLS.filter((t) => t.available);
  const unavailableTools = TOOLS.filter((t) => !t.available);

  const handleLaunch = async () => {
    if (!selectedTool || !target) return;
    setLaunching(true);
    setError(null);

    try {
      const { error: insertError } = await supabase.from('scans').insert({
        target,
        tool: selectedTool.id,
        status: 'pending',
        options,
      });

      if (insertError) throw insertError;

      const { data: scanData } = await supabase
        .from('scans')
        .select('id')
        .eq('target', target)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (scanData) {
        // Run the built-in HTTP scanner for immediate results.
        // Note: The Termux/Kali agent scans are executed separately via the Lab,
        // so we avoid firing both here to prevent duplicate vulnerabilities.
        const scanUrl = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/orion-scan`;
        const response = await fetch(scanUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${session?.access_token ?? ''}`,
          },
          body: JSON.stringify({
            scanId: scanData.id,
            tool: selectedTool.id,
            target,
            options,
          }),
        });

        if (response.ok) {
          const result = await response.json();
          const vulns = result.vulnerabilities ?? [];

          if (vulns.length > 0) {
            const vulnRows = vulns.map((v: Record<string, unknown>) => ({
              scan_id: scanData.id,
              title: v.title as string,
              severity: v.severity as string,
              description: (v.description as string) ?? '',
              evidence: (v.evidence as string) ?? '',
              remediation: (v.remediation as string) ?? '',
              cve: (v.cve as string) ?? null,
              port: (v.port as number) ?? null,
              service: (v.service as string) ?? null,
            }));
            await supabase.from('vulnerabilities').insert(vulnRows);
          }
        }

        setSuccess(true);
        setTimeout(() => {
          onNavigate('vulnerabilities');
        }, 2000);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to launch scan');
    } finally {
      setLaunching(false);
    }
  };

  if (success) {
    return (
      <div className="flex flex-col items-center justify-center h-96 fade-in">
        <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mb-4">
          <CheckCircle2 className="w-8 h-8 text-green-500" />
        </div>
        <h2 className="text-xl font-bold mb-2">Scan Completed!</h2>
        <p className="text-gray-500 text-sm">Redirecting to vulnerability report...</p>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6 fade-in">
      {/* Progress steps */}
      <div className="flex items-center justify-center gap-2 mb-2">
        {(['tool', 'target', 'options', 'confirm'] as ScanStep[]).map((s, i) => {
          const isActive = step === s;
          const isPast = ['tool', 'target', 'options', 'confirm'].indexOf(step) > i;
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
              {i < 3 && <div className={`w-12 h-px ${isPast ? 'bg-blue-500/30' : 'bg-white/[0.06]'}`} />}
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
          <p className="text-sm text-gray-500 mb-4">Choose which security tool to use for this scan</p>

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
                <span>{unavailableTools.length} tools not installed on this system</span>
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
                        <div className="text-xs text-yellow-500/50 mt-1.5">Not installed</div>
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
            Using <span className="text-blue-400 font-medium">{selectedTool.name}</span> — specify the target URL or IP address
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
              Only scan targets you own or have explicit permission to test. Unauthorized scanning is illegal.
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
              onClick={() => target && setStep('options')}
              disabled={!target}
              className="flex items-center gap-1 text-sm px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white transition-colors"
            >
              Continue <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Step: Options */}
      {step === 'options' && selectedTool && (
        <div className="glass-card p-6">
          <h3 className="font-semibold mb-1 flex items-center gap-2">
            <Settings className="w-4 h-4 text-blue-400" />
            Configure Scan Options
          </h3>
          <p className="text-sm text-gray-500 mb-4">
            Customize the scan parameters for {selectedTool.name}
          </p>

          <div className="space-y-4">
            {selectedTool.capabilities.map((cap) => (
              <div key={cap}>
                <label className="block text-sm font-medium text-gray-400 mb-1.5">{cap}</label>
                <input
                  type="text"
                  value={options[cap] ?? ''}
                  onChange={(e) => setOptions({ ...options, [cap]: e.target.value })}
                  placeholder="Leave empty for default"
                  className="w-full bg-[#0a0b14] border border-white/[0.06] rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-blue-500/50 transition-colors"
                />
              </div>
            ))}
          </div>

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
            Review & Launch
          </h3>
          <p className="text-sm text-gray-500 mb-4">Confirm your scan configuration before launching</p>

          <div className="space-y-3 mb-6">
            <ConfirmRow label="Tool" value={selectedTool.name} />
            <ConfirmRow label="Target" value={target} />
            <ConfirmRow
              label="Options"
              value={
                Object.keys(options).length > 0
                  ? Object.entries(options)
                      .filter(([, v]) => v)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join(', ')
                  : 'Default settings'
              }
            />
          </div>

          {error && (
            <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400 mb-4">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center justify-between">
            <button
              onClick={() => setStep('options')}
              className="flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" /> Back
            </button>
            <button
              onClick={handleLaunch}
              disabled={launching}
              className="flex items-center gap-2 text-sm px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium transition-colors"
            >
              {launching ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> Scanning...
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
