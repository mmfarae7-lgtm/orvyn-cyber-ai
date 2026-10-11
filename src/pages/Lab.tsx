import { useEffect, useState, useCallback, useMemo } from 'react';
import {
  FlaskConical,
  Loader2,
  Terminal,
  Trash2,
  Play,
  Clock,
  Smartphone,
  Server,
  CheckCircle2,
  XCircle,
  Wifi,
  Download,
  RefreshCw,
  Wrench,
} from 'lucide-react';
import { supabase, type Agent, type AgentTool } from '@/lib/supabase';
import { useAuth } from '@/context/AuthContext';
import { TOOLS } from '@/lib/tools';

type AgentTask = {
  id: string;
  tool: string;
  target: string;
  kind?: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  raw_output: string | null;
  error: string | null;
  assigned_to: string | null;
  progress?: { state?: string; note?: string } | null;
  created_at: string;
  completed_at: string | null;
};

type CapabilityInfo = {
  tool: string;
  in_registry: boolean;
  recipes: Record<string, string>;
  online_agents: Array<{
    agent_key: string;
    name: string;
    platform: string;
    status: string;
    last_seen: string;
    has_tool: boolean;
    tool_version: string | null;
  }>;
  available: boolean;
  missing: boolean;
};

function isFresh(lastSeen: string | null): boolean {
  if (!lastSeen) return false;
  return Date.now() - new Date(lastSeen).getTime() < 120_000;
}

export default function Lab() {
  const { session } = useAuth();
  const [tasks, setTasks] = useState<AgentTask[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTool, setSelectedTool] = useState(TOOLS.find((t) => t.available)!.id);
  const [command, setCommand] = useState('');
  const [running, setRunning] = useState(false);
  const [activeTask, setActiveTask] = useState<AgentTask | null>(null);
  const [capability, setCapability] = useState<CapabilityInfo | null>(null);
  const [showInstall, setShowInstall] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const base = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/orion-agent`;
  const token = session?.access_token ?? '';

  const agentConnected = useMemo(
    () => agents.some((a) => (a.status === 'online' || a.status === 'busy') && isFresh(a.last_seen)),
    [agents]
  );

  const loadTasks = useCallback(async () => {
    const { data } = await supabase
      .from('agent_tasks')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(20);
    setTasks((data ?? []) as AgentTask[]);
    setLoading(false);
  }, []);

  const loadAgents = useCallback(async () => {
    if (!token) {
      setAgents([]);
      return;
    }
    try {
      const res = await fetch(`${base}/agents`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return;
      const data = await res.json();
      setAgents((data.agents ?? []) as Agent[]);
    } catch {
      /* keep previous list */
    }
  }, [base, token]);

  useEffect(() => {
    loadTasks();
    loadAgents();
    const interval = setInterval(() => {
      loadTasks();
      loadAgents();
    }, 5000);
    return () => clearInterval(interval);
  }, [loadTasks, loadAgents]);

  const getCapabilities = async (tool: string): Promise<CapabilityInfo | null> => {
    if (!token) return null;
    try {
      const res = await fetch(`${base}/capabilities?tool=${encodeURIComponent(tool)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return null;
      return (await res.json()) as CapabilityInfo;
    } catch {
      return null;
    }
  };

  const submitTask = async (tool: string, target: string, kind: 'scan' | 'install') => {
    const res = await fetch(`${base}/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ tool, target, kind }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Failed to submit task');
    if (data.capabilities) setCapability(data.capabilities);
    setActiveTask(data.task as AgentTask);
    loadTasks();
    startPolling(data.task.id as string);
  };

  const startPolling = (taskId: string) => {
    const interval = setInterval(async () => {
      const { data } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('id', taskId)
        .maybeSingle();
      if (data) {
        setActiveTask(data as AgentTask);
        if (['completed', 'failed', 'cancelled'].includes(data.status)) {
          clearInterval(interval);
          setRunning(false);
          loadTasks();
          loadAgents();
        }
      }
    }, 2000);
    setTimeout(() => {
      clearInterval(interval);
      setRunning(false);
    }, 180000);
  };

  const handleRun = async () => {
    if (!command.trim() || running) return;
    if (!token) {
      setActionError('You must be signed in to dispatch agent tasks.');
      return;
    }
    setActionError(null);
    setRunning(true);
    try {
      const cap = await getCapabilities(selectedTool);
      if (cap && cap.in_registry && cap.missing && !cap.available) {
        setCapability(cap);
        setShowInstall(true);
        setRunning(false);
        return;
      }
      await submitTask(selectedTool, command.trim(), 'scan');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to dispatch task');
      setRunning(false);
    }
  };

  const handleInstall = async () => {
    setShowInstall(false);
    setRunning(true);
    setActionError(null);
    try {
      await submitTask(selectedTool, selectedTool, 'install');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to dispatch install task');
      setRunning(false);
    }
  };

  const handleContinueWithoutTool = async () => {
    setShowInstall(false);
    setRunning(true);
    setActionError(null);
    try {
      await submitTask(selectedTool, command.trim(), 'scan');
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to dispatch task');
      setRunning(false);
    }
  };

  const handleClear = async () => {
    await supabase.from('agent_tasks').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    setTasks([]);
  };

  const tool = TOOLS.find((t) => t.id === selectedTool);
  const recipeEntries = capability ? Object.entries(capability.recipes ?? {}) : [];

  return (
    <div className="space-y-6 fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <FlaskConical className="w-5 h-5 text-cyan-400" />
            Security Lab
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Real tool execution via registered Orvyn Agents — capabilities are reported, never assumed
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              loadTasks();
              loadAgents();
            }}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-white/[0.04] text-gray-300 border border-white/[0.06] hover:bg-white/[0.07] transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
          {tasks.length > 0 && (
            <button
              onClick={handleClear}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-all"
            >
              <Trash2 className="w-3.5 h-3.5" /> Clear History
            </button>
          )}
        </div>
      </div>

      {/* Agent status banner */}
      <div
        className={`glass-card p-4 flex items-center gap-3 ${
          agentConnected ? 'border-green-500/20' : 'border-amber-500/20'
        }`}
      >
        <div
          className={`w-10 h-10 rounded-lg flex items-center justify-center ${
            agentConnected ? 'bg-green-500/10' : 'bg-amber-500/10'
          }`}
        >
          {agentConnected ? (
            <Wifi className="w-5 h-5 text-green-400" />
          ) : (
            <Smartphone className="w-5 h-5 text-amber-400" />
          )}
        </div>
        <div className="flex-1">
          <div className={`text-sm font-medium ${agentConnected ? 'text-green-400' : 'text-amber-400'}`}>
            {agentConnected
              ? `${agents.filter((a) => isFresh(a.last_seen)).length} agent(s) connected`
              : 'No agent connected'}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">
            {agentConnected
              ? 'Tasks are matched to the tools each agent actually has'
              : 'Run the Orvyn agent on your device (see instructions below), signed in as your user so it can register.'}
          </div>
        </div>
      </div>

      {/* Agents panel */}
      {agents.length > 0 && (
        <div className="glass-card p-5">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" /> Registered Agents
          </h3>
          <div className="grid sm:grid-cols-2 gap-3">
            {agents.map((a) => {
              const installed = (a.tools ?? []).filter((t: AgentTool) => t.installed);
              return (
                <div key={a.id} className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isFresh(a.last_seen) && (a.status === 'online' || a.status === 'busy')
                          ? a.status === 'busy'
                            ? 'bg-blue-500 animate-pulse'
                            : 'bg-green-500'
                          : 'bg-gray-600'
                      }`}
                    />
                    <span className="text-sm font-medium text-gray-200">{a.name}</span>
                    <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-white/[0.05] text-gray-400">
                      {a.platform}
                    </span>
                    <span className="text-[10px] text-gray-600 ml-auto">
                      {a.last_seen ? new Date(a.last_seen).toLocaleTimeString() : 'never'}
                    </span>
                  </div>
                  <div className="text-[11px] text-gray-500 mt-1.5">
                    {a.os ?? 'unknown OS'} · {a.package_manager ?? 'n/a'} ·{' '}
                    {installed.length} tool{installed.length === 1 ? '' : 's'}
                  </div>
                  {installed.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {installed.map((t) => (
                        <span
                          key={t.name}
                          className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-mono"
                          title={t.version ? `${t.name} ${t.version}` : t.name}
                        >
                          {t.name}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Command panel */}
        <div className="glass-card p-5">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-green-400" />
            Command Terminal
          </h3>

          {/* Tool selector */}
          <div className="mb-4">
            <label className="block text-xs font-medium text-gray-500 mb-2">Select Tool</label>
            <div className="grid grid-cols-3 sm:grid-cols-4 gap-2">
              {TOOLS.filter((t) => t.available).map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setSelectedTool(t.id);
                    setCapability(null);
                  }}
                  className={`p-2 rounded-lg border text-xs font-medium transition-all flex flex-col items-center gap-1 ${
                    selectedTool === t.id
                      ? 'bg-blue-600/15 border-blue-500/30 text-blue-400'
                      : 'bg-white/[0.02] border-white/[0.04] text-gray-400 hover:text-gray-200'
                  }`}
                >
                  <t.icon className="w-4 h-4" style={{ color: t.color }} />
                  {t.name}
                </button>
              ))}
            </div>
          </div>

          {/* Command input */}
          <div className="mb-4">
            <label className="block text-xs font-medium text-gray-500 mb-2">
              Target (URL, IP, or hostname)
            </label>
            <div className="flex items-center gap-2 bg-[#0a0b14] border border-white/[0.06] rounded-lg px-3 py-2.5">
              <span className="text-xs font-mono text-green-400">{tool?.id}$</span>
              <input
                type="text"
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRun()}
                placeholder="example.com or 192.168.1.1"
                disabled={running}
                className="flex-1 bg-transparent text-sm font-mono focus:outline-none disabled:opacity-50"
              />
            </div>
          </div>

          {actionError && (
            <div className="mb-3 p-2 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-400">
              {actionError}
            </div>
          )}

          {/* Run button */}
          <button
            onClick={handleRun}
            disabled={running || !command.trim()}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white font-medium text-sm transition-colors"
          >
            {running ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> Waiting for agent…
              </>
            ) : (
              <>
                <Play className="w-4 h-4" /> Send to Agent
              </>
            )}
          </button>

          {/* Active task status */}
          {activeTask && (
            <div className="mt-4 fade-in">
              <div className="flex items-center gap-2 mb-2">
                <div
                  className={`w-2 h-2 rounded-full ${
                    activeTask.status === 'pending'
                      ? 'bg-amber-500'
                      : activeTask.status === 'running'
                      ? 'bg-blue-500 animate-pulse'
                      : activeTask.status === 'completed'
                      ? 'bg-green-500'
                      : activeTask.status === 'cancelled'
                      ? 'bg-gray-500'
                      : 'bg-red-500'
                  }`}
                />
                <span className="text-xs font-medium text-gray-400">
                  {activeTask.kind === 'install' ? 'Install' : 'Task'} {activeTask.status}
                  {activeTask.assigned_to ? ` (${activeTask.assigned_to})` : ''}
                </span>
                {activeTask.progress?.note && (
                  <span className="text-[11px] text-gray-600 truncate">
                    {activeTask.progress.note}
                  </span>
                )}
              </div>
              {activeTask.raw_output && (
                <div className="bg-[#06070d] border border-white/[0.06] rounded-lg p-4 max-h-64 overflow-y-auto">
                  <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap">
                    {activeTask.raw_output}
                  </pre>
                </div>
              )}
              {activeTask.error && (
                <div className="mt-2 p-2 bg-red-500/10 border border-red-500/20 rounded-lg text-xs text-red-400">
                  {activeTask.error}
                </div>
              )}
            </div>
          )}
        </div>

        {/* History panel */}
        <div className="glass-card p-5">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <Clock className="w-4 h-4 text-blue-400" />
            Task History
          </h3>

          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
            </div>
          ) : tasks.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Terminal className="w-10 h-10 text-gray-700 mb-3" />
              <p className="text-sm text-gray-400">No tasks yet</p>
              <p className="text-xs text-gray-600 mt-1">Send a command to the agent to see results</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {tasks.map((task) => {
                const t = TOOLS.find((tl) => tl.id === task.tool);
                return (
                  <div key={task.id} className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.04]">
                    <div className="flex items-center gap-2 mb-2">
                      {t && <t.icon className="w-3.5 h-3.5" style={{ color: t.color }} />}
                      <span className="text-xs font-medium text-gray-300">{t?.name ?? task.tool}</span>
                      {task.kind === 'install' && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          install
                        </span>
                      )}
                      <span
                        className={`text-xs px-1.5 py-0.5 rounded-full flex items-center gap-1 ${
                          task.status === 'completed'
                            ? 'bg-green-500/10 text-green-400'
                            : task.status === 'failed'
                            ? 'bg-red-500/10 text-red-400'
                            : task.status === 'running'
                            ? 'bg-blue-500/10 text-blue-400'
                            : task.status === 'cancelled'
                            ? 'bg-gray-500/10 text-gray-400'
                            : 'bg-amber-500/10 text-amber-400'
                        }`}
                      >
                        {task.status === 'completed' && <CheckCircle2 className="w-3 h-3" />}
                        {task.status === 'failed' && <XCircle className="w-3 h-3" />}
                        {task.status}
                      </span>
                      <span className="text-xs text-gray-600 ml-auto">
                        {new Date(task.created_at).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-xs font-mono text-gray-500 mb-1">
                      <span className="text-green-400">$</span> {task.target}
                    </div>
                    {task.raw_output && (
                      <div className="text-xs font-mono text-gray-400 bg-[#06070d] p-2 rounded mt-1 max-h-32 overflow-y-auto">
                        <pre className="whitespace-pre-wrap">{task.raw_output.slice(0, 2000)}</pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Agent setup instructions */}
      {!agentConnected && (
        <div className="glass-card p-5">
          <h3 className="font-semibold mb-3 flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" />
            How to Connect Your Orvyn Agent
          </h3>
          <div className="space-y-3 text-sm text-gray-400">
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">
                1. Install the agent (Termux / Kali / macOS / Windows)
              </p>
              <p className="text-xs text-gray-500">
                Termux from F-Droid (not the Play Store). The agent scripts ship in{' '}
                <span className="font-mono">termux-agent/</span>.
              </p>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">2. Configure the agent</p>
              <div className="bg-[#06070d] border border-white/[0.06] rounded-lg p-3 mt-1">
                <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap">{`# copy the example and fill in your project + a signed-in user:
#   ORION_SUPABASE_URL, ORION_ANON_KEY
#   ORION_USER_EMAIL, ORION_USER_PASSWORD   (required to register)
cp orion-config.sh.example orion-config.sh
$EDITOR orion-config.sh`}</pre>
              </div>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">3. Run the agent</p>
              <div className="bg-[#06070d] border border-white/[0.06] rounded-lg p-3 mt-1">
                <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap">{`chmod +x orion-agent.sh
./orion-agent.sh

# Windows:
powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1`}</pre>
              </div>
            </div>
            <div>
              <p className="text-xs text-gray-500">
                The agent discovers installed tools itself and reports them here. Missing tools can be
                installed with an approved recipe — never an arbitrary command.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Missing-tool dialog */}
      {showInstall && capability && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="glass-card max-w-lg w-full p-5 fade-in">
            <h3 className="font-semibold flex items-center gap-2 mb-2">
              <Wrench className="w-4 h-4 text-amber-400" />
              {selectedTool} is not available on any online agent
            </h3>
            <p className="text-xs text-gray-500 mb-4">
              {capability.online_agents.length === 0
                ? 'No agent is currently online. Install and start the Orvyn agent, then run the install action — or continue and the task will wait.'
                : `${capability.online_agents.length} agent(s) online, none reporting ${selectedTool}. You can ask an agent to install it using the approved recipe for its platform.`}
            </p>

            {recipeEntries.length > 0 && (
              <div className="mb-4">
                <p className="text-[11px] font-medium text-gray-500 mb-1.5">Approved install recipes</p>
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {recipeEntries.map(([platform, recipe]) => (
                    <div
                      key={platform}
                      className="p-2 rounded bg-[#06070d] border border-white/[0.06] text-[11px] font-mono"
                    >
                      <span className="text-purple-300">{platform}</span>
                      <span className="text-gray-600"> · </span>
                      <span className="text-gray-400 break-all">{recipe}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-end gap-2">
              <button
                onClick={() => setShowInstall(false)}
                className="text-sm px-4 py-2 rounded-lg bg-white/[0.04] border border-white/[0.06] text-gray-300 hover:bg-white/[0.07] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleContinueWithoutTool}
                className="text-sm px-4 py-2 rounded-lg bg-white/[0.04] border border-white/[0.06] text-gray-300 hover:bg-white/[0.07] transition-colors"
              >
                Continue without {selectedTool}
              </button>
              <button
                onClick={handleInstall}
                disabled={capability.online_agents.length === 0}
                className="flex items-center justify-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white font-medium transition-colors"
              >
                <Download className="w-4 h-4" /> Install via agent
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
