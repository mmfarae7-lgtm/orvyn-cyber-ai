import { useEffect, useState, useCallback } from 'react';
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
} from 'lucide-react';
import { supabase } from '@/lib/supabase';
import { TOOLS } from '@/lib/tools';

type AgentTask = {
  id: string;
  tool: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  raw_output: string | null;
  error: string | null;
  assigned_to: string | null;
  created_at: string;
  completed_at: string | null;
};

export default function Lab() {
  const [tasks, setTasks] = useState<AgentTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTool, setSelectedTool] = useState(TOOLS[0].id);
  const [command, setCommand] = useState('');
  const [running, setRunning] = useState(false);
  const [activeTask, setActiveTask] = useState<AgentTask | null>(null);
  const [agentConnected, setAgentConnected] = useState(false);

  const loadTasks = useCallback(async () => {
    const { data } = await supabase
      .from('agent_tasks')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(20);
    setTasks((data ?? []) as AgentTask[]);

    // Check if any task was recently picked up by an agent (within last 60s)
    const recent = (data ?? []).find(
      (t: AgentTask) =>
        (t.status === 'running' || t.status === 'completed') &&
        t.assigned_to &&
        Date.now() - new Date(t.created_at).getTime() < 120000
    );
    setAgentConnected(!!recent);
    setLoading(false);
  }, []);

  useEffect(() => {
    loadTasks();
    const interval = setInterval(loadTasks, 3000);
    return () => clearInterval(interval);
  }, [loadTasks]);

  const handleRun = async () => {
    if (!command.trim() || running) return;
    setRunning(true);
    setActiveTask(null);

    try {
      const apiUrl = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/orion-agent/submit`;
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`,
        },
        body: JSON.stringify({ tool: selectedTool, target: command.trim() }),
      });

      if (!response.ok) throw new Error('Failed to submit task');
      const data = await response.json();
      setActiveTask(data.task);
      loadTasks();

      // Poll for task completion
      const taskId = data.task.id;
      const pollTask = async () => {
        const { data: taskData } = await supabase
          .from('agent_tasks')
          .select('*')
          .eq('id', taskId)
          .maybeSingle();
        if (taskData) {
          setActiveTask(taskData as AgentTask);
          if (taskData.status === 'completed' || taskData.status === 'failed') {
            loadTasks();
            return true;
          }
        }
        return false;
      };

      const pollInterval = setInterval(async () => {
        const done = await pollTask();
        if (done) {
          clearInterval(pollInterval);
          setRunning(false);
        }
      }, 2000);

      // Timeout after 120s
      setTimeout(() => {
        clearInterval(pollInterval);
        setRunning(false);
      }, 120000);
    } catch {
      setActiveTask(null);
      setRunning(false);
    }
  };

  const handleClear = async () => {
    await supabase.from('agent_tasks').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    setTasks([]);
  };

  const tool = TOOLS.find((t) => t.id === selectedTool);

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
            Real tool execution via Termux/Kali agent
          </p>
        </div>
        {tasks.length > 0 && (
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-all"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear History
          </button>
        )}
      </div>

      {/* Agent status banner */}
      <div className={`glass-card p-4 flex items-center gap-3 ${agentConnected ? 'border-green-500/20' : 'border-amber-500/20'}`}>
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${agentConnected ? 'bg-green-500/10' : 'bg-amber-500/10'}`}>
          {agentConnected ? (
            <Wifi className="w-5 h-5 text-green-400" />
          ) : (
            <Smartphone className="w-5 h-5 text-amber-400" />
          )}
        </div>
        <div className="flex-1">
          <div className={`text-sm font-medium ${agentConnected ? 'text-green-400' : 'text-amber-400'}`}>
            {agentConnected ? 'Agent Connected' : 'No Agent Connected'}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">
            {agentConnected
              ? 'Tasks will be executed on your Termux/Kali device'
              : 'Run the Termux agent on your device to execute real scans. See instructions below.'}
          </div>
        </div>
      </div>

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
                  onClick={() => setSelectedTool(t.id)}
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

          {/* Run button */}
          <button
            onClick={handleRun}
            disabled={running || !command.trim()}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white font-medium text-sm transition-colors"
          >
            {running ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" /> Waiting for agent...
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
                <div className={`w-2 h-2 rounded-full ${
                  activeTask.status === 'pending' ? 'bg-amber-500' :
                  activeTask.status === 'running' ? 'bg-blue-500 animate-pulse' :
                  activeTask.status === 'completed' ? 'bg-green-500' : 'bg-red-500'
                }`} />
                <span className="text-xs font-medium text-gray-400">
                  Task {activeTask.status} {activeTask.assigned_to ? `(${activeTask.assigned_to})` : ''}
                </span>
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
                      <span
                        className={`text-xs px-1.5 py-0.5 rounded-full flex items-center gap-1 ${
                          task.status === 'completed'
                            ? 'bg-green-500/10 text-green-400'
                            : task.status === 'failed'
                            ? 'bg-red-500/10 text-red-400'
                            : task.status === 'running'
                            ? 'bg-blue-500/10 text-blue-400'
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
            How to Connect Your Termux/Kali Agent
          </h3>
          <div className="space-y-3 text-sm text-gray-400">
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">1. Install Termux on your Android device</p>
              <p className="text-xs text-gray-500">Download Termux from F-Droid (not Play Store — the Play Store version is outdated).</p>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">2. Install security tools</p>
              <div className="bg-[#06070d] border border-white/[0.06] rounded-lg p-3 mt-1">
                <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap">{`pkg update && pkg upgrade
pkg install nmap nikto whatweb curl jq git
pip install httpx-toolkit
npm install -g nuclei`}</pre>
              </div>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">3. Download and run the agent</p>
              <div className="bg-[#06070d] border border-white/[0.06] rounded-lg p-3 mt-1">
                <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap">{`# Download the agent script from this project:
# termux-agent/orion-agent.sh

chmod +x orion-agent.sh
./orion-agent.sh`}</pre>
              </div>
            </div>
            <div>
              <p className="text-xs font-medium text-gray-500 mb-1">4. Start scanning</p>
              <p className="text-xs text-gray-500">Once the agent is running, come back to this page and send commands. The agent will pick them up and run the real tools on your device.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
