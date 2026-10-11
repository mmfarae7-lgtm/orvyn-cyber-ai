import {
  BookOpen,
  Rocket,
  Shield,
  MessageSquare,
  FlaskConical,
  FileWarning,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  ShieldCheck,
  Smartphone,
  Monitor,
  Terminal,
  Layers,
} from 'lucide-react';
import { TOOLS } from '@/lib/tools';
import { PROFILES, PORT_STATES, PORT_STATE_LABEL } from '@/lib/scanModel';

export default function Guide() {
  return (
    <div className="max-w-3xl mx-auto space-y-6 fade-in">
      {/* Header */}
      <div className="glass-card p-6">
          <h1 className="text-lg font-semibold flex items-center gap-2 mb-1">
            <BookOpen className="w-5 h-5 text-blue-400" />
            How Orvyn Cyber Works
          </h1>
          <p className="text-gray-500 text-sm">
            A complete guide to using the platform — from launching your first scan to analyzing vulnerabilities
          </p>
        </div>

      {/* Getting Started */}
      <Section icon={Rocket} title="Getting Started" color="blue">
        <Step num={1} title="Create an Account">
          Sign up with your email and password. Your profile is created automatically — no email confirmation needed.
        </Step>
        <Step num={2} title="Launch a Scan">
          Go to the <b>New Scan</b> page, pick a security tool, enter your target (URL or IP), choose a
          <b> scan profile</b>, and confirm you are authorized to test the target. The authorization you
          assert is recorded with the scan.
        </Step>
        <Step num={3} title="Review Findings">
          After a scan completes, the <b>Scan History</b> page shows live phases, coverage, and the raw
          evidence — port states, banners, DNS records, and TLS data — while the <b>Vulnerabilities</b>{' '}
          page lists each finding with severity, evidence, and remediation steps. Coverage is reported
          honestly: a scan is only labelled comprehensive when nothing was skipped.
        </Step>
        <Step num={4} title="Use the AI Assistant">
          The <b>AI Assistant</b> answers questions about security concepts, tools, and best practices. Your conversation is saved.
        </Step>
        <Step num={5} title="Experiment in the Lab">
          The <b>Lab</b> lets you run security tools interactively with custom commands and see real output.
        </Step>
      </Section>

      {/* Pages Overview */}
      <Section icon={BookOpen} title="Pages Overview" color="cyan">
        <PageCard icon={Rocket} title="Dashboard" description="Your home base — see scan stats, vulnerability breakdown, tool availability, and recent activity at a glance." />
        <PageCard icon={Shield} title="New Scan" description="A step-by-step wizard to select a tool, enter a target, choose a scan profile, record your authorization, and launch a real scan." />
        <PageCard icon={FileWarning} title="Vulnerabilities" description="All findings from your scans, filterable by severity and searchable. Click any finding for full details." />
        <PageCard icon={MessageSquare} title="AI Assistant" description="Chat with the Orvyn Cyber AI about security topics. Your conversation history is saved across sessions." />
        <PageCard icon={FlaskConical} title="Lab" description="Dispatch real tool runs to registered Orvyn Agents on your devices. If a tool is missing, the agent can install it with an approved recipe." />
      </Section>

      {/* Profiles & Coverage */}
      <Section icon={Layers} title="Scan Profiles & Honest Coverage" color="blue">
        <p className="text-sm text-gray-400 mb-4">
          A profile decides which phases run and how many ports get probed. The platform never claims
          more than it actually did — a scan is only marked <b>comprehensive</b> when every requested
          capability area completed without limitations.
        </p>
        <div className="space-y-2 mb-4">
          {PROFILES.map((p) => (
            <div key={p.id} className="p-3 rounded-lg bg-white/[0.02] border border-white/[0.06]">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-medium">{p.name}</span>
                <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-white/[0.05] text-gray-500">
                  {p.tagline}
                </span>
                {p.needsAgent && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 ml-auto">
                    agent needed for full sweep
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-500 mt-1.5">{p.description}</p>
            </div>
          ))}
        </div>
        <p className="text-xs font-medium text-gray-500 mb-2">
          Port states are reported exactly as observed — eight states, never collapsed
        </p>
        <div className="flex flex-wrap gap-1.5 mb-4">
          {PORT_STATES.map((s) => (
            <span
              key={s}
              className="text-[11px] px-2 py-0.5 rounded border border-white/[0.08] bg-white/[0.03] text-gray-400"
            >
              {PORT_STATE_LABEL[s]}
            </span>
          ))}
        </div>
        <div className="flex items-start gap-2 p-3 bg-amber-500/[0.06] border border-amber-500/20 rounded-lg">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-amber-300/90">
            A state is <b>never</b> converted: a timeout stays a timeout, never "closed". Ports the edge
            runtime could not probe are reported as <b>not tested</b> with a reason — and results are
            labelled <b>NOT comprehensive</b> whenever anything was skipped or unavailable.
          </p>
        </div>
      </Section>

      {/* Agents */}
      <Section icon={Terminal} title="Run Agents on Your Devices" color="cyan">
        <p className="text-sm text-gray-400 mb-4">
          The platform runs <b>real security tools</b> on your own devices. Install the <b>Orvyn Agent</b>{' '}
          on your phone (Termux), laptop (Kali / macOS) or Windows PC. The agent discovers which tools are
          actually installed, reports them to your account, and executes the scans you launch from the web app.
        </p>

        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-white/[0.02] border border-white/[0.06]">
            <div className="flex items-center gap-2 mb-3">
              <Smartphone className="w-4 h-4 text-green-400" />
              <h3 className="text-sm font-medium">Phone — via Termux (F-Droid, not the Play Store)</h3>
            </div>
            <div className="space-y-1 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
              {`# 1. Install base packages
pkg update && pkg upgrade
pkg install curl jq git

# 2. Copy termux-agent/ from the repo, then configure:
cp orion-config.sh.example orion-config.sh
$EDITOR orion-config.sh   # project URL + anon key + your login

# 3. Run the agent
chmod +x orion-agent.sh
./orion-agent.sh`}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              The agent reports its installed tools and keeps a heartbeat. Missing tools can be installed
              from the Lab using an approved recipe for that platform.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-white/[0.02] border border-white/[0.06]">
            <div className="flex items-center gap-2 mb-3">
              <Monitor className="w-4 h-4 text-blue-400" />
              <h3 className="text-sm font-medium">Laptop / PC — Linux, macOS or Windows</h3>
            </div>
            <div className="space-y-1 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
              {`# Configure first:
cp orion-config.sh.example  orion-config.sh     # Linux / macOS
cp orion-config.ps1.example orion-config.ps1    # Windows

# Run (Linux / macOS):
chmod +x orion-agent.sh && ./orion-agent.sh

# Run (Windows PowerShell):
powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1`}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Registered agents appear in the <b>Lab</b> with the exact tools each one has, so tasks are
              only dispatched where they can actually run.
            </p>
          </div>
        </div>
      </Section>

      {/* Tools */}
      <Section icon={ShieldCheck} title="Available Security Tools" color="green">
        <div className="grid sm:grid-cols-2 gap-3">
          {TOOLS.map((tool) => (
            <div
              key={tool.id}
              className={`p-3 rounded-lg border ${
                tool.available
                  ? 'bg-white/[0.02] border-white/[0.06]'
                  : 'bg-yellow-500/[0.03] border-yellow-500/15'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                <tool.icon className="w-4 h-4" style={{ color: tool.color }} />
                <span className="text-sm font-medium">{tool.name}</span>
                {tool.available ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-500 ml-auto" />
                ) : (
                  <AlertTriangle className="w-3.5 h-3.5 text-yellow-500/60 ml-auto" />
                )}
              </div>
              <p className="text-xs text-gray-500">{tool.description}</p>
              <div className="flex flex-wrap gap-1 mt-2">
                {tool.capabilities.map((cap) => (
                  <span key={cap} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.04] text-gray-500">
                    {cap}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Safety */}
      <Section icon={AlertTriangle} title="Important Safety Notice" color="yellow">
        <div className="space-y-3">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-gray-300">
              <b>Only scan targets you own or have explicit written permission to test.</b> The New Scan
              wizard asks you to confirm this, and records your authorization assertion with the scan.
              Unauthorized scanning of systems you do not own is illegal in most jurisdictions.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <Lightbulb className="w-4 h-4 text-yellow-500 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-gray-300">
              Good practice: start with reconnaissance tools (WhatWeb, httpx, DNS) before running aggressive
              scans (Nuclei, ZAP). Understand what each tool does before using it.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <ShieldCheck className="w-4 h-4 text-yellow-500 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-gray-300">
              Tools marked as <b>not installed</b> will show a notification on the dashboard. You can still use
              all available tools — the unavailable ones are listed so you know what the platform supports.
            </p>
          </div>
        </div>
      </Section>

      {/* Tips */}
      <Section icon={Lightbulb} title="Tips for Effective Scanning" color="blue">
        <ul className="space-y-2 text-sm text-gray-300">
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Start with DNS and HTTP probing to map your target before deep scanning
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Use Nmap for port discovery, then Nuclei for known vulnerability templates
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Run SSLyze on any HTTPS targets to check for weak TLS configurations
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            Use the AI Assistant to understand any vulnerability you find — ask about remediation
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
            The Lab is great for quick one-off checks without setting up a full scan
          </li>
        </ul>
      </Section>
    </div>
  );
}

function Section({
  icon: Icon,
  title,
  color,
  children,
}: {
  icon: typeof BookOpen;
  title: string;
  color: 'blue' | 'cyan' | 'green' | 'yellow';
  children: React.ReactNode;
}) {
  const colors = {
    blue: 'text-blue-400',
    cyan: 'text-cyan-400',
    green: 'text-green-400',
    yellow: 'text-yellow-400',
  };
  return (
    <div className="glass-card p-5">
      <h2 className="font-semibold mb-4 flex items-center gap-2">
        <Icon className={`w-5 h-5 ${colors[color]}`} />
        {title}
      </h2>
      {children}
    </div>
  );
}

function Step({ num, title, children }: { num: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3 mb-4 last:mb-0">
      <div className="w-7 h-7 rounded-full bg-blue-600/15 text-blue-400 flex items-center justify-center text-sm font-bold flex-shrink-0">
        {num}
      </div>
      <div>
        <h3 className="text-sm font-medium mb-1">{title}</h3>
        <p className="text-sm text-gray-400">{children}</p>
      </div>
    </div>
  );
}

function PageCard({ icon: Icon, title, description }: { icon: typeof Rocket; title: string; description: string }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-white/[0.02] mb-2">
      <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center flex-shrink-0">
        <Icon className="w-4 h-4 text-blue-400" />
      </div>
      <div>
        <h3 className="text-sm font-medium">{title}</h3>
        <p className="text-xs text-gray-500 mt-0.5">{description}</p>
      </div>
    </div>
  );
}
