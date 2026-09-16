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
} from 'lucide-react';
import { TOOLS } from '@/lib/tools';

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
          Go to the <b>New Scan</b> page, pick a security tool, enter your target (URL or IP), configure options, and launch.
        </Step>
        <Step num={3} title="Review Findings">
          After a scan completes, results appear in the <b>Vulnerabilities</b> page. Each finding includes severity, evidence, and remediation steps.
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
        <PageCard icon={Shield} title="New Scan" description="A step-by-step wizard to select a tool, enter a target, configure options, and launch a real scan." />
        <PageCard icon={FileWarning} title="Vulnerabilities" description="All findings from your scans, filterable by severity and searchable. Click any finding for full details." />
        <PageCard icon={MessageSquare} title="AI Assistant" description="Chat with the Orvyn Cyber AI about security topics. Your conversation history is saved across sessions." />
        <PageCard icon={FlaskConical} title="Lab" description="Run security tools interactively with custom commands. All sessions are saved for later review." />
      </Section>

      {/* Agents */}
      <Section icon={Terminal} title="Run Agents on Your Devices" color="cyan">
        <p className="text-sm text-gray-400 mb-4">
          The platform can run <b>real security tools</b> on your own devices. Install the
          <b> Orion Agent</b> on your phone (Termux) or computer (CMD) — it stays connected to your
          account and executes scans you launch from the web app. Download the agent files from the
          GitHub repository: <code>termux-agent/</code> folder.
        </p>

        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-white/[0.02] border border-white/[0.06]">
            <div className="flex items-center gap-2 mb-3">
              <Smartphone className="w-4 h-4 text-green-400" />
              <h3 className="text-sm font-medium">Phone — via Termux</h3>
            </div>
            <div className="space-y-1 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
              {`# 1. Install Termux from F-Droid, then open it and run:
pkg update && pkg upgrade

# 2. Install the required tools:
pkg install curl jq nmap nikto whatweb yara git

# 3. Copy the file "orion-agent.sh" to your phone
#    (from the GitHub repo folder: termux-agent/)

# 4. Make it executable and run:
chmod +x orion-agent.sh
./orion-agent.sh`}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              The agent will stay running, poll for new scans every 5 seconds, and execute them locally.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-white/[0.02] border border-white/[0.06]">
            <div className="flex items-center gap-2 mb-3">
              <Monitor className="w-4 h-4 text-blue-400" />
              <h3 className="text-sm font-medium">Laptop / PC — via CMD</h3>
            </div>
            <div className="space-y-1 text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
              {`# 1. Download the files to one folder:
#    orion-agent-windows.bat
#    orion-agent-windows.ps1

# 2. Install the security tools you want (see README),
#    e.g. Nmap from https://nmap.org/download.html

# 3. Open CMD in that folder and run:
orion-agent-windows.bat`}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Or PowerShell: <code>powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1</code>
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
              <b>Only scan targets you own or have explicit written permission to test.</b> Unauthorized scanning
              of systems you do not own is illegal in most jurisdictions.
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
