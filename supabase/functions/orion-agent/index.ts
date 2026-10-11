import { createClient } from 'npm:@supabase/supabase-js@2';
import type { SupabaseClient } from 'npm:@supabase/supabase-js@2';
import {
  parsePortToolOutput,
  parsePortExpression,
  computeCoverage,
  truncate,
  audit,
} from '../_shared/scan-core.ts';
import type { CoverageArea, PhaseState, PortEntry, PortCoverage } from '../_shared/scan-core.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

const json = (data: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });

/** Postgres text rejects NUL bytes; agent output can contain them. */
const clean = (s: string) => (s ?? '').replace(/\u0000/g, '');

interface RegistryRow {
  name: string;
  display_name: string;
  aliases: string[];
  platforms: string[];
  detect: Record<string, string>;
  version: Record<string, string>;
  version_regex: string;
  install: Record<string, string>;
  capabilities: string[];
  phases: string[];
  risk_level: string;
  max_runtime_seconds: number;
  url: string | null;
  enabled: boolean;
}

interface ToolInfo {
  name: string;
  installed: boolean;
  version?: string;
  path?: string;
  executable?: boolean;
  broken?: boolean;
}

interface AgentRow {
  id: string;
  user_id: string;
  agent_key: string;
  name: string;
  platform: string;
  status: string;
  tools: ToolInfo[];
  last_seen: string;
}

interface TaskRow {
  id: string;
  user_id: string;
  scan_id: string | null;
  tool: string;
  kind?: string;
  status: string;
  assigned_to: string | null;
  options: Record<string, string> | null;
}

/** Resolve the authenticated user; null means legacy anon-key client. */
async function identify(supabase: SupabaseClient, req: Request): Promise<string | null> {
  try {
    const token = (req.headers.get('Authorization') ?? '').replace('Bearer ', '');
    if (!token) return null;
    const { data } = await supabase.auth.getUser(token);
    return data.user?.id ?? null;
  } catch {
    return null;
  }
}

async function getRegistry(supabase: SupabaseClient): Promise<RegistryRow[]> {
  const { data } = await supabase.from('tool_registry').select('*').eq('enabled', true);
  return (data ?? []) as RegistryRow[];
}

function findRegistry(registry: RegistryRow[], tool: string): RegistryRow | null {
  return registry.find((r) => r.name === tool || (r.aliases ?? []).includes(tool)) ?? null;
}

/**
 * Capability check for task dispatch. Unknown capabilities stay permissive so
 * legacy agents (never registered) keep working exactly as before.
 */
function canRun(task: TaskRow, agent: AgentRow | null, registry: RegistryRow[]): boolean {
  const kind = task.kind ?? 'scan';
  if (kind === 'install') {
    const row = findRegistry(registry, task.tool);
    if (row && agent && !row.install?.[agent.platform]) return false; // no approved recipe on this platform
    return true;
  }
  if (kind !== 'scan') return true;
  if (!agent || !Array.isArray(agent.tools) || agent.tools.length === 0) return true;
  const row = findRegistry(registry, task.tool);
  if (!row) return true; // tool unknown to the registry — cannot verify, preserve legacy behavior
  const have = new Set(
    agent.tools.filter((t) => t.installed).map((t) => t.name)
  );
  if (have.has(row.name)) return true;
  for (const a of row.aliases ?? []) if (have.has(a)) return true;
  return false;
}

interface CapabilityInfo {
  tool: string;
  in_registry: boolean;
  registry: RegistryRow | null;
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
}

async function capabilityInfo(
  supabase: SupabaseClient,
  userId: string,
  tool: string
): Promise<CapabilityInfo> {
  const registry = await getRegistry(supabase);
  const row = findRegistry(registry, tool);
  const cutoff = new Date(Date.now() - 120_000).toISOString();
  const { data: agents } = await supabase
    .from('agents')
    .select('*')
    .eq('user_id', userId)
    .in('status', ['online', 'busy'])
    .gte('last_seen', cutoff);
  const online = (agents ?? []) as AgentRow[];
  const info: CapabilityInfo = {
    tool,
    in_registry: !!row,
    registry: row,
    recipes: row?.install ?? {},
    online_agents: [],
    available: false,
    missing: !!row,
  };
  for (const a of online) {
    const match = row
      ? a.tools?.find(
          (t) =>
            t.installed && (t.name === row.name || (row.aliases ?? []).includes(t.name))
        )
      : undefined;
    info.online_agents.push({
      agent_key: a.agent_key,
      name: a.name,
      platform: a.platform,
      status: a.status,
      last_seen: a.last_seen,
      has_tool: !!match,
      tool_version: match?.version ?? null,
    });
    if (match) info.available = true;
  }
  if (!row) info.missing = false; // not in registry → not tracked as missing
  return info;
}

// ---------------------------------------------------------------------------
// Result merging into scans (never overwrites server-side scan data)
// ---------------------------------------------------------------------------

function mergeAgentPortCoverage(
  existing: PortCoverage | null,
  raw: string,
  requestedExpr: string
): PortCoverage | null {
  const requested = parsePortExpression(requestedExpr) ?? [];
  const requestedCount = requested.length || 65535;
  const parsed = parsePortToolOutput(raw);
  const notShownClosed = raw.match(/Not shown:\s*([\d,]+)\s+closed ports/i);
  const notShownFiltered = raw.match(/Not shown:\s*([\d,]+)\s+filtered ports/i);
  const sawTable = /PORT\s+STATE\s+SERVICE/i.test(raw) || parsed.length > 0;

  if (!sawTable) return null; // tool produced no parseable port evidence

  const counts = { ...emptyCounts() };
  for (const e of parsed) counts[e.state] += 1;
  if (notShownClosed) counts.closed += parseInt(notShownClosed[1].replace(/,/g, ''), 10) || 0;
  if (notShownFiltered) counts.filtered += parseInt(notShownFiltered[1].replace(/,/g, ''), 10) || 0;
  const accounted = Object.values(counts).reduce((a, b) => a + b, 0);
  if (accounted < requestedCount) counts.unknown += requestedCount - accounted;

  // Entries: tool lines win; keep edge-run detail for ports the tool did not print.
  const byKey = new Map<string, PortEntry>();
  for (const e of existing?.entries ?? []) byKey.set(`${e.port}/${e.protocol}`, e);
  for (const e of parsed) byKey.set(`${e.port}/${e.protocol}`, e);
  const entries = [...byKey.values()].sort((a, b) => a.port - b.port);

  return {
    requested: { expr: requestedExpr, count: requestedCount },
    tested: requestedCount,
    not_tested: null,
    counts,
    entries,
    tool: 'nmap (agent full-range sweep)',
    delegated: null,
  };
}

function emptyCounts() {
  return {
    open: 0,
    closed: 0,
    filtered: 0,
    timeout: 0,
    unreachable: 0,
    error: 0,
    not_tested: 0,
    unknown: 0,
  } as Record<string, number>;
}

function parseNucleiOutput(raw: string): Array<{ severity: string; template: string; rest: string }> {
  const out: Array<{ severity: string; template: string; rest: string }> = [];
  for (const line of clean(raw).split('\n')) {
    const m = line.match(/^\[(critical|high|medium|low|info|unknown)\]\s+\[([^\]]+)\]\s+(.*)$/i);
    if (m) {
      const sev = m[1].toLowerCase();
      out.push({ severity: sev === 'unknown' ? 'medium' : sev, template: m[2], rest: m[3] });
    }
    if (out.length >= 200) break;
  }
  return out;
}

async function mergeIntoScan(
  supabase: SupabaseClient,
  task: TaskRow,
  status: string,
  raw: string,
  output: Record<string, unknown> | null,
  toolVersion: string | null,
  agentName: string
): Promise<void> {
  const scanId = task.scan_id;
  if (!scanId) return;
  const { data: scan } = await supabase.from('scans').select('*').eq('id', scanId).maybeSingle();
  if (!scan) return;

  const results: Record<string, unknown> =
    scan.results && typeof scan.results === 'object' ? { ...(scan.results as Record<string, unknown>) } : {};
  const phases: PhaseState[] = Array.isArray(results.phases)
    ? JSON.parse(JSON.stringify(results.phases as PhaseState[]))
    : [];
  const coverageKey = task.options?.coverage_phase ?? null;
  const rawClean = clean(truncate(raw ?? '', 120_000));

  // 1) raw evidence for this run
  try {
    await supabase.from('scan_evidence').insert({
      scan_id: scanId,
      user_id: task.user_id,
      phase: coverageKey === 'port_discovery' ? 4 : coverageKey === 'vulnerability_assessment' ? 10 : null,
      tool: task.tool,
      tool_version: toolVersion,
      command_profile: {
        source: 'agent',
        agent: agentName,
        task_id: task.id,
        kind: task.kind ?? 'scan',
        ports: task.options?.ports ?? null,
      },
      stdout: rawClean,
      exit_code: status === 'completed' ? 0 : 1,
    });
  } catch {
    /* evidence must never break result handling */
  }

  // 2) tool-specific merges
  let phaseNo: number | null = null;
  let phaseSummary = '';
  if (coverageKey === 'port_discovery' && ['nmap', 'masscan'].includes(task.tool)) {
    phaseNo = 4;
    if (status === 'completed') {
      const merged = mergeAgentPortCoverage(
        (results.port_coverage as PortCoverage) ?? null,
        rawClean,
        task.options?.ports ?? '1-65535'
      );
      if (merged) {
        results.port_coverage = merged;
        results.ports = merged.entries.map((e) => ({
          port: e.port,
          state: e.state,
          service: e.service ?? 'unknown',
          banner: e.banner ?? '',
          elapsed_ms: e.elapsed_ms ?? 0,
        }));
        const open = merged.counts.open ?? 0;
        phaseSummary = `Full-range sweep completed by agent "${agentName}" (${task.tool} ${toolVersion ?? ''} over ${task.options?.ports ?? '1-65535'}): ${open} open, ${merged.counts.closed} closed, ${merged.counts.filtered} filtered, ${merged.counts.unknown} unclassified`.trim();
      } else {
        phaseNo = 4;
        phaseSummary = `Agent ${task.tool} run finished but produced no parseable port output — see evidence`;
      }
    } else {
      phaseSummary = `Agent ${task.tool} run failed: ${clean(taskErrorOf(output, rawClean))}`;
    }
  } else if (coverageKey === 'vulnerability_assessment' && task.tool === 'nuclei') {
    phaseNo = 10;
    if (status === 'completed') {
      const hits = parseNucleiOutput(rawClean);
      if (hits.length > 0) {
        const mapped = hits.map((h) => ({
          scan_id: scanId,
          user_id: task.user_id,
          title: `[${h.template}] ${h.rest.split(' - ')[0].slice(0, 300)}`,
          severity: h.severity,
          description: h.rest.slice(0, 4000),
          evidence: `nuclei output line: [${h.severity}] [${h.template}] ${h.rest}`.slice(0, 4000),
          remediation: `Fix the condition reported by nuclei template "${h.template}" and re-run the template to confirm.`,
          cve: /^[cC][vV][eE]-\d{4}-\d+$/.test(h.template) ? h.template.toUpperCase() : null,
          port: null as number | null,
          service: null as string | null,
          confidence: 'confirmed',
          detection_method: 'nuclei_template',
          tool: 'nuclei',
          tool_version: toolVersion,
          detected_at: new Date().toISOString(),
          asset: typeof results.scope === 'object' && results.scope ? ((results.scope as { hostname?: string }).hostname ?? null) : null,
          protocol: null as string | null,
          refs: ['https://github.com/projectdiscovery/nuclei-templates'],
        }));

        // Idempotent: never re-insert a finding already stored for this scan
        // (agent retries / repeated results) and never insert the same
        // title+port twice in one batch — the DB has a partial unique index.
        const { data: existingRows } = await supabase
          .from('vulnerabilities')
          .select('title, port')
          .eq('scan_id', scanId);
        const stored = new Set(
          (existingRows ?? []).map(
            (r: { title: string; port: number | null }) => `${r.title}::${r.port ?? ''}`
          )
        );
        const seen = new Set<string>();
        const rows = mapped.filter((r) => {
          const k = `${r.title}::${r.port ?? ''}`;
          if (stored.has(k) || seen.has(k)) return false;
          seen.add(k);
          return true;
        });

        if (rows.length > 0) {
          const { error: insErr } = await supabase.from('vulnerabilities').insert(rows);
          if (insErr) {
            // fall back to a single finding row so nothing is silently lost
            await supabase.from('vulnerabilities').insert({
              scan_id: scanId,
              user_id: task.user_id,
              title: `nuclei reported ${hits.length} finding(s)`,
              severity: 'info',
              description: 'Bulk insert failed; raw output preserved in scan evidence.',
              evidence: rawClean.slice(0, 2000),
              remediation: 'Review the stored nuclei output in the evidence tab.',
              confidence: 'confirmed',
              detection_method: 'nuclei_template',
              tool: 'nuclei',
              tool_version: toolVersion,
              detected_at: new Date().toISOString(),
            });
          }
        }
      }
      phaseSummary = `Binary nuclei run completed by agent "${agentName}" (${hits.length} template hit(s) recorded)`;
    } else {
      phaseSummary = `Agent nuclei run failed: ${clean(taskErrorOf(output, rawClean))}`;
    }
  } else {
    phaseSummary = `Agent ${task.tool} ${status} (agent "${agentName}")`;
  }

  // 3) update the phase row (status + summary)
  if (phaseNo !== null) {
    const ph = phases.find((p) => p.phase === phaseNo);
    if (ph) {
      ph.status = status === 'completed' ? 'complete' : 'error';
      ph.summary = phaseSummary;
    }
    await supabase.from('scan_phases').upsert(
      {
        scan_id: scanId,
        user_id: task.user_id,
        phase: phaseNo,
        key: phKey(phaseNo),
        name: phName(phaseNo),
        status: status === 'completed' ? 'complete' : 'error',
        summary: phaseSummary,
        completed_at: new Date().toISOString(),
      },
      { onConflict: 'scan_id,phase' }
    );
  }

  // 4) agent run ledger
  const ledger = Array.isArray(results.agent_results)
    ? (results.agent_results as Array<Record<string, unknown>>)
    : [];
  ledger.push({
    task_id: task.id,
    tool: task.tool,
    tool_version: toolVersion,
    agent: agentName,
    status,
    completed_at: new Date().toISOString(),
    summary: (output && typeof output.summary === 'string' ? output.summary : null) as string | null,
  });
  results.agent_results = ledger;
  results.phases = phases;

  // 5) recompute coverage from updated phases
  const areas: CoverageArea[] = phases.map((p) => ({
    phase: p.phase,
    key: p.key,
    name: p.name,
    status: p.status as CoverageArea['status'],
    note: p.status === 'complete' ? undefined : p.summary,
  }));
  const coverage = computeCoverage(areas);
  results.coverage = coverage;
  results.limitations = coverage.limitations;

  // 6) scan status: done only when no other agent task is still pending/running
  const { count: remaining } = await supabase
    .from('agent_tasks')
    .select('id', { count: 'exact', head: true })
    .eq('scan_id', scanId)
    .in('status', ['pending', 'running']);
  const done = (remaining ?? 0) === 0;

  const patch: Record<string, unknown> = {
    results,
    coverage,
    status: scan.status === 'cancelled' ? 'cancelled' : done ? 'completed' : 'waiting_agent',
    progress: done
      ? { percent: 100, state: 'done', updated_at: new Date().toISOString() }
      : {
          percent: 90,
          state: 'waiting_agent',
          updated_at: new Date().toISOString(),
          remaining_tasks: remaining ?? 0,
        },
  };
  if (done) patch.completed_at = scan.completed_at ?? new Date().toISOString();
  await supabase.from('scans').update(patch).eq('id', scanId);

  await audit(supabase, task.user_id, 'agent_result_merged', {
    scan_id: scanId,
    task_id: task.id,
    tool: task.tool,
    status,
    phase: phaseNo,
    coverage_percent: coverage.percent,
  });
}

function taskErrorOf(output: Record<string, unknown> | null, raw: string): string {
  if (output && typeof output.error === 'string' && output.error) return output.error;
  const lines = raw.split('\n').filter(Boolean);
  return lines.slice(-3).join(' | ') || 'unknown error';
}

function phKey(phase: number): string {
  const map: Record<number, string> = {
    4: 'port_discovery',
    10: 'vulnerability_assessment',
  };
  return map[phase] ?? `phase_${phase}`;
}
function phName(phase: number): string {
  const map: Record<number, string> = {
    4: 'TCP Port Discovery',
    10: 'Vulnerability Assessment',
  };
  return map[phase] ?? `Phase ${phase}`;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  const url = new URL(req.url);
  const path = url.pathname.split('/').pop() ?? '';

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  );

  try {
    // GET /orion-agent/registry — tool registry (approved recipes only)
    if (req.method === 'GET' && path === 'registry') {
      const registry = await getRegistry(supabase);
      return json({ tools: registry });
    }

    // GET /orion-agent/agents — the caller's agents (user token required)
    if (req.method === 'GET' && path === 'agents') {
      const userId = await identify(supabase, req);
      if (!userId) return json({ error: 'Unauthorized' }, 401);
      const { data: agents } = await supabase
        .from('agents')
        .select('*')
        .eq('user_id', userId)
        .order('last_seen', { ascending: false })
        .limit(50);
      return json({ agents: agents ?? [] });
    }

    // GET /orion-agent/capabilities?tool=nmap — missing-tool preflight (user token)
    if (req.method === 'GET' && path === 'capabilities') {
      const userId = await identify(supabase, req);
      if (!userId) return json({ error: 'Unauthorized' }, 401);
      const tool = url.searchParams.get('tool') ?? '';
      if (!tool) return json({ error: 'tool query parameter required' }, 400);
      const info = await capabilityInfo(supabase, userId, tool);
      return json(info);
    }

    // POST /orion-agent/register — agent identity + discovery results (user token)
    if (req.method === 'POST' && path === 'register') {
      const userId = await identify(supabase, req);
      if (!userId) {
        return json(
          {
            error: 'Unauthorized',
            hint: 'Agent registration requires a signed-in user. Set ORION_USER_EMAIL / ORION_USER_PASSWORD in the agent config.',
          },
          401
        );
      }
      const body = await req.json();
      const agentKey: string = body.agentKey ?? body.agent_key ?? '';
      const platform: string = body.platform ?? '';
      if (!agentKey || !platform) return json({ error: 'agentKey and platform are required' }, 400);

      const tools: ToolInfo[] = Array.isArray(body.tools) ? body.tools : [];
      const payload = {
        user_id: userId,
        agent_key: agentKey,
        name: body.name?.slice(0, 120) || agentKey,
        platform: platform.slice(0, 40),
        os: body.os?.slice(0, 120) ?? null,
        architecture: body.architecture?.slice(0, 40) ?? null,
        agent_version: body.agentVersion?.slice(0, 40) ?? null,
        package_manager: body.packageManager?.slice(0, 40) ?? null,
        status: 'online',
        tools,
        capabilities: Array.isArray(body.capabilities) ? body.capabilities : [],
        last_seen: new Date().toISOString(),
      };

      const { data: existing } = await supabase
        .from('agents')
        .select('id')
        .eq('user_id', userId)
        .eq('agent_key', agentKey)
        .maybeSingle();

      let agent;
      if (existing) {
        const { data: updated } = await supabase
          .from('agents')
          .update(payload)
          .eq('id', existing.id)
          .select()
          .single();
        agent = updated;
      } else {
        const { data: created, error: insErr } = await supabase
          .from('agents')
          .insert(payload)
          .select()
          .single();
        if (insErr) return json({ error: insErr.message }, 500);
        agent = created;
      }

      await audit(supabase, userId, 'agent_registered', {
        agent_key: agentKey,
        platform: payload.platform,
        agent_version: payload.agent_version,
        tools_found: tools.filter((t) => t.installed).length,
        tools_total: tools.length,
      });
      return json({ agent });
    }

    // POST /orion-agent/heartbeat — liveness (+ optional refreshed tools)
    if (req.method === 'POST' && path === 'heartbeat') {
      const userId = await identify(supabase, req);
      if (!userId) return json({ error: 'Unauthorized' }, 401);
      const body = await req.json();
      const agentKey: string = body.agentKey ?? body.agent_key ?? '';
      if (!agentKey) return json({ error: 'agentKey required' }, 400);

      const patch: Record<string, unknown> = { last_seen: new Date().toISOString() };
      if (['online', 'offline', 'busy', 'error', 'needs_update'].includes(body.status)) {
        patch.status = body.status;
      }
      if (Array.isArray(body.tools)) patch.tools = body.tools;
      if (body.currentTask !== undefined) patch.current_task = body.currentTask ?? null;

      const { data: agent } = await supabase
        .from('agents')
        .update(patch)
        .eq('user_id', userId)
        .eq('agent_key', agentKey)
        .select()
        .maybeSingle();
      return json({ ok: true, agent: agent ?? null });
    }

    // GET /orion-agent/poll — claim next task (capability-aware for registered agents)
    if (req.method === 'GET' && path === 'poll') {
      const agentKey = url.searchParams.get('agent_key') ?? url.searchParams.get('agent_id') ?? 'default';
      const userId = await identify(supabase, req);

      if (userId) {
        const registry = await getRegistry(supabase);
        const { data: agent } = await supabase
          .from('agents')
          .select('*')
          .eq('user_id', userId)
          .eq('agent_key', agentKey)
          .maybeSingle();

        const { data: tasks } = await supabase
          .from('agent_tasks')
          .select('*')
          .eq('user_id', userId)
          .eq('status', 'pending')
          .order('created_at', { ascending: true })
          .limit(10);

        const candidate =
          (tasks ?? []).find((t) => canRun(t as TaskRow, (agent as AgentRow) ?? null, registry)) ?? null;

        if (candidate) {
          const { data: claimed } = await supabase
            .from('agent_tasks')
            .update({
              status: 'running',
              assigned_to: agentKey,
              started_at: new Date().toISOString(),
            })
            .eq('id', candidate.id)
            .eq('status', 'pending')
            .select()
            .maybeSingle();
          if (claimed) {
            if (agent) {
              await supabase
                .from('agents')
                .update({
                  last_seen: new Date().toISOString(),
                  status: 'busy',
                  current_task: claimed.id,
                })
                .eq('id', (agent as AgentRow).id);
            }
            await audit(supabase, userId, 'task_claimed', {
              task_id: claimed.id,
              tool: claimed.tool,
              kind: claimed.kind ?? 'scan',
              agent_key: agentKey,
            });
            return json({ task: claimed });
          }
        }

        if (agent) {
          await supabase
            .from('agents')
            .update({ last_seen: new Date().toISOString(), status: 'online', current_task: null })
            .eq('id', (agent as AgentRow).id);
        }
        return json({ task: null });
      }

      // Legacy anon-key mode: preserved exactly (any pending scan task; install
      // tasks are excluded because legacy agents cannot execute them).
      const { data: task } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('status', 'pending')
        .neq('kind', 'install')
        .order('created_at', { ascending: true })
        .limit(1)
        .maybeSingle();

      if (!task) return json({ task: null });

      await supabase
        .from('agent_tasks')
        .update({
          status: 'running',
          assigned_to: agentKey,
          started_at: new Date().toISOString(),
        })
        .eq('id', task.id);

      return json({ task });
    }

    // GET /orion-agent/status — task status (progress included)
    if (req.method === 'GET' && path === 'status') {
      const taskId = url.searchParams.get('task_id');
      if (!taskId) return json({ error: 'task_id required' }, 400);
      const { data: task } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('id', taskId)
        .maybeSingle();
      return json({ task });
    }

    // POST /orion-agent/progress — agent-side progress for a claimed task
    if (req.method === 'POST' && path === 'progress') {
      const body = await req.json();
      const { taskId, agentId, progress } = body;
      if (!taskId) return json({ error: 'taskId required' }, 400);
      const { data: task } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('id', taskId)
        .maybeSingle();
      if (!task) return json({ error: 'Task not found' }, 404);
      if (agentId && task.assigned_to && task.assigned_to !== agentId) {
        return json({ error: 'Not authorized to update this task' }, 403);
      }
      const patch: Record<string, unknown> = { progress: progress ?? {} };
      await supabase.from('agent_tasks').update(patch).eq('id', taskId);
      if (task.scan_id) {
        const { data: scan } = await supabase
          .from('scans')
          .select('progress')
          .eq('id', task.scan_id)
          .maybeSingle();
        await supabase
          .from('scans')
          .update({
            progress: {
              ...(scan?.progress ?? {}),
              agent: { task_id: taskId, tool: task.tool, ...(progress ?? {}), updated_at: new Date().toISOString() },
            },
          })
          .eq('id', task.scan_id);
      }
      return json({ success: true });
    }

    // POST /orion-agent/submit — create a task (user token; returns capability preflight)
    if (req.method === 'POST' && path === 'submit') {
      const userId = await identify(supabase, req);
      if (!userId) return json({ error: 'Unauthorized' }, 401);

      const body = await req.json();
      const { tool, target, options, scanId } = body;
      const kind: string = ['scan', 'install', 'probe'].includes(body.kind) ? body.kind : 'scan';

      if (!tool || !target) return json({ error: 'tool and target are required' }, 400);

      const { data: task, error } = await supabase
        .from('agent_tasks')
        .insert({
          user_id: userId,
          scan_id: scanId ?? null,
          tool,
          target,
          kind,
          options: options ?? {},
          status: 'pending',
        })
        .select()
        .single();

      if (error) return json({ error: error.message }, 500);

      await audit(supabase, userId, 'task_created', {
        task_id: task.id,
        tool,
        kind,
        scan_id: scanId ?? null,
      });

      const capabilities = await capabilityInfo(supabase, userId, tool).catch(() => null);
      return json({ task, capabilities });
    }

    // POST /orion-agent/result — agent submits a result (merged, never overwriting)
    if (req.method === 'POST' && path === 'result') {
      const body = await req.json();
      const { taskId, status, output, rawOutput, error: errText, agentId, toolVersion } = body;

      if (!taskId) return json({ error: 'taskId required' }, 400);

      const { data: existing } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('id', taskId)
        .maybeSingle();

      if (!existing) return json({ error: 'Task not found' }, 404);

      if (existing.status === 'cancelled') {
        return json({ error: 'Task was cancelled — result discarded', cancelled: true }, 409);
      }

      if (agentId && existing.assigned_to && existing.assigned_to !== agentId) {
        return json({ error: 'Not authorized to update this task' }, 403);
      }

      if (!existing.assigned_to && status !== 'failed') {
        return json({ error: 'Task has not been claimed by an agent' }, 409);
      }

      const finalStatus = status === 'failed' ? 'failed' : 'completed';
      const updateData: Record<string, unknown> = {
        status: finalStatus,
        completed_at: new Date().toISOString(),
      };
      if (output !== undefined) updateData.output = output ?? {};
      if (rawOutput !== undefined) updateData.raw_output = clean(truncate(String(rawOutput ?? ''), 400_000));
      if (errText) updateData.error = clean(String(errText)).slice(0, 4000);

      const { data: task, error: updateError } = await supabase
        .from('agent_tasks')
        .update(updateData)
        .eq('id', taskId)
        .select()
        .single();

      if (updateError) return json({ error: updateError.message }, 500);

      // free the agent
      await supabase
        .from('agents')
        .update({ status: 'online', current_task: null, last_seen: new Date().toISOString() })
        .eq('agent_key', existing.assigned_to);

      await audit(supabase, existing.user_id, existing.kind === 'install' ? 'tool_install_executed' : 'tool_executed', {
        task_id: taskId,
        tool: existing.tool,
        kind: existing.kind ?? 'scan',
        status: finalStatus,
        agent_key: existing.assigned_to,
        tool_version: toolVersion ?? null,
      });

      if (existing.kind === 'install') {
        // The agent re-registers itself with fresh discovery afterwards; nothing
        // to merge into a scan.
        return json({ success: true, task });
      }

      if (task.scan_id) {
        try {
          await mergeIntoScan(
            supabase,
            task as TaskRow,
            finalStatus,
            String(rawOutput ?? ''),
            (output as Record<string, unknown>) ?? null,
            toolVersion ?? null,
            existing.assigned_to ?? 'agent'
          );
        } catch (mergeErr) {
          // never fail the result submission because of a merge problem
          await audit(supabase, existing.user_id, 'agent_result_merge_error', {
            task_id: taskId,
            error: mergeErr instanceof Error ? mergeErr.message : 'unknown',
          });
        }
      }

      return json({ success: true, task });
    }

    // GET /orion-agent/tasks — list caller's tasks (user token)
    if (req.method === 'GET' && path === 'tasks') {
      const userId = await identify(supabase, req);
      if (!userId) return json({ error: 'Unauthorized' }, 401);
      const { data: tasks } = await supabase
        .from('agent_tasks')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(20);
      return json({ tasks: tasks ?? [] });
    }

    // POST /orion-agent/cancel — cancel a task and/or a scan's queued agent work
    if (req.method === 'POST' && path === 'cancel') {
      const userId = await identify(supabase, req);
      if (!userId) return json({ error: 'Unauthorized' }, 401);
      const body = await req.json();
      const { taskId, scanId } = body;

      if (taskId) {
        const { data: task } = await supabase
          .from('agent_tasks')
          .select('*')
          .eq('id', taskId)
          .eq('user_id', userId)
          .maybeSingle();
        if (!task) return json({ error: 'Task not found' }, 404);
        if (!['pending', 'running'].includes(task.status)) {
          return json({ error: `Task already ${task.status}` }, 409);
        }
        await supabase
          .from('agent_tasks')
          .update({ status: 'cancelled', completed_at: new Date().toISOString() })
          .eq('id', taskId);
        await audit(supabase, userId, 'task_cancelled', { task_id: taskId, tool: task.tool });
        const { data: updated } = await supabase
          .from('agent_tasks')
          .select('*')
          .eq('id', taskId)
          .maybeSingle();
        return json({ success: true, task: updated });
      }

      if (scanId) {
        const { data: scan } = await supabase
          .from('scans')
          .select('id, status')
          .eq('id', scanId)
          .eq('user_id', userId)
          .maybeSingle();
        if (!scan) return json({ error: 'Scan not found' }, 404);
        const { data: cancelledTasks } = await supabase
          .from('agent_tasks')
          .update({ status: 'cancelled', completed_at: new Date().toISOString() })
          .eq('scan_id', scanId)
          .in('status', ['pending', 'running'])
          .select('id');
        if (['pending', 'running', 'waiting_agent'].includes(scan.status)) {
          await supabase
            .from('scans')
            .update({
              status: 'cancelled',
              completed_at: new Date().toISOString(),
              progress: { percent: 0, state: 'cancelled', updated_at: new Date().toISOString() },
            })
            .eq('id', scanId);
        }
        await audit(supabase, userId, 'scan_cancelled_via_agent_api', {
          scan_id: scanId,
          tasks_cancelled: (cancelledTasks ?? []).length,
        });
        return json({ success: true, tasks_cancelled: (cancelledTasks ?? []).length });
      }

      return json({ error: 'taskId or scanId required' }, 400);
    }

    return json({ error: 'Unknown endpoint' }, 404);
  } catch (err) {
    return json({ error: err instanceof Error ? err.message : 'Unknown error' }, 500);
  }
});
