# Orvyn Cyber — Architecture Audit & Migration Plan

Written before the modular scanner upgrade (STEP 1–2 of the implementation
order). Everything below was verified by reading the code in this repo, not
from assumptions. Line counts are as of commit `58971ad`.

---

## CURRENT ARCHITECTURE

```text
BROWSER / APK (WebView)                 AGENT DEVICES
───────────────────────                 ─────────────
React 19 + Vite SPA (src/)              termux-agent/orion-agent.sh      (bash, 478 lines)
  pages: Dashboard, ScanLaunch,         termux-agent/orion-agent-windows.ps1 (292 lines)
  Scans, Vulnerabilities, Chat,         termux-agent/orion-env.ps1/.sh  (config resolver)
  Lab, Guide, Auth
  PWA (manifest, sw.js)                         │ polls POST /orion-agent/poll every 5 s
        │ Bearer user token                     │ executes hardcoded tool commands
        ▼                                       ▼ POST /orion-agent/result (raw text)
┌────────────────────── Supabase project ahkyfokibvnqkprxvkpf (ap-southeast-1) ─────────────────────┐
│  Edge functions (Deno, verify_jwt=false):                                                         │
│    orion-scan   — server-side scan engine, one synchronous invocation (~7–16 s)                   │
│    orion-agent  — task queue: poll / status / submit / result / tasks (211 lines)                 │
│    orion-lab    — legacy duplicate of orion-scan checks; NOT called by the frontend               │
│    orion-chat   — AI chat assistant                                                                │
│  Postgres (RLS on): profiles, scans, vulnerabilities, chat_messages, lab_sessions, agent_tasks    │
│  Auth: email/password, mailer_autoconfirm=true                                                    │
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
        │                                     │
        ▼                                     ▼
InfinityFree static hosting            GitHub Actions (APK signed, release v1.0.0)
(2 domains, FTP deploy)
```

- Configuration is **not** hardcoded: frontend reads `.env`, agents read
  `orion-config.sh` / `orion-config.ps1` via `orion-env.*`.
- `src/pages/ScanLaunch.tsx` creates the `scans` row, calls `orion-scan`
  directly, then **inserts the returned findings client-side**.
- `src/pages/Scans.tsx` renders stored `scans.results` (Scan History).
- `src/pages/Lab.tsx` submits agent tasks and shows `agent_tasks` with a 3 s poll.

## CURRENT SCANNER

`supabase/functions/orion-scan/index.ts` (~1 230 lines), a single
synchronous request that runs inline steps:

1. SSRF guard + target normalization.
2. TCP connect probes via `Deno.connect` against `options.ports ?? TOP_PORTS`
   — **TOP_PORTS is 27 ports**.
3. DNS over DoH (`dns.google`): A/AAAA/CNAME/MX/NS/TXT/SOA/CAA + SPF/DMARC/DS.
4. Certificate data from crt.sh (1 retry; service currently 502 → honest
   "no data after retries").
5. HTTP checks: status/redirect/title/server/security headers/cookies,
   plus pattern checks for the named tools (nuclei/zap/nikto/whatweb/httpx/
   trivy/semgrep/gitleaks/yara) implemented **inside the engine** — no binary
   is executed.
6. Writes `scans.results`, returns `{ success, scanId, vulnerabilities, results }`.

Port states produced: **`open | closed | timeout | unchecked`** (4 values).

**Why it stays at 27 ports:** a 65 535-port connect scan from a Deno edge
function would take far beyond the platform request timeout, so the engine
defaults to 27 common ports and only scans more if `options.ports` is set —
but nothing in the UI lets the user choose a port scope, and there is no
explicit "requested / tested / not tested" coverage structure.

There are **no scan profiles, no persisted phases, no progress, no
cancellation, no agent involvement** in this path. Findings are inserted by
the browser, so an insert failure is silent.

`orion-lab/index.ts` (445 lines) re-implements weaker versions of the same
checks and returns a table labelled "Nmap" containing only `open/filtered`
rows — misleading output that looks fabricated even though it isn't.

## CURRENT AGENT

Both agents (`orion-agent.sh`, `orion-agent-windows.ps1`):

- Detect platform locally (termux/debian/kali/macos/linux; Windows) — **for
  display only, never reported to the backend**.
- Check tool presence with `command -v` at startup for a local table — **no
  versions, not sent anywhere**.
- Poll `/orion-agent/poll` every 5 s; the server hands out **any** pending
  task regardless of whether this agent has the required tool.
- Execute hardcoded per-tool command lines (e.g. `nmap -sT -p- --open -T4` =
  full 65 535-port scan with no time bound) and POST raw stdout as text.
- No registration, no heartbeat, no capability report, no progress events,
  no cancellation handling, no structured output parsing, no install flow.
- `orion-agent` endpoint `result` **overwrites** `scans.results` wholesale
  when `scan_id` is set — an agent result would destroy the server-side
  scan phases/evidence stored there.

Security/auth gaps found:

- `/poll` has no authentication; `/result` checks only `assigned_to`.
- `src/pages/Lab.tsx` submits tasks with the **anon key** as Bearer, but
  `submit` resolves the token via `auth.getUser()` → **401; the Lab
  "Send to Agent" button cannot work today**.

## CURRENT TOOLS

- `src/lib/tools.ts`: 16 static entries (13 `available: true`, 3 false).
  `available` is a hardcoded flag, not discovery.
- ScanLaunch's "Configure Scan Options" step renders a free-text input **per
  capability string** (`"TCP connect() scan": …`) and sends those keys
  verbatim as `options`; the backend only understands `options.ports`, so
  user input there is meaningless.
- Tool recipes exist only as comments in the bash agent; the Windows agent
  has different comments. No central registry, no install approval flow.

## CURRENT DATABASE

6 tables (all RLS enabled, per-user policies): `profiles`, `scans`,
`vulnerabilities`, `chat_messages`, `lab_sessions`, `agent_tasks`.

- `scans`: target, tool, status (pending/running/completed/failed), options,
  results — **no profile, authorization, coverage, or progress columns**.
- `vulnerabilities`: title, severity, description, evidence, remediation,
  cve, port, service — **no confidence, tool, tool version, detection
  method, timestamp, or references**.
- `agent_tasks`: tool, target, options, status, output, raw_output, error,
  assigned_to — **no task kind, no progress, no 'cancelled' status**.
- Missing entirely: tool registry, agent registry/capabilities, scan phases,
  scan evidence.

## CURRENT LIMITATIONS

1. 27 ports by default; no UI port scope; no requested/tested/not-tested
   coverage report (§11 of the master prompt).
2. Port states limited to 4; no `FILTERED/UNREACHABLE/ERROR/NOT_TESTED/
   UNKNOWN` (§12). (`timeout` is not converted to `closed` — that part is
   already correct and must be preserved.)
3. No scan profiles (quick/standard/comprehensive/custom) (§9).
4. No phase pipeline, no persisted progress, therefore no real-time UI
   state (§10, §21, §22).
5. No cancellation (§23).
6. Agent capabilities unknown to the server → tasks can be claimed by an
   agent that lacks the tool (§6, §20).
7. No tool registry; install hints duplicated in comments only (§8, §7).
8. No missing-tool UX; `available` flags are hardcoded (§20).
9. Findings lack confidence/tool/version/timestamp/evidence-source fields
   (§17, §18).
10. Findings are inserted by the browser, not the backend.
11. `orion-lab` returns misleading "Nmap"-labelled output; duplicates work.
12. Lab task submission is broken (anon key vs. user-token check).
13. ScanLaunch "options" step collects meaningless free text.
14. `orion-agent/result` overwrites `scans.results` (data loss).
15. `/poll` unauthenticated; no heartbeat/agent identity (§28, §29).
16. Authorization is a text warning only — no recorded approval (§3, §25).
17. No audit log of security-sensitive actions (§26).
18. No raw-tool-output model (tool, command profile, exit code, timing) (§32).

---

## PROPOSED ARCHITECTURE

```text
                    ORVYN WEB APP
                          │  profile + authorization + real-time phase polling
                          ▼
                 ORVYN CONTROL API (orion-scan as orchestrator)
                   │  phases 1–15, coverage tracker, evidence writer
                   │  scans.progress / scan_phases / scan_evidence
        ┌──────────┴───────────┐
        ▼ server-executable    ▼ agent-required phases
   engine probes          ORVYN AGENT (orion-agent task queue, capability-aware)
   (connect, DoH,            │  tool discovery → agents.tools / heartbeat
    HTTP, TLS)               │  structured args, install recipes from registry
        │                    ▼
        │              Nmap / Curl / OpenSSL / Dig / …
        └──────────────► RESULT PROCESSOR (correlate, dedupe, risk)
                              ▼
                    findings + coverage + honest report
```

New/changed pieces:

| Piece | Change |
|---|---|
| `tool_registry` table | Single source of truth: platforms, detect/version commands, install recipes, capabilities, risk, phases. Seeded by migration. |
| `agents` table | Identity + heartbeat + last_seen + tools jsonb (discovery results). |
| `scan_phases`, `scan_evidence` tables | Persisted phase state and raw tool output (tool, command profile, exit code, ms, truncated stdout/stderr). |
| `scans` extra columns | `profile`, `target_type`, `authorization` (jsonb), `progress` (jsonb), `coverage` (jsonb), `agent_id`. |
| `vulnerabilities` extra columns | `confidence`, `detection_method`, `tool`, `tool_version`, `detected_at`, `references`, `protocol`. |
| `orion-scan` | Orchestrates 15 phases, writes `scan_phases` + `scan_evidence`, computes coverage, configurable port scope, 8 port states, inserts findings server-side, supports profiles, returns progress state. |
| `orion-agent` | `register`/`heartbeat` (capabilities), `registry`, capability-aware `poll`, `progress` endpoint, `cancel`, authenticated result with **merge** (never overwrite) into `scans.results`. |
| bash/ps1 agents | OS/arch/version discovery from registry, capability reporting, structured argv execution (no shell interpolation of targets), phase-by-phase runs for comprehensive profile, install-approval tasks restricted to registry recipes, heartbeat + progress. |
| Frontend | Profile picker + real options (port scope), required authorization checkbox, coverage panel, real-time phase progress polled from DB, Agents/Tools view with install approval, missing-capability dialog with Install / Continue / Cancel. |

## MIGRATION PLAN

One **additive** migration (`20261008…_platform_upgrade.sql`):

- `CREATE TABLE tool_registry`, `agents`, `scan_phases`, `scan_evidence`
  (all with RLS; registry/agents readable by the owning user).
- `ALTER TABLE scans ADD COLUMN` profile/target_type/authorization/progress/
  coverage/agent_id — defaults keep existing rows valid.
- `ALTER TABLE vulnerabilities ADD COLUMN` confidence/tool/tool_version/
  detection_method/detected_at/references/protocol — nullable or defaulted.
- `ALTER TABLE agent_tasks ADD COLUMN` kind ('scan'|'install'|'probe') and
  extend status CHECK with `'cancelled'`.
- Seed `tool_registry` from the current recipes (one row per tool).
- **No drops, no data deletion, no re-created migrations.** Existing scans
  and findings remain readable (old rows: profile = legacy, coverage = null
  → UI shows "not reported").

Deploy order: migration → edge functions (CLI deploy) → agents (user pulls
scripts) → frontend build/deploy → APK CI. Each step is independently
revertible; the frontend tolerates null coverage/progress so it can ship
before or after the backend.

---