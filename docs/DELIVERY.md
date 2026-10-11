# Orvyn Cyber — Delivery Report (Real Security Scanner & Agent Platform)

Status: **delivered and verified**. This document records what shipped, how it was
verified, and the honest limitations. It complements `docs/AUDIT.md` (the
before/after architecture audit).

## AUDIT SUMMARY (what this phase delivered)

The platform moved from a single-shot, client-driven "scan" endpoint to an
evidence-based, multi-stage assessment platform:

- A **Tool Registry** (`tool_registry`) is the single source of truth for every
  agent-executable tool: per-platform detect/version commands, approved install
  recipes, capabilities, supported phases, and risk level. 16 tools seeded.
- **Tool Discovery**: agents detect what is actually installed and report it;
  capability queries decide where a task can run.
- **Scan profiles**: `quick`, `standard`, `comprehensive`, `custom`, driving a
  15-phase orchestrator with explicit requested/skipped/partial states.
- **Honest port states**: 8 states (open, closed, filtered, timeout, unreachable,
  error, not_tested, unknown). A timeout is never reported as "closed".
- **Coverage tracking** with an explicit "NOT comprehensive" disclosure whenever
  anything was skipped or delegated.
- **Authorization model**: the scan wizard records the user's authorization
  assertion; rows carrying the column are rejected unless `confirmed === true`.
  Legacy rows (NULL authorization) keep working so old clients are not broken.
- **Installation assistant**: missing tools are installed by the agent using
  approved recipes fetched from the registry (never improvised locally).
- **Real-time UI**: live phase list, coverage panel, 8-state port table, cancel.
- **Real, verified scans** end-to-end against live targets.

### Compatibility guarantees
- Old APK / old clients keep working (legacy response shapes, legacy global poll
  queue, NULL-authorization scans accepted).
- Legacy `results.ports` array retained alongside `results.port_coverage`.
- Database upgrades are additive only.

## CHANGED

- Parsed port output now produces per-port states + coverage instead of a
  boolean open/closed list.
- Findings are stamped with tool/version/detection method/confidence, deduped in
  the correlation phase, and written **server-side** with idempotent inserts.
- Custom profiles previously crashed (`phaseSelection` was called without
  `options`); fixed and redeployed.
- Frontend scan flow is now a 4-step wizard (tool → target → profile → confirm).
- Agents (bash + Windows PowerShell) rewritten: registry discovery, optional
  login/JWT-refresh, registration, heartbeat, progress, cancel, install.

## FILES (this phase)

Key files:
- `supabase/migrations/20261008090000_platform_upgrade.sql` — 11 new tables
  (tool_registry, agents, scan_phases, scan_evidence, audit_log) + column
  extensions + 16 registry seeds.
- `supabase/migrations/20261008090100_vuln_dedupe.sql` — partial unique index
  `vulnerabilities(scan_id, title, coalesce(port,-1))` + duplicate collapse.
- `supabase/functions/_shared/scan-core.ts` — shared scan model (phases,
  coverage, port parsing, top ports, budgets).
- `supabase/functions/orion-scan/index.ts` — 15-phase orchestrator, authorization
  gate, delegation, idempotent findings writer.
- `supabase/functions/orion-agent/index.ts` — registry/agents/capabilities/
  register/heartbeat/submit/tasks/cancel/progress/result + legacy poll.
- `termux-agent/orion-agent.sh`, `termux-agent/orion-agent-windows.ps1` — agents.
- `termux-agent/orion-env.{sh,ps1}`, `orion-config.{sh,ps1}.example` — config.
- `src/lib/scanModel.ts` — frontend mirror of the server scan model.
- `src/lib/supabase.ts` — extended Scan/Vulnerability + Agent/RegistryTool/
  ScanPhase types.
- `src/pages/ScanLaunch.tsx` — wizard with profiles + authorization gate.
- `src/pages/Scans.tsx` — live phases, coverage, 8-state ports, cancel.
- `src/pages/Lab.tsx` — registered agents, capability preflight, install dialog.
- `src/pages/Guide.tsx` — profiles/coverage docs + new agent instructions.

## MIGRATIONS

Applied live to `ahkyfokibvnqkprxvkpf` (additive only):

1. `20261008090000_platform_upgrade.sql`
2. `20261008090100_vuln_dedupe.sql`

Both verified afterwards (tables/columns/index present; 16 registry rows).

## TEST RESULTS

- `tsc --noEmit`: pass.
- `eslint src`: 0 errors (one pre-existing AuthContext fast-refresh warning).
- `npm run build`: pass — `assets/index-HW7HqUQt.js` (399.64 kB).
- esbuild bundle of `orion-scan` and `orion-agent`: pass.
- Edge functions deployed: `orion-scan`, `orion-agent`.

## E2E (live, against the real project)

Platform E2E — **27/27 passed**:
- standard profile → completed; `results.port_coverage` present; every entry is
  one of the 8 states; counts include all 8; legacy `results.ports` kept.
- DB: scan `completed`, `coverage`/`progress` persisted, `scan_phases` and
  `scan_evidence` rows written.
- idempotent re-run of the same scan id → no duplicate findings.
- custom profile → port expression honored (3 ports), selected phases ran,
  unselected heavier phases explicitly skipped.
- authorization gate → unconfirmed scan rejected `403 authorization_required`.
- comprehensive without an agent → 65535 requested, 27 tested, 65508 not_tested,
  `comprehensive=false` (honest, no fake completion).

Agent protocol E2E — **23/23 passed**:
- registry lists tools; agent registers; `/agents` lists it; `/capabilities?tool=nmap`
  reports available.
- task dispatched, claimed via `/poll` (status running, assigned to agent),
  `/progress` accepted; `/result` merged nmap output into `results.port_coverage`
  (22/80/443 open) and updated the phase.
- `/cancel` sets status cancelled; a late `/result` is rejected `409`.
- install task dispatches, is claimed, and completes without a scan merge.

Site verification (both domains):
- `status.php` served, backend reported online.
- new bundle served; carries the authorization gate, the "NOT a comprehensive
  assessment" label, and the 8-state model (`waiting_agent`, `not_tested`).
- `downloads/` preserved.

APK:
- Built by CI (run `38125167773`, commit `790456d`), signed (`ORVYN.RSA`/`ORVYN.SF`).
- Embeds the **byte-identical** web bundle (sha256 `C8C2EBA5…`) to the live site.
- Published to three locations, all byte-identical
  (sha256 `ECBCFDC51FFD5D692E804E8D3AEAF1007D1853FFA4AA152014A339E361A82C4D`,
  824834 bytes):
  - GitHub Release `v1.0.0` asset `orvyn-cyber-v1.0.0.apk`
  - `https://orvyn.is-great.org/downloads/orvyn-cyber-v1.0.0.apk`
  - `https://orioncyberai.great-site.net/downloads/orvyn-cyber-v1.0.0.apk`

## LIMITATIONS (honest)

- A full 1–65535 sweep needs an online agent with `nmap`. Without one, the edge
  runtime probes only the first 1000 ports and reports the remainder as
  `not_tested` (never as closed).
- Some tools are intentionally `available: false` (OpenVAS, Wireshark) — the
  platform does not pretend to support them from the edge.
- `crt.sh` is occasionally unavailable (502) for Certificate Transparency; the
  scan records the failure instead of inventing a result.
- Windows install recipes depend on `winget`/`pip` being present.
- InfinityFree serves a JS challenge to non-browser clients, which only affects
  command-line health checks, not real browsers/APK.
- Rotate the InfinityFree FTP password and the GitHub PAT (both were exposed in
  chat). Supabase dashboard cleanup (delete stray orgs, rename the personal org)
  is still pending as a user action.
