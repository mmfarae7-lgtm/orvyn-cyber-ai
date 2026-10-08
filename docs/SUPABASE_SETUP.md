# Orvyn Cyber AI — Supabase setup

Everything in this repo targets a Supabase project. The project is **not**
hardcoded anywhere: the frontend reads it from `.env`, and the agent reads it
from `termux-agent/orion-config.sh`.

## Current deployment

Verified against the Supabase Management API:

| Item | Value |
|------|-------|
| Project | `Orion cyber AI` |
| Ref | `ahkyfokibvnqkprxvkpf` |
| Organization | `Orion Org` (`sybgzvvvlqdiepytpzwh`) |
| Region | `ap-southeast-1` |
| Status | `ACTIVE_HEALTHY` |

Database and functions are already live and in sync with this repo:

- All 5 migrations in `supabase/migrations/` are applied
  (`20260903184007` → `20260903210047`).
- Tables `profiles`, `scans`, `vulnerabilities`, `chat_messages`,
  `lab_sessions`, `agent_tasks` all exist with RLS enabled and per-user
  policies (3–4 policies each).
- Edge functions `orion-scan`, `orion-chat`, `orion-lab`, `orion-agent`
  are all `ACTIVE` with `verify_jwt = false`.
- Function secrets (`SUPABASE_URL`, `SUPABASE_ANON_KEY`,
  `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_DB_URL`, …) are set.
- Auth config: `mailer_autoconfirm = true` (set 2026-10-08 via
  `PATCH /v1/projects/{ref}/config/auth`). The built-in email provider
  allows only **2 emails/hour per project**, so confirmation emails made
  signups fail with `over_email_send_rate_limit`. With auto-confirm,
  `signup` returns a session immediately and no email is sent.
  Verified end-to-end: signup → signin with no manual confirm → user row
  has `email_confirmed_at` set → test user deleted.

So for normal use you only need `.env` with the project URL and anon key.

### End-to-end connectivity verified (2026-10-08)

A temporary test account was exercised against the live project, then removed
(`DELETE` of the scan/task rows and the `auth.users` row, confirmed gone):

| Step | Result |
|------|--------|
| `POST /auth/v1/signup` | `200`, user created |
| Email confirmation (`UPDATE auth.users SET email_confirmed_at`) | ok |
| `POST /auth/v1/token?grant_type=password` | session obtained |
| `POST /rest/v1/profiles` (RLS) | created/touched only own row |
| `POST /rest/v1/scans` (RLS) | row created with `status: pending` |
| `POST /functions/v1/orion-scan` (headers) | `200 {"success":true,...}` |
| `POST /functions/v1/orion-agent/submit` | task created (`status: pending`) |
| `GET /functions/v1/orion-agent/poll` | `200 {"task":null}` (anon) |
| `GET /functions/v1/orion-agent/tasks` (anon) | `401` (correctly guarded) |

The remaining "one-time" dashboard items are documented in the next section.

### Organizations on this account

| Name | Id | Projects |
|------|----|----------|
| Orion Org | `sybgzvvvlqdiepytpzwh` | 1 (the live one) |
| Awriq | `asntsultucigueqsdrup` | 0 (empty) |

Two limits are worth knowing before you plan a second project:

1. **Renaming an organization is not available in the Management API.** The
   spec exposes only `GET` and `POST` on `/v1/organizations` — no `PATCH`,
   `PUT`, or `DELETE`. Renaming must be done in the dashboard
   (Organization Settings → rename).
2. **The account is at the Free plan's 2 active project limit**, so
   `POST /v1/projects` returns HTTP 400. Creating another project needs the
   existing one paused or deleted, or the organization upgraded.

## 1. Create the organization

In the Supabase Dashboard: **Organization Settings → New organization**, and
name it `oryvn cyber`.

Each organization has its own subscription. On the Free plan you get 2
projects per account, so an empty organization is fine.

## 2. Create the project

**New project** → pick the `oryvn cyber` organization → generate a strong
database password and save it (it cannot be recovered).

Copy the two values from **Project Settings → API**:

- `Project URL` → `https://<project-ref>.supabase.co`
- `Project anon key` → the `anon` / public key

## 3. Point the frontend at it

```bash
cp .env.example .env
```

```bash
VITE_SUPABASE_URL=https://<project-ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<anon-key>
VITE_ADMIN_EMAILS=you@example.com
```

The anon key is designed to be public and is protected by Row Level Security.
Never put the `service_role` key in `.env` or in any `VITE_` variable — those
are compiled into the browser bundle and would hand out full database access.

## 4. Apply the schema

```bash
npm install -g supabase
supabase login
supabase link --project-ref <project-ref>
supabase db push
```

This applies the five migrations in `supabase/migrations/`, which create
`profiles`, `scans`, `vulnerabilities`, `chat_messages`, `lab_sessions` and
`agent_tasks`, each with Row Level Security enabled and per-user policies.

## 5. Deploy the edge functions

```bash
supabase functions deploy orion-scan  --no-verify-jwt
supabase functions deploy orion-chat  --no-verify-jwt
supabase functions deploy orion-lab   --no-verify-jwt
supabase functions deploy orion-agent --no-verify-jwt
```

`--no-verify-jwt` matches `supabase/config.toml`. The functions authenticate
the caller themselves by validating the bearer token and checking row
ownership, which is required because the agent polls with the anon key rather
than a user session.

## 6. Point the agent at it

**Termux / Linux / macOS**

```bash
cd termux-agent
cp orion-config.sh.example orion-config.sh
$EDITOR orion-config.sh
chmod +x orion-agent.sh
./orion-agent.sh
```

**Windows**

```powershell
cd termux-agent
copy orion-config.ps1.example orion-config.ps1
notepad orion-config.ps1
powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1
```

Both agents print the `Backend:` line they resolved. If configuration is
missing they exit with instructions instead of polling an unknown project.

## 7. Build and deploy

```bash
npm run build              # static bundle in dist/
npm run build:android      # same, synced into android/app/src/main/assets/www
./scripts/build-infinityfree.sh   # bundle + status page in deploy/infinityfree/htdocs
```

## Where each piece can run

| Piece | Needs | Notes |
|-------|-------|-------|
| Frontend (`dist/`) | Any static host | Works on InfinityFree, Netlify, Vercel, GitHub Pages |
| Edge Functions | Supabase only | Deno runtime; will not run on shared PHP hosting |
| Postgres + Auth + REST | Supabase only | Same |
| Agent | Device with the tools | Termux, Linux, Windows, macOS |
| `status.php` | PHP 8 | Optional; InfinityFree is fine for this |

InfinityFree provides PHP 8.4 + MySQL on shared hosting, with no Node.js,
Docker, or long-running processes. It can host the **static frontend** and the
PHP status page, but it cannot host the Supabase backend. The browser talks to
Supabase directly, so no server-side proxy is required.

## Real scanning engine (orion-scan)

`supabase/functions/orion-scan/index.ts` performs **live network checks**, not
simulated results. What each tool actually does server-side:

| Tool | Real mechanism |
|------|----------------|
| nmap / masscan | Raw TCP `connect()` probes (27 common ports, or `options.ports`), banner grab, HTTP probe for web ports. States: open / closed / timeout / unchecked. Verified against independent local tests (9/9 match on scanme.nmap.org + orvyn.is-great.org). |
| dns | DNS-over-HTTPS (dns.google): A/AAAA/CNAME/MX/NS/TXT/SOA/CAA + SPF/DMARC/CAA/DNSSEC analysis |
| sslyze | Real TLS handshake + latency, HSTS policy analysis, HTTP→HTTPS redirect check, certificate issuer/expiry from crt.sh (Certificate Transparency, one retry) |
| httpx | Live probes of both schemes: status, redirect target, latency, real `<title>`, server header |
| nuclei | Live fetches: security headers, `.git/config` + `.env` content-validated, directory listing, admin paths with soft-404 detection |
| nikto | Dangerous files with **content validation** (ZIP magic, SQL keywords, phpinfo markers) — no SPA false positives |
| zap | Cookie flag audit (Secure/HttpOnly/SameSite), mixed content, CSRF heuristics, version disclosure |
| trivy / semgrep / gitleaks / yara | Pattern analysis of assets the target actually serves (HTML + up to 5 external scripts). Gitleaks also decodes JWTs to flag exposed `service_role` keys. Scope is stated in every result as an `info` finding; container/repo/file scans run on the Termux/Windows agent. |

Safety: an SSRF guard resolves the target (DoH) and refuses private/loopback/
link-local addresses before any probe.

The frontend **Scan History** page (`src/pages/Scans.tsx`) renders the raw
`scans.results` payload: port table with banners/timings, DNS records, TLS
evidence, probes, and the check log.
