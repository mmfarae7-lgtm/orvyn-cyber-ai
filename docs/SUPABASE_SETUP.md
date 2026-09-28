# Orvyn Cyber AI — Supabase setup

Everything in this repo targets a Supabase project. The project is **not**
hardcoded anywhere: the frontend reads it from `.env`, and the agent reads it
from `termux-agent/orion-config.sh`.

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
