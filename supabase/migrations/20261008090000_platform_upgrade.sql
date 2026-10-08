/*
# Orvyn Cyber — platform upgrade (STEP 3+: tool registry, agents, phases, evidence)

ADDITIVE ONLY. No drops of existing tables, no data deletion, no re-created
migrations. Existing rows stay valid:

- scans.profile/target_type/authorization/progress/coverage are nullable, so
  legacy scans read as "not reported" in the UI.
- vulnerabilities.confidence is nullable: legacy findings show "unspecified"
  instead of a fabricated confidence.
- agent_tasks gains kind ('scan'|'install'|'probe') default 'scan' and the
  status CHECK gains 'cancelled'.

New tables:
  tool_registry  — single source of truth for agent-executable tools:
                   per-platform detect/version commands, approved install
                   recipes, capabilities, supported scan phases, risk level.
  agents         — agent identity, OS/arch/version, discovery results,
                   heartbeat (last_seen/status).
  scan_phases    — persisted state of each of the 15 scan phases.
  scan_evidence  — raw tool output (tool, command profile, exit code, ms).
  audit_log      — security-sensitive actions (never secrets).

Everything is RLS-enabled. tool_registry is read-only for clients (writes
happen through this migration / service role only).
*/

-- ============================================================
-- 1. tool_registry
-- ============================================================
CREATE TABLE IF NOT EXISTS tool_registry (
  name text PRIMARY KEY,
  display_name text NOT NULL,
  description text NOT NULL DEFAULT '',
  aliases text[] NOT NULL DEFAULT '{}',
  platforms text[] NOT NULL DEFAULT '{}',
  -- detect/version commands are keyed: "posix" and/or "windows".
  -- Command must exit 0 when the tool is available.
  detect jsonb NOT NULL DEFAULT '{}'::jsonb,
  version jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- POSIX ERE applied to version output; empty or no match => first line.
  version_regex text NOT NULL DEFAULT '',
  -- Approved install recipes per platform. Only these may ever be executed
  -- by an agent, and only after explicit user approval. Key absent => no
  -- automated recipe for that platform (manual install via `url`).
  install jsonb NOT NULL DEFAULT '{}'::jsonb,
  capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
  phases text[] NOT NULL DEFAULT '{}',
  risk_level text NOT NULL DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high')),
  max_runtime_seconds integer NOT NULL DEFAULT 300,
  url text,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tool_registry ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_registry" ON tool_registry;
CREATE POLICY "select_registry" ON tool_registry FOR SELECT
  TO authenticated USING (true);

-- ============================================================
-- 2. agents (identity + discovery + heartbeat)
-- ============================================================
CREATE TABLE IF NOT EXISTS agents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  -- agent-generated stable key (hostname-random), scoped per user so a key
  -- can never collide with or hijack another user's agent.
  agent_key text NOT NULL,
  name text NOT NULL DEFAULT 'Unnamed agent',
  platform text NOT NULL,
  os text,
  architecture text,
  agent_version text,
  package_manager text,
  status text NOT NULL DEFAULT 'online'
    CHECK (status IN ('online', 'offline', 'busy', 'error', 'needs_update')),
  -- discovery results: [{name, installed, version, path, executable, broken}]
  tools jsonb NOT NULL DEFAULT '[]'::jsonb,
  capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
  current_task uuid,
  last_seen timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, agent_key)
);

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_agents" ON agents;
CREATE POLICY "select_own_agents" ON agents FOR SELECT
  TO authenticated USING (user_id = auth.uid());
DROP POLICY IF EXISTS "insert_own_agents" ON agents;
CREATE POLICY "insert_own_agents" ON agents FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "update_own_agents" ON agents;
CREATE POLICY "update_own_agents" ON agents FOR UPDATE
  TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "delete_own_agents" ON agents;
CREATE POLICY "delete_own_agents" ON agents FOR DELETE
  TO authenticated USING (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(user_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status, last_seen);

-- ============================================================
-- 3. scan_phases (15-phase pipeline state)
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_phases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  phase integer NOT NULL CHECK (phase BETWEEN 1 AND 15),
  key text NOT NULL,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'complete', 'partial',
                      'unavailable', 'skipped', 'error')),
  summary text,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, phase)
);

ALTER TABLE scan_phases ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_phases" ON scan_phases;
CREATE POLICY "select_own_phases" ON scan_phases FOR SELECT
  TO authenticated USING (user_id = auth.uid());
DROP POLICY IF EXISTS "insert_own_phases" ON scan_phases;
CREATE POLICY "insert_own_phases" ON scan_phases FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "update_own_phases" ON scan_phases;
CREATE POLICY "update_own_phases" ON scan_phases FOR UPDATE
  TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "delete_own_phases" ON scan_phases;
CREATE POLICY "delete_own_phases" ON scan_phases FOR DELETE
  TO authenticated USING (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_scan_phases_scan ON scan_phases(scan_id);

-- ============================================================
-- 4. scan_evidence (raw tool output)
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  phase integer,
  tool text NOT NULL,
  tool_version text,
  -- structured description of what ran (never a shell string built from
  -- user input): e.g. {"kind":"tcp_connect","ports":"80,443"}
  command_profile jsonb NOT NULL DEFAULT '{}'::jsonb,
  exit_code integer,
  duration_ms integer,
  stdout text,
  stderr text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE scan_evidence ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_evidence" ON scan_evidence;
CREATE POLICY "select_own_evidence" ON scan_evidence FOR SELECT
  TO authenticated USING (user_id = auth.uid());
DROP POLICY IF EXISTS "insert_own_evidence" ON scan_evidence;
CREATE POLICY "insert_own_evidence" ON scan_evidence FOR INSERT
  TO authenticated WITH CHECK (user_id = auth.uid());
DROP POLICY IF EXISTS "delete_own_evidence" ON scan_evidence;
CREATE POLICY "delete_own_evidence" ON scan_evidence FOR DELETE
  TO authenticated USING (user_id = auth.uid());

CREATE INDEX IF NOT EXISTS idx_scan_evidence_scan ON scan_evidence(scan_id);

-- ============================================================
-- 5. audit_log (security-sensitive actions, no secrets)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  action text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_audit" ON audit_log;
CREATE POLICY "select_own_audit" ON audit_log FOR SELECT
  TO authenticated USING (user_id = auth.uid());
-- inserts happen through service role only (edge functions)

CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_log(user_id, created_at DESC);

-- ============================================================
-- 6. scans: profile, target type, authorization, progress, coverage
-- ============================================================
ALTER TABLE scans ADD COLUMN IF NOT EXISTS profile text;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS target_type text;
-- "authorization" is a reserved word in Postgres: quoted here; PostgREST /
-- supabase-js quote it automatically on their side too.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS "authorization" jsonb;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS coverage jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS agent_id uuid REFERENCES agents(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status, created_at DESC);

-- ============================================================
-- 7. vulnerabilities: evidence-based finding fields
-- ============================================================
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS confidence text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS detection_method text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS tool text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS tool_version text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS detected_at timestamptz;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS asset text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS protocol text;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS refs jsonb;

-- ============================================================
-- 8. agent_tasks: kind, progress, cancelled status
-- ============================================================
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'scan'
  CHECK (kind IN ('scan', 'install', 'probe'));
ALTER TABLE agent_tasks ADD COLUMN IF NOT EXISTS progress jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE agent_tasks DROP CONSTRAINT IF EXISTS agent_tasks_status_check;
ALTER TABLE agent_tasks ADD CONSTRAINT agent_tasks_status_check
  CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'));

-- ============================================================
-- 9. tool_registry seed — approved recipes only
--    detect/version commands exit 0 when the tool is available.
-- ============================================================
INSERT INTO tool_registry
  (name, display_name, description, aliases, platforms, detect, version,
   version_regex, install, capabilities, phases, risk_level,
   max_runtime_seconds, url)
VALUES
(
  'nmap', 'Nmap',
  'Network mapper: TCP connect/SYN port scanning, service and version detection',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v nmap", "windows": "if (Get-Command nmap -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "nmap --version", "windows": "nmap --version"}',
  'Nmap version ([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y nmap",
    "debian": "sudo apt-get install -y nmap",
    "kali": "sudo apt-get install -y nmap",
    "linux": "sudo apt-get install -y nmap",
    "macos": "brew install nmap",
    "windows": "winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements"}',
  '["host_discovery","port_scanning","service_detection","version_detection","banner_grabbing"]',
  ARRAY['host_discovery','port_scan','service_detection'],
  'medium', 3600, 'https://nmap.org'
),
(
  'masscan', 'Masscan',
  'TCP port scanner at very high rates for full-range sweeps',
  '{}',
  ARRAY['debian','kali','linux','macos','windows'],
  '{"posix": "command -v masscan", "windows": "if (Get-Command masscan -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "masscan --version", "windows": "masscan --version"}',
  '([0-9][0-9A-Za-z._-]*)',
  '{"debian": "sudo apt-get install -y masscan",
    "kali": "sudo apt-get install -y masscan",
    "linux": "sudo apt-get install -y masscan",
    "macos": "brew install masscan"}',
  '["port_scanning","full_range_sweep","high_rate_scanning"]',
  ARRAY['port_scan'],
  'medium', 1800, 'https://github.com/robertdavidgraham/masscan'
),
(
  'nuclei', 'Nuclei',
  'Template-based vulnerability scanner (ProjectDiscovery)',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v nuclei", "windows": "if (Get-Command nuclei -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "nuclei -version", "windows": "nuclei -version"}',
  'Nuclei ([0-9][0-9A-Za-z._-]*)',
  '{"debian": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "kali": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "linux": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "macos": "brew install projectdiscovery/tap/nuclei",
    "windows": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}',
  '["template_scanning","cve_detection","misconfiguration_detection"]',
  ARRAY['vulnerability_assessment'],
  'low', 1800, 'https://github.com/projectdiscovery/nuclei'
),
(
  'nikto', 'Nikto',
  'Web server scanner: dangerous files, outdated software, misconfigurations',
  '{}',
  ARRAY['termux','debian','kali','linux','macos'],
  '{"posix": "command -v nikto"}',
  '{"posix": "nikto -Version"}',
  'Nikto ([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y nikto",
    "debian": "sudo apt-get install -y nikto",
    "kali": "sudo apt-get install -y nikto",
    "linux": "sudo apt-get install -y nikto",
    "macos": "brew install nikto"}',
  '["web_server_audit","dangerous_file_detection","outdated_software_detection"]',
  ARRAY['web_audit','vulnerability_assessment'],
  'medium', 900, 'https://github.com/sullo/nikto'
),
(
  'whatweb', 'WhatWeb',
  'Web technology fingerprinting: CMS, frameworks, components',
  '{}',
  ARRAY['termux','debian','kali','linux','macos'],
  '{"posix": "command -v whatweb"}',
  '{"posix": "whatweb --version"}',
  'WhatWeb ([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y whatweb",
    "debian": "sudo apt-get install -y whatweb",
    "kali": "sudo apt-get install -y whatweb",
    "linux": "sudo apt-get install -y whatweb",
    "macos": "brew install whatweb"}',
  '["technology_fingerprinting","cms_detection","framework_identification"]',
  ARRAY['technology_identification'],
  'low', 300, 'https://github.com/urbanadventurer/WhatWeb'
),
(
  'httpx', 'httpx',
  'Fast HTTP probing: status codes, titles, technology detection',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v httpx", "windows": "if (Get-Command httpx -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "httpx -version", "windows": "httpx -version"}',
  'httpx v?([0-9][0-9A-Za-z._-]*)',
  '{"debian": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "kali": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "linux": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "macos": "brew install projectdiscovery/tap/httpx",
    "windows": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"}',
  '["http_probing","status_detection","title_extraction","tech_detect"]',
  ARRAY['http_analysis'],
  'low', 300, 'https://github.com/projectdiscovery/httpx'
),
(
  'trivy', 'Trivy',
  'Scanner for vulnerable dependencies in containers, repos and served assets',
  '{}',
  ARRAY['debian','kali','linux','macos','windows'],
  '{"posix": "command -v trivy", "windows": "if (Get-Command trivy -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "trivy --version", "windows": "trivy --version"}',
  'Version: ([0-9][0-9A-Za-z._-]*)',
  '{"macos": "brew install trivy",
    "windows": "winget install --id AquaSecurity.Trivy -e --accept-source-agreements --accept-package-agreements"}',
  '["dependency_scanning","cve_detection","misconfiguration_detection"]',
  ARRAY['vulnerability_assessment','dependency_analysis'],
  'low', 900, 'https://github.com/aquasecurity/trivy'
),
(
  'semgrep', 'Semgrep',
  'Static analysis (SAST) for source code patterns',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v semgrep", "windows": "if (Get-Command semgrep -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "semgrep --version", "windows": "semgrep --version"}',
  '([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pip install semgrep",
    "debian": "pip install semgrep",
    "kali": "pip install semgrep",
    "linux": "pip install semgrep",
    "macos": "pip3 install semgrep",
    "windows": "pip install semgrep"}',
  '["sast","pattern_detection","code_analysis"]',
  ARRAY['code_analysis'],
  'low', 900, 'https://semgrep.dev'
),
(
  'gitleaks', 'Gitleaks',
  'Secret detection in repositories and served files',
  '{}',
  ARRAY['debian','kali','linux','macos','windows'],
  '{"posix": "command -v gitleaks", "windows": "if (Get-Command gitleaks -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "gitleaks version", "windows": "gitleaks version"}',
  '([0-9][0-9A-Za-z._-]*)',
  '{"debian": "sudo apt-get install -y gitleaks",
    "kali": "sudo apt-get install -y gitleaks",
    "linux": "sudo apt-get install -y gitleaks",
    "macos": "brew install gitleaks",
    "windows": "winget install --id Gitleaks.Gitleaks -e --accept-source-agreements --accept-package-agreements"}',
  '["secret_detection","credential_detection","token_leak_detection"]',
  ARRAY['secret_detection'],
  'low', 600, 'https://github.com/gitleaks/gitleaks'
),
(
  'yara', 'YARA',
  'Pattern matching for malware and indicator detection',
  '{}',
  ARRAY['termux','debian','kali','linux','macos'],
  '{"posix": "command -v yara"}',
  '{"posix": "yara --version"}',
  '([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y yara",
    "debian": "sudo apt-get install -y yara",
    "kali": "sudo apt-get install -y yara",
    "linux": "sudo apt-get install -y yara",
    "macos": "brew install yara"}',
  '["pattern_matching","malware_indicator_detection"]',
  ARRAY['threat_detection'],
  'low', 300, 'https://virustotal.github.io/yara/'
),
(
  'dns', 'DNS Tools (dig/nslookup)',
  'DNS record lookups via dig or nslookup',
  ARRAY['dig'],
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v dig || command -v nslookup",
    "windows": "if ((Get-Command dig -ErrorAction SilentlyContinue) -or (Get-Command nslookup -ErrorAction SilentlyContinue)) { exit 0 } else { exit 1 }"}',
  '{"posix": "dig -v", "windows": ""}',
  'DiG ([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y dnsutils",
    "debian": "sudo apt-get install -y dnsutils",
    "kali": "sudo apt-get install -y dnsutils",
    "linux": "sudo apt-get install -y dnsutils",
    "macos": "brew install bind"}',
  '["dns_lookup","record_enumeration"]',
  ARRAY['dns_analysis'],
  'low', 120, 'https://bind9.readthedocs.io/'
),
(
  'curl', 'curl',
  'HTTP client for requests, headers, redirects and response analysis',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v curl", "windows": "if (Get-Command curl.exe -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "curl --version", "windows": "curl.exe --version"}',
  'curl ([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y curl",
    "debian": "sudo apt-get install -y curl",
    "kali": "sudo apt-get install -y curl",
    "linux": "sudo apt-get install -y curl",
    "macos": "brew install curl"}',
  '["http_requests","header_analysis","redirect_analysis"]',
  ARRAY['http_analysis'],
  'low', 120, 'https://curl.se'
),
(
  'openssl', 'OpenSSL',
  'TLS/SSL toolkit: handshakes, certificate and cipher inspection',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v openssl", "windows": "if (Get-Command openssl -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "openssl version", "windows": "openssl version"}',
  'OpenSSL ([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y openssl",
    "debian": "sudo apt-get install -y openssl",
    "kali": "sudo apt-get install -y openssl",
    "linux": "sudo apt-get install -y openssl"}',
  '["tls_handshake","certificate_inspection","cipher_enumeration"]',
  ARRAY['tls_analysis'],
  'low', 120, 'https://www.openssl.org'
),
(
  'sslyze', 'SSLyze',
  'TLS configuration analyzer: protocols, ciphers, certificate chain',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v sslyze", "windows": "if (Get-Command sslyze -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"}',
  '{"posix": "sslyze --version", "windows": "sslyze --version"}',
  'sslyze v?([0-9][0-9A-Za-z._-]*)',
  '{"termux": "pip install sslyze",
    "debian": "pip install sslyze",
    "kali": "pip install sslyze",
    "linux": "pip install sslyze",
    "macos": "pip3 install sslyze",
    "windows": "pip install sslyze"}',
  '["tls_analysis","protocol_testing","certificate_validation"]',
  ARRAY['tls_analysis'],
  'low', 300, 'https://github.com/nabla-c0d3/sslyze'
),
(
  'traceroute', 'Traceroute',
  'Network path analysis to the target',
  '{}',
  ARRAY['termux','debian','kali','linux','macos','windows'],
  '{"posix": "command -v traceroute || command -v tracert",
    "windows": "if ((Get-Command tracert -ErrorAction SilentlyContinue) -or (Get-Command traceroute -ErrorAction SilentlyContinue)) { exit 0 } else { exit 1 }"}',
  '{"posix": "traceroute -V", "windows": ""}',
  '([0-9]+\.[0-9][0-9A-Za-z._-]*)',
  '{"termux": "pkg install -y traceroute",
    "debian": "sudo apt-get install -y traceroute",
    "kali": "sudo apt-get install -y traceroute",
    "linux": "sudo apt-get install -y traceroute"}',
  '["network_path_analysis","hop_enumeration"]',
  ARRAY['network_path'],
  'low', 300, 'https://linux.die.net/man/8/traceroute'
),
(
  'lynis', 'Lynis',
  'Host security auditing for the local system (compliance, hardening)',
  '{}',
  ARRAY['debian','kali','linux','macos'],
  '{"posix": "command -v lynis"}',
  '{"posix": "lynis --version"}',
  'lynis ([0-9][0-9A-Za-z._-]*)',
  '{"debian": "sudo apt-get install -y lynis",
    "kali": "sudo apt-get install -y lynis",
    "linux": "sudo apt-get install -y lynis",
    "macos": "brew install lynis"}',
  '["host_audit","hardening_checks","compliance_checks"]',
  ARRAY['host_audit'],
  'low', 600, 'https://cisofy.com/lynis/'
)
ON CONFLICT (name) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  description = EXCLUDED.description,
  aliases = EXCLUDED.aliases,
  platforms = EXCLUDED.platforms,
  detect = EXCLUDED.detect,
  version = EXCLUDED.version,
  version_regex = EXCLUDED.version_regex,
  install = EXCLUDED.install,
  capabilities = EXCLUDED.capabilities,
  phases = EXCLUDED.phases,
  risk_level = EXCLUDED.risk_level,
  max_runtime_seconds = EXCLUDED.max_runtime_seconds,
  url = EXCLUDED.url;
