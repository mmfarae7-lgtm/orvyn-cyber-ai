import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

interface ScanRequest {
  scanId: string;
  tool: string;
  target: string;
  options: Record<string, string>;
}

interface VulnerabilityFinding {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  evidence: string;
  remediation: string;
  cve?: string;
  port?: number;
  service?: string;
}

type ProbeState = 'open' | 'closed' | 'timeout' | 'unchecked';

interface ProbeResult {
  state: ProbeState;
  banner?: string;
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { scanId, tool, target, options } = (await req.json()) as ScanRequest;

    if (!target || !tool) {
      return new Response(
        JSON.stringify({ error: 'Target and tool are required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    );

    const authHeader = req.headers.get('Authorization') ?? '';
    const token = authHeader.replace('Bearer ', '');
    const { data: userData } = await supabase.auth.getUser(token);
    const userId = userData.user?.id;

    if (!userId) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const { data: scanRow } = await supabase
      .from('scans')
      .select('id')
      .eq('id', scanId)
      .eq('user_id', userId)
      .maybeSingle();

    if (!scanRow) {
      return new Response(
        JSON.stringify({ error: 'Scan not found or not owned by user' }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    await supabase.from('scans').update({
      status: 'running',
      started_at: new Date().toISOString(),
    }).eq('id', scanId);

    const vulnerabilities: VulnerabilityFinding[] = [];
    const scanResults: Record<string, unknown> = {
      tool,
      target,
      timestamp: new Date().toISOString(),
    };

    const url = target.startsWith('http') ? target : `https://${target}`;
    const hostname = target.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];

    try {
      // SSRF guard: refuse to scan private / loopback / link-local addresses.
      const guard = await isPrivateHostname(hostname);
      if (guard) {
        throw new Error(`SSRF protection blocked scan of private address: ${hostname} (${guard})`);
      }

      if (tool === 'nmap') {
        const r = await performNmapScan(hostname, options);
        scanResults.ports = r.ports;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'masscan') {
        const r = await performMasscanScan(hostname, options);
        scanResults.ports = r.ports;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'nuclei') {
        const r = await performNucleiScan(url, hostname, options);
        scanResults.findings = r.findings;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'zap') {
        const r = await performZapScan(url, options);
        scanResults.findings = r.findings;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'nikto') {
        const r = await performNiktoScan(url, options);
        scanResults.findings = r.findings;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'whatweb') {
        const r = await performWhatwebScan(url);
        scanResults.technologies = r.technologies;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'httpx') {
        const r = await performHttpxScan(url, hostname);
        scanResults.probes = r.probes;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'dns') {
        const r = await performDnsScan(hostname);
        scanResults.records = r.records;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'sslyze') {
        const r = await performSslyzeScan(hostname);
        scanResults.tls = r.tls;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'trivy') {
        const r = await performTrivyScan(target, options);
        scanResults.findings = r.findings;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'semgrep') {
        const r = await performSemgrepScan(target, options);
        scanResults.findings = r.findings;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'gitleaks') {
        const r = await performGitleaksScan(target, options);
        scanResults.findings = r.findings;
        vulnerabilities.push(...r.vulnerabilities);
      } else if (tool === 'yara') {
        const r = await performYaraScan(target, options);
        scanResults.findings = r.findings;
        vulnerabilities.push(...r.vulnerabilities);
      } else {
        throw new Error(`Unknown tool: ${tool}`);
      }
    } catch (scanError) {
      scanResults.error = scanError instanceof Error ? scanError.message : 'Scan error';
    }

    await supabase.from('scans').update({
      status: 'completed',
      results: scanResults,
      completed_at: new Date().toISOString(),
    }).eq('id', scanId);

    return new Response(
      JSON.stringify({ success: true, scanId, vulnerabilities, results: scanResults }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err instanceof Error ? err.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});

// =====================================================================
// Core helpers: real network probing, SSRF guard, HTTP with timeout
// =====================================================================

async function safeFetch(
  urlStr: string,
  timeoutMs = 8000,
  redirect: RequestRedirect = 'follow'
): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(urlStr, {
      signal: controller.signal,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 OrvynScanner/2.0',
        Accept: '*/*',
      },
      redirect,
    });
    clearTimeout(timer);
    return res;
  } catch {
    return null;
  }
}

async function fetchBody(
  urlStr: string,
  timeoutMs = 8000
): Promise<{ status: number; headers: Headers; body: string; finalUrl: string } | null> {
  const res = await safeFetch(urlStr, timeoutMs, 'follow');
  if (!res) return null;
  let body = '';
  try {
    body = (await res.text()).slice(0, 500_000);
  } catch {
    /* ignore body read errors */
  }
  return { status: res.status, headers: res.headers, body, finalUrl: res.url };
}

function resolveUrl(base: string, path: string): string {
  try {
    return new URL(path, base).toString();
  } catch {
    return base.replace(/\/+$/, '') + path;
  }
}

function isPrivateIp(ip: string): string | null {
  if (ip.includes(':')) {
    const v6 = ip.toLowerCase();
    if (v6 === '::1') return 'IPv6 loopback';
    if (v6.startsWith('fc') || v6.startsWith('fd')) return 'IPv6 unique-local';
    if (v6.startsWith('fe8')) return 'IPv6 link-local';
    const mapped = v6.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return null;
  }
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return null;
  const [a, b] = parts;
  if (a === 0) return '0.0.0.0/8';
  if (a === 10) return '10.0.0.0/8';
  if (a === 127) return 'loopback 127.0.0.0/8';
  if (a === 169 && b === 254) return 'link-local 169.254.0.0/16';
  if (a === 172 && b >= 16 && b <= 31) return '172.16.0.0/12';
  if (a === 192 && b === 168) return '192.168.0.0/16';
  if (a === 192 && b === 0) return '192.0.0.0/24';
  if (a === 100 && b >= 64 && b <= 127) return '100.64.0.0/10';
  if (a === 198 && (b === 18 || b === 19)) return '198.18.0.0/15';
  if (a >= 224) return 'multicast/reserved';
  return null;
}

/** Returns a reason string when the hostname resolves to a private address. */
async function isPrivateHostname(hostname: string): Promise<string | null> {
  const literal = isPrivateIp(hostname);
  if (literal) return literal;

  const answers: string[] = [];
  for (const type of ['A', 'AAAA']) {
    try {
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${type}`,
        { headers: { Accept: 'application/dns-json' } }
      );
      if (res.ok) {
        const data = await res.json();
        for (const ans of data.Answer ?? []) {
          if (type === 'A' && ans.type === 1) answers.push(ans.data);
          if (type === 'AAAA' && ans.type === 28) answers.push(ans.data);
        }
      }
    } catch {
      /* lookup failed — connect attempts will fail naturally */
    }
  }
  for (const ip of answers) {
    const reason = isPrivateIp(ip);
    if (reason) return `${ip} is ${reason}`;
  }
  return null;
}

/**
 * Real TCP connect() probe. Returns:
 *  - open:      TCP handshake completed (SYN/ACK observed)
 *  - closed:    connection refused / reset by target
 *  - timeout:   no response within timeout (filtered)
 *  - unchecked: this runtime could not perform raw TCP (reported honestly)
 */
async function tcpProbe(host: string, port: number, grabBanner = true): Promise<ProbeResult> {
  const timeoutMs = 3000;
  let conn: Deno.TcpConn | null = null;
  try {
    const raced = await Promise.race([
      Deno.connect({ hostname: host, port, transport: 'tcp' }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('PROBE_TIMEOUT')), timeoutMs)
      ),
    ]);
    conn = raced as Deno.TcpConn;
  } catch (err) {
    const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    if (msg.includes('PROBE_TIMEOUT')) return { state: 'timeout' };
    if (/refused|reset/i.test(msg)) return { state: 'closed' };
    if (/timed out|timeout/i.test(msg)) return { state: 'timeout' };
    if (/permission|notsupported|not supported|unsupported|operation not permitted/i.test(msg)) {
      return { state: 'unchecked' };
    }
    return { state: 'unchecked', banner: msg.slice(0, 120) };
  }

  let banner: string | undefined;
  if (grabBanner) {
    try {
      const buf = new Uint8Array(256);
      const n = await Promise.race([
        conn.read(buf),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 1200)),
      ]);
      if (typeof n === 'number' && n > 0) {
        banner = new TextDecoder()
          .decode(buf.subarray(0, n))
          .replace(/[\r\n\t]+/g, ' ')
          .trim()
          .slice(0, 140);
      }
    } catch {
      /* no banner offered */
    }
  }
  try {
    conn.close();
  } catch {
    /* already closed */
  }
  return banner ? { state: 'open', banner } : { state: 'open' };
}

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function compareVersions(a: string, b: string): number {
  const aParts = a.split('.').map(Number);
  const bParts = b.split('.').map(Number);
  for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
    const av = aParts[i] ?? 0;
    const bv = bParts[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

// =====================================================================
// Nmap / Masscan — real TCP connect scan of common ports
// =====================================================================

const TOP_PORTS: Array<{ port: number; service: string }> = [
  { port: 21, service: 'ftp' },
  { port: 22, service: 'ssh' },
  { port: 23, service: 'telnet' },
  { port: 25, service: 'smtp' },
  { port: 53, service: 'domain' },
  { port: 80, service: 'http' },
  { port: 110, service: 'pop3' },
  { port: 111, service: 'rpcbind' },
  { port: 135, service: 'msrpc' },
  { port: 139, service: 'netbios-ssn' },
  { port: 143, service: 'imap' },
  { port: 443, service: 'https' },
  { port: 445, service: 'microsoft-ds' },
  { port: 993, service: 'imaps' },
  { port: 995, service: 'pop3s' },
  { port: 1433, service: 'ms-sql-s' },
  { port: 1521, service: 'oracle' },
  { port: 3306, service: 'mysql' },
  { port: 3389, service: 'ms-wbt' },
  { port: 5432, service: 'postgresql' },
  { port: 5900, service: 'vnc' },
  { port: 6379, service: 'redis' },
  { port: 8080, service: 'http-proxy' },
  { port: 8443, service: 'https-alt' },
  { port: 9200, service: 'elasticsearch' },
  { port: 11211, service: 'memcached' },
  { port: 27017, service: 'mongodb' },
];

const WEB_PORTS = new Set([80, 443, 3000, 8000, 8080, 8443, 8888, 9090]);

const RISKY_SERVICES: Record<number, { severity: 'critical' | 'high' | 'medium'; name: string; note: string }> = {
  23: { severity: 'critical', name: 'telnet', note: 'Telnet transmits credentials in cleartext.' },
  3306: { severity: 'high', name: 'mysql', note: 'Database port exposed to the internet.' },
  5432: { severity: 'high', name: 'postgresql', note: 'Database port exposed to the internet.' },
  6379: { severity: 'high', name: 'redis', note: 'Redis is frequently exposed without authentication.' },
  27017: { severity: 'high', name: 'mongodb', note: 'MongoDB exposed to the internet.' },
  9200: { severity: 'high', name: 'elasticsearch', note: 'Elasticsearch exposed without authentication.' },
  5900: { severity: 'high', name: 'vnc', note: 'VNC exposed to the internet.' },
  445: { severity: 'high', name: 'microsoft-ds', note: 'SMB exposed to the internet (WannaCry-class risk).' },
  11211: { severity: 'medium', name: 'memcached', note: 'Memcached often amplifies DDoS and leaks data.' },
  1433: { severity: 'medium', name: 'ms-sql-s', note: 'MSSQL exposed to the internet.' },
  1521: { severity: 'medium', name: 'oracle', note: 'Oracle listener exposed to the internet.' },
  3389: { severity: 'medium', name: 'ms-wbt', note: 'RDP exposed to the internet.' },
  21: { severity: 'medium', name: 'ftp', note: 'FTP transmits credentials in cleartext.' },
  111: { severity: 'medium', name: 'rpcbind', note: 'RPC binder exposes service enumeration.' },
  139: { severity: 'medium', name: 'netbios-ssn', note: 'NetBIOS exposed to the internet.' },
};

async function performNmapScan(hostname: string, options: Record<string, string>) {
  const vulnerabilities: VulnerabilityFinding[] = [];
  const started = performance.now();

  let portList: number[];
  if ((options.ports ?? '').trim()) {
    portList = options.ports
      .split(',')
      .map((p) => parseInt(p.trim(), 10))
      .filter((n) => n > 0 && n <= 65535);
  } else {
    portList = TOP_PORTS.map((p) => p.port);
  }

  interface PortResult {
    port: number;
    service: string;
    state: ProbeState;
    banner: string;
    http: string;
    elapsedMs: number;
  }

  const results: PortResult[] = [];
  for (const group of chunk(portList, 9)) {
    const batch = await Promise.all(
      group.map(async (port) => {
        const known = TOP_PORTS.find((p) => p.port === port);
        const service = known?.service ?? 'unknown';
        const isWeb = WEB_PORTS.has(port);
        const t0 = performance.now();
        const probe = await tcpProbe(hostname, port, !isWeb);

        let http = '';
        if (probe.state === 'open' && isWeb) {
          const scheme = port === 443 || port === 8443 ? 'https' : 'http';
          const res = await safeFetch(`${scheme}://${hostname}:${port}/`, 5000);
          if (res) {
            http = `HTTP ${res.status}, server=${res.headers.get('server') ?? 'n/a'}, ` +
              `content-type=${res.headers.get('content-type') ?? 'n/a'}`;
          }
        }
        return {
          port,
          service,
          state: probe.state,
          banner: probe.banner ?? '',
          http,
          elapsedMs: Math.round(performance.now() - t0),
        };
      })
    );
    results.push(...batch);
  }

  const ports = results.map((r) => ({
    port: r.port,
    state: r.state,
    service: r.service,
    banner: r.banner || r.http || '',
    elapsed_ms: r.elapsedMs,
  }));

  const openPorts = results.filter((r) => r.state === 'open');
  const uncheckedCount = results.filter((r) => r.state === 'unchecked').length;
  const durationMs = Math.round(performance.now() - started);

  if (uncheckedCount === results.length) {
    vulnerabilities.push({
      title: 'Raw TCP scanning unavailable in this runtime',
      severity: 'info',
      description:
        'This serverless runtime refused raw TCP connections, so port states could not be determined here. ' +
        'HTTP-based checks still ran. For a full nmap connect-scan run the Termux/Windows agent, ' +
        'which executes the real nmap binary.',
      evidence: `All ${results.length} probes returned "unchecked" (no raw socket access)`,
      remediation: 'Start the Termux/Windows agent and launch the scan from the Lab.',
    });
  } else {
    vulnerabilities.push({
      title: `Port scan completed: ${openPorts.length} open port(s) on ${hostname}`,
      severity: 'info',
      description:
        `Performed real TCP connect() probes against ${results.length} ports in ${durationMs}ms. ` +
        `States: ${openPorts.length} open, ` +
        `${results.filter((r) => r.state === 'closed').length} closed, ` +
        `${results.filter((r) => r.state === 'timeout').length} filtered/timeout, ` +
        `${uncheckedCount} unchecked.`,
      evidence: openPorts.length
        ? openPorts
            .map(
              (r) =>
                `${r.port}/${r.service} open (${r.elapsedMs}ms)` +
                (r.banner ? ` banner: ${r.banner}` : r.http ? ` ${r.http}` : '')
            )
            .join('; ')
        : 'No open ports among those probed',
      remediation: 'Review whether every open port is required and restrict exposure via firewall rules.',
    });
  }

  for (const r of openPorts) {
    const risky = RISKY_SERVICES[r.port];
    if (risky) {
      vulnerabilities.push({
        title: `${risky.name.toUpperCase()} service exposed on port ${r.port}`,
        severity: risky.severity,
        description: `${risky.note} A real TCP handshake completed against port ${r.port}.`,
        evidence:
          `TCP connect() succeeded on ${hostname}:${r.port} in ${r.elapsedMs}ms` +
          (r.banner ? `; banner: ${r.banner}` : r.http ? `; ${r.http}` : ''),
        remediation: `Restrict port ${r.port} to trusted source IPs or bind it to localhost; disable it if unused.`,
        port: r.port,
        service: r.service,
      });
    }
    if (WEB_PORTS.has(r.port) && r.port !== 80 && r.port !== 443) {
      vulnerabilities.push({
        title: `Non-standard web port ${r.port} exposed (${r.service})`,
        severity: 'low',
        description: `Port ${r.port} answered an HTTP probe and is publicly accessible.`,
        evidence: `TCP connect succeeded in ${r.elapsedMs}ms; ${r.http || 'HTTP probe OK'}`,
        remediation: 'Ensure this service is behind a firewall or requires authentication. Consider moving to standard ports.',
        port: r.port,
        service: r.service,
      });
    }
  }

  return { ports, vulnerabilities };
}

async function performMasscanScan(hostname: string, options: Record<string, string>) {
  // Masscan shares the same real connect-scan engine; nmap passes options through.
  const r = await performNmapScan(hostname, options);
  return { ports: r.ports, vulnerabilities: r.vulnerabilities };
}

// =====================================================================
// Nuclei — real HTTP template checks against live responses
// =====================================================================

async function performNucleiScan(url: string, hostname: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const base = await fetchBody(url, 10000);
  if (!base) {
    const fallback = await fetchBody(`http://${hostname}`, 10000);
    if (!fallback) {
      vulnerabilities.push({
        title: 'Target not reachable',
        severity: 'info',
        description: `Could not reach ${hostname} over HTTP or HTTPS.`,
        evidence: 'Connection timed out or was refused on both schemes',
        remediation: 'Verify the target is online and accessible from the internet.',
      });
      return { findings, vulnerabilities };
    }
  }

  const page = base ?? (await fetchBody(`http://${hostname}`, 10000))!;
  const headers = Object.fromEntries(page.headers.entries());
  const html = page.body;

  const securityHeaders = [
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'content-security-policy',
    'referrer-policy',
    'permissions-policy',
  ];
  const severityMap: Record<string, 'medium' | 'low' | 'info'> = {
    'strict-transport-security': 'medium',
    'content-security-policy': 'medium',
    'x-frame-options': 'low',
    'x-content-type-options': 'low',
    'referrer-policy': 'low',
    'permissions-policy': 'info',
  };

  for (const header of securityHeaders) {
    if (!headers[header]) {
      findings.push(`Missing security header: ${header}`);
      vulnerabilities.push({
        title: `Missing ${header} header`,
        severity: severityMap[header] ?? 'low',
        description: `The ${header} security header is not set on the live response from ${hostname}.`,
        evidence: `GET ${page.finalUrl} → HTTP ${page.status}; header "${header}" absent`,
        remediation: `Add the ${header} header to your web server configuration.`,
      });
    }
  }

  const gitRes = await fetchBody(resolveUrl(url, '/.git/config'), 6000);
  if (gitRes && gitRes.status === 200 && /\[core\]/.test(gitRes.body)) {
    findings.push('Exposed .git directory detected');
    vulnerabilities.push({
      title: 'Exposed .git directory',
      severity: 'high',
      description: 'The .git/config file is publicly accessible, leaking repository metadata and history.',
      evidence: `GET /.git/config → HTTP 200 with git config content: ${gitRes.body.split('\n')[0]}`,
      remediation: 'Block access to .git directories in your web server configuration.',
    });
  }

  const envRes = await fetchBody(resolveUrl(url, '/.env'), 6000);
  if (envRes && envRes.status === 200 && /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(envRes.body) &&
      /(KEY|SECRET|PASSWORD|TOKEN)/i.test(envRes.body) && !/^\s*<(!doctype|html)/i.test(envRes.body)) {
    findings.push('Exposed .env file detected');
    vulnerabilities.push({
      title: 'Exposed environment file',
      severity: 'critical',
      description: 'A .env file containing configuration secrets is publicly accessible.',
      evidence: `GET /.env → HTTP 200, ${envRes.body.split('\n').length} config lines, sample key: ${
        (envRes.body.match(/^[A-Za-z_][A-Za-z0-9_]*=/m) || [''])[0]
      }`,
      remediation: 'Remove the .env file from the web root and block access to dotfiles.',
    });
  }

  if (/Index of \//.test(html) && /<a href/i.test(html)) {
    findings.push('Directory listing enabled');
    vulnerabilities.push({
      title: 'Directory listing enabled',
      severity: 'medium',
      description: 'Directory listing is enabled, allowing visitors to browse files without an index page.',
      evidence: `GET ${page.finalUrl} → HTTP ${page.status} contains "Index of /" with file links`,
      remediation: 'Disable directory listing in your web server configuration.',
    });
  }

  const adminPaths = ['/admin', '/wp-admin', '/administrator', '/phpmyadmin'];
  for (const path of adminPaths) {
    const adminRes = await fetchBody(resolveUrl(url, path), 6000);
    if (!adminRes) continue;
    const isHtml = (adminRes.headers.get('content-type') ?? '').includes('html');
    const soft404 = adminRes.status === 200 && isHtml && adminRes.body.trim() === html.trim();
    if (soft404) continue; // SPA served the same shell — not a real panel
    if (adminRes.status === 200 || adminRes.status === 401 || adminRes.status === 403) {
      findings.push(`Admin panel found at ${path} (HTTP ${adminRes.status})`);
      vulnerabilities.push({
        title: `Admin panel exposed at ${path}`,
        severity: adminRes.status === 200 ? 'high' : 'low',
        description: `An admin endpoint responded at ${path} with a response different from the main page.`,
        evidence: `GET ${path} → HTTP ${adminRes.status}, ${adminRes.headers.get('content-type') ?? 'n/a'}, body differs from base page`,
        remediation: 'Restrict admin panel access to specific IP addresses or require VPN access.',
      });
    }
  }

  return { findings, vulnerabilities };
}

// =====================================================================
// ZAP — passive checks on the live response
// =====================================================================

async function performZapScan(url: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const page = await fetchBody(url, 10000);
  if (!page) return { findings, vulnerabilities };

  const headers = Object.fromEntries(page.headers.entries());
  const html = page.body;

  if (url.startsWith('https://') && /(?:src|href|action)\s*=\s*["']http:\/\//i.test(html)) {
    findings.push('Mixed content detected');
    vulnerabilities.push({
      title: 'Mixed content on HTTPS page',
      severity: 'medium',
      description: 'The page loads resources over HTTP despite being served over HTTPS.',
      evidence: `GET ${page.finalUrl} → ${html.match(/(?:src|href|action)\s*=\s*["']http:\/\/[^"']+/i)?.[0]?.slice(0, 120) ?? 'http:// resource found'}`,
      remediation: 'Update all resource URLs to use HTTPS.',
    });
  }

  if (/<form/i.test(html) && !/csrf|authenticity_token|_token/i.test(html)) {
    findings.push('Forms may lack CSRF protection');
    vulnerabilities.push({
      title: 'Potential missing CSRF protection',
      severity: 'medium',
      description: 'Forms on the page do not appear to include CSRF tokens.',
      evidence: `${(html.match(/<form[^>]*>/gi) || []).length} form(s) found; no csrf/authenticity_token/_token in page source`,
      remediation: 'Implement CSRF tokens on all forms that perform state-changing operations.',
    });
  }

  const rawCookies: string[] =
    typeof (page.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie === 'function'
      ? (page.headers as Headers & { getSetCookie: () => string[] }).getSetCookie()
      : headers['set-cookie']
      ? [headers['set-cookie']]
      : [];

  for (const cookie of rawCookies) {
    const name = cookie.split('=')[0];
    if (!/secure/i.test(cookie)) {
      vulnerabilities.push({
        title: `Cookie "${name}" missing Secure flag`,
        severity: 'medium',
        description: 'A cookie is set without the Secure flag and can be transmitted over plain HTTP.',
        evidence: `Set-Cookie: ${cookie.substring(0, 140)}`,
        remediation: 'Add the Secure flag to all cookies.',
      });
    }
    if (!/httponly/i.test(cookie)) {
      vulnerabilities.push({
        title: `Cookie "${name}" missing HttpOnly flag`,
        severity: 'medium',
        description: 'A cookie is set without HttpOnly and can be read by JavaScript (XSS theft risk).',
        evidence: `Set-Cookie: ${cookie.substring(0, 140)}`,
        remediation: 'Add the HttpOnly flag to all cookies.',
      });
    }
    if (!/samesite/i.test(cookie)) {
      vulnerabilities.push({
        title: `Cookie "${name}" missing SameSite attribute`,
        severity: 'low',
        description: 'No SameSite attribute on the cookie; browsers default to Lax but explicit is safer.',
        evidence: `Set-Cookie: ${cookie.substring(0, 140)}`,
        remediation: 'Set SameSite=Strict or SameSite=Lax on all cookies.',
      });
    }
  }

  if (headers['x-powered-by']) {
    findings.push(`X-Powered-By header reveals technology: ${headers['x-powered-by']}`);
    vulnerabilities.push({
      title: 'X-Powered-By header exposes technology',
      severity: 'low',
      description: `The X-Powered-By header reveals the backend technology.`,
      evidence: `X-Powered-By: ${headers['x-powered-by']}`,
      remediation: 'Remove the X-Powered-By header from your server configuration.',
    });
  }

  if (headers['server']) {
    findings.push(`Server header: ${headers['server']}`);
    if (/\d/.test(headers['server'])) {
      vulnerabilities.push({
        title: 'Server version disclosed',
        severity: 'low',
        description: 'The Server header reveals the software version, easing targeted attacks.',
        evidence: `Server: ${headers['server']}`,
        remediation: 'Configure your web server to hide version information.',
      });
    }
  }

  return { findings, vulnerabilities };
}

// =====================================================================
// Nikto — dangerous files with content validation (no SPA false positives)
// =====================================================================

async function performNiktoScan(url: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const page = await fetchBody(url, 8000);
  const headers = page ? Object.fromEntries(page.headers.entries()) : {};

  if (headers['server']) {
    const serverHeader = headers['server'];
    findings.push(`Server: ${serverHeader}`);
    if (/Apache\/2\.2\./.test(serverHeader)) {
      vulnerabilities.push({
        title: 'Outdated Apache version',
        severity: 'high',
        description: 'Apache 2.2.x is end-of-life and no longer receives security updates.',
        evidence: `Server: ${serverHeader}`,
        remediation: 'Upgrade to a supported version of Apache (2.4.x or later).',
      });
    }
    if (/nginx\/1\.[0-9]\./.test(serverHeader)) {
      vulnerabilities.push({
        title: 'Potentially outdated nginx version',
        severity: 'medium',
        description: 'The nginx version appears to be from an older release branch.',
        evidence: `Server: ${serverHeader}`,
        remediation: 'Update nginx to the latest stable version.',
      });
    }
  }

  const dangerousFiles: Array<{
    path: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    validate: (body: string, contentType: string) => boolean;
  }> = [
    { path: '/.env', severity: 'critical', validate: (b, c) => !/html/i.test(c) && /^[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(b) },
    { path: '/backup.zip', severity: 'high', validate: (b, c) => !/html/i.test(c) && b.startsWith('PK') },
    { path: '/backup.sql', severity: 'high', validate: (b, c) => !/html/i.test(c) && /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) },
    { path: '/dump.sql', severity: 'high', validate: (b, c) => !/html/i.test(c) && /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b) },
    { path: '/phpinfo.php', severity: 'high', validate: (b) => /phpinfo\(\)|PHP Version/i.test(b) },
    { path: '/info.php', severity: 'high', validate: (b) => /phpinfo\(\)|PHP Version/i.test(b) },
    { path: '/wp-config.php.bak', severity: 'critical', validate: (b, c) => !/html/i.test(c) && /DB_NAME|DB_PASSWORD/.test(b) },
    { path: '/.htpasswd', severity: 'high', validate: (b, c) => !/html/i.test(c) && /:\$apr1\$|:\$2[aby]\$|^[^:]+:[^:]+$/m.test(b) },
    { path: '/web.config', severity: 'medium', validate: (b, c) => !/html/i.test(c) && /<configuration>/.test(b) },
    { path: '/robots.txt', severity: 'info', validate: (b, c) => !/html/i.test(c) && /user-agent:/i.test(b) },
  ];

  const checks = await Promise.all(
    dangerousFiles.map(async (f) => {
      const res = await fetchBody(resolveUrl(url, f.path), 6000);
      if (!res || res.status !== 200) return { f, ok: false, evidence: '' };
      const contentType = res.headers.get('content-type') ?? '';
      const ok = f.validate(res.body, contentType);
      return { f, ok, evidence: `GET ${f.path} → HTTP 200, content-type=${contentType || 'n/a'}, body[0..80]=${JSON.stringify(res.body.slice(0, 80))}` };
    })
  );

  for (const { f, ok, evidence } of checks) {
    if (!ok) continue;
    findings.push(`Sensitive file accessible: ${f.path}`);
    vulnerabilities.push({
      title: `Sensitive file accessible: ${f.path}`,
      severity: f.severity,
      description: `The file ${f.path} is publicly accessible and its content matched expected patterns.`,
      evidence,
      remediation: `Remove or restrict access to ${f.path}.`,
    });
  }

  return { findings, vulnerabilities };
}

// =====================================================================
// WhatWeb — real header/body fingerprinting
// =====================================================================

async function performWhatwebScan(url: string) {
  const technologies: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const page = await fetchBody(url, 8000);
  if (!page) return { technologies, vulnerabilities };

  const headers = Object.fromEntries(page.headers.entries());
  const html = page.body;

  if (headers['x-powered-by']) technologies.push(`X-Powered-By: ${headers['x-powered-by']}`);
  if (headers['server']) technologies.push(`Server: ${headers['server']}`);

  if (/wp-content|wp-includes/i.test(html)) {
    technologies.push('CMS: WordPress');
    const wpVersionMatch = html.match(/wp-includes\/[^?]*\?ver=([0-9.]+)/);
    if (wpVersionMatch) {
      technologies.push(`WordPress version: ${wpVersionMatch[1]}`);
      vulnerabilities.push({
        title: 'WordPress version detected',
        severity: 'low',
        description: `WordPress version ${wpVersionMatch[1]} is visible in the page source.`,
        evidence: `Found wp-includes?ver=${wpVersionMatch[1]}`,
        remediation: 'Remove version numbers from WordPress asset URLs.',
      });
    }
  }
  if (/drupal/i.test(html)) technologies.push('CMS: Drupal');
  if (/joomla|com_content/i.test(html)) technologies.push('CMS: Joomla');

  if (html.includes('__NEXT_DATA__') || /_next\/static/i.test(html)) technologies.push('Framework: Next.js');
  else if (/<div id="root"|__REACT/i.test(html)) technologies.push('Framework: React');
  if (html.includes('__nuxt__')) technologies.push('Framework: Nuxt/Vue');
  if (headers['x-aspnetmvc-version']) technologies.push('Framework: ASP.NET MVC');

  if (/google-analytics|gtag\(/i.test(html)) technologies.push('Analytics: Google Analytics');
  if (/googletagmanager/i.test(html)) technologies.push('Analytics: Google Tag Manager');

  if (headers['cf-ray']) technologies.push('CDN: Cloudflare');
  if (headers['x-amz-cf-id']) technologies.push('CDN: AWS CloudFront');

  return { technologies, vulnerabilities };
}

// =====================================================================
// httpx — live probes of both schemes with latency + real <title>
// =====================================================================

async function performHttpxScan(url: string, hostname: string) {
  const probes: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];
  let anyUp = false;

  for (const scheme of ['https', 'http']) {
    const t0 = performance.now();
    const res = await safeFetch(`${scheme}://${hostname}/`, 8000, 'manual');
    const latency = Math.round(performance.now() - t0);
    if (!res) {
      probes.push(`${scheme}://${hostname} — DOWN (connection failed within 8000ms)`);
      continue;
    }
    anyUp = true;
    let title = '';
    let length = 0;
    if (res.status < 400) {
      try {
        const body = (await res.text()).slice(0, 300_000);
        length = body.length;
        title = (body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] ?? '').trim();
      } catch {
        /* ignore */
      }
    }
    probes.push(
      `${scheme}://${hostname} — HTTP ${res.status}` +
        `${res.status >= 300 && res.status < 400 ? ` → ${res.headers.get('location') ?? ''}` : ''}` +
        ` — ${latency}ms — ${length} bytes` +
        `${title ? ` — title: ${title.slice(0, 80)}` : ''}` +
        `${res.headers.get('server') ? ` — server: ${res.headers.get('server')}` : ''}`
    );
  }

  if (!anyUp) {
    vulnerabilities.push({
      title: 'No live web service detected',
      severity: 'high',
      description: 'Neither HTTP nor HTTPS responded for this host.',
      evidence: probes.join(' | '),
      remediation: 'Verify the host is running a web server and is reachable from the internet.',
    });
  }

  return { probes, vulnerabilities };
}

// =====================================================================
// DNS — real DoH lookups + SPF / DMARC / CAA / DNSSEC analysis
// =====================================================================

async function dohLookup(name: string, type: string): Promise<Array<{ name: string; type: number; data: string }>> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { Accept: 'application/dns-json' } }
    );
    if (!res.ok) return [];
    const data = await res.json();
    return (data.Answer ?? []).map((a: { name: string; type: number; data: string }) => ({
      name: a.name,
      type: a.type,
      data: String(a.data).replace(/^"|"$/g, ''),
    }));
  } catch {
    return [];
  }
}

async function performDnsScan(hostname: string) {
  const records: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
  const results = await Promise.all(types.map((t) => dohLookup(hostname, t)));

  let total = 0;
  results.forEach((answers, i) => {
    for (const a of answers) {
      records.push(`${a.name} ${types[i]} ${a.data}`);
      total++;
    }
  });

  const txts = results[types.indexOf('TXT')].map((a) => a.data);

  const spf = txts.find((t) => /^v=spf1/i.test(t));
  if (!spf) {
    vulnerabilities.push({
      title: 'SPF record missing',
      severity: 'medium',
      description: 'No SPF record found — anyone can send email claiming to be from this domain (spoofing).',
      evidence: `TXT queries for ${hostname} returned ${txts.length} record(s), none starting with "v=spf1"`,
      remediation: 'Publish an SPF TXT record, e.g. v=spf1 -all if you send no email from this domain.',
    });
  } else if (/\+all\b/i.test(spf)) {
    vulnerabilities.push({
      title: 'SPF record allows any sender (+all)',
      severity: 'high',
      description: 'The SPF record ends with +all, explicitly authorizing the entire internet to send as this domain.',
      evidence: `SPF: ${spf}`,
      remediation: 'Change +all to -all (fail) after listing your legitimate senders.',
    });
  } else {
    records.push(`SPF analysis: ${spf}`);
  }

  const dmarcAnswers = await dohLookup(`_dmarc.${hostname}`, 'TXT');
  const dmarc = dmarcAnswers.find((a) => /^v=dmarc1/i.test(a.data));
  if (!dmarc) {
    vulnerabilities.push({
      title: 'DMARC record missing',
      severity: 'medium',
      description: 'No DMARC record at _dmarc.' + hostname + ' — receivers have no policy against forged mail.',
      evidence: `TXT query for _dmarc.${hostname} returned 0 records`,
      remediation: 'Publish v=DMARC1; p=quarantine; rua=mailto:you@' + hostname,
    });
  } else {
    records.push(`DMARC: ${dmarc.data}`);
    if (/[?;]\s*p\s*=\s*none/i.test(dmarc.data)) {
      vulnerabilities.push({
        title: 'DMARC policy is "none" (monitor only)',
        severity: 'low',
        description: 'DMARC is present but p=none, so forged messages are not quarantined or rejected.',
        evidence: `DMARC: ${dmarc.data}`,
        remediation: 'Escalate to p=quarantine then p=reject once reports look clean.',
      });
    }
  }

  const caa = results[types.indexOf('CAA')];
  if (caa.length === 0) {
    vulnerabilities.push({
      title: 'No CAA record',
      severity: 'low',
      description: 'No Certificate Authority Authorization record — any CA may issue a certificate for this domain.',
      evidence: `CAA query for ${hostname} returned 0 records`,
      remediation: 'Add CAA records restricting certificate issuance to your chosen CA(s).',
    });
  }

  const ds = await dohLookup(hostname, 'DS');
  if (ds.length === 0) {
    vulnerabilities.push({
      title: 'DNSSEC not configured',
      severity: 'low',
      description: 'No DS records — DNS responses are unsigned and vulnerable to cache poisoning/spoofing.',
      evidence: 'DS query for ' + hostname + ' returned 0 records',
      remediation: 'Enable DNSSEC at your registrar/DNS provider.',
    });
  } else {
    records.push(`DNSSEC: ${ds.length} DS record(s) present`);
  }

  const soa = results[types.indexOf('SOA')];
  if (soa.length > 0) records.push(`SOA: ${soa[0].data}`);

  if (total === 0) {
    vulnerabilities.push({
      title: 'No DNS records found',
      severity: 'high',
      description: `The resolver returned no records for ${hostname} — the domain may not exist.`,
      evidence: 'All DoH queries returned empty answers',
      remediation: 'Check the domain name spelling and DNS configuration.',
    });
  }

  records.push(`Query method: DNS-over-HTTPS (dns.google), ${total} records returned`);
  return { records, vulnerabilities };
}

// =====================================================================
// SSLyze — real TLS handshake + Certificate Transparency data (crt.sh)
// =====================================================================

async function performSslyzeScan(hostname: string) {
  const tls: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const t0 = performance.now();
  const httpsRes = await safeFetch(`https://${hostname}/`, 10000, 'manual');
  const handshakeMs = Math.round(performance.now() - t0);

  if (!httpsRes) {
    vulnerabilities.push({
      title: 'HTTPS not available',
      severity: 'high',
      description: 'The target did not complete a TLS handshake within 10 seconds.',
      evidence: `TLS handshake to https://${hostname}/ failed or timed out`,
      remediation: 'Install a valid TLS certificate and enable HTTPS on the web server.',
    });
    tls.push(`TLS handshake FAILED for ${hostname}`);
  } else {
    tls.push(`TLS handshake OK → HTTP ${httpsRes.status} in ${handshakeMs}ms`);
    const hsts = httpsRes.headers.get('strict-transport-security');
    if (hsts) {
      tls.push(`HSTS: ${hsts}`);
      const maxAge = parseInt((hsts.match(/max-age=(\d+)/i) ?? ['', '0'])[1], 10);
      if (maxAge > 0 && maxAge < 15_552_000) {
        vulnerabilities.push({
          title: 'HSTS max-age too short',
          severity: 'low',
          description: `HSTS max-age is ${maxAge}s (< 180 days), so browsers will forget the policy quickly.`,
          evidence: `Strict-Transport-Security: ${hsts}`,
          remediation: 'Set max-age to at least 31536000 and consider includeSubDomains + preload.',
        });
      }
    } else {
      vulnerabilities.push({
        title: 'HSTS not enabled',
        severity: 'medium',
        description: 'No Strict-Transport-Security header — allows HTTPS downgrade on first visit.',
        evidence: `GET https://${hostname}/ → HTTP ${httpsRes.status}, header absent`,
        remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
      });
    }
  }

  // Real certificate data from Certificate Transparency logs (crt.sh)
  // crt.sh occasionally returns 5xx — retry once before giving up.
  let ctlData: unknown = null;
  for (let attempt = 0; attempt < 2 && !ctlData; attempt++) {
    try {
      const ctl = await fetch(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`, {
        headers: { 'User-Agent': 'OrvynScanner/2.0' },
      });
      if (ctl.ok) {
        ctlData = await ctl.json();
      } else {
        tls.push(`crt.sh attempt ${attempt + 1}: HTTP ${ctl.status}`);
        if (attempt === 0) await new Promise((r) => setTimeout(r, 1500));
      }
    } catch {
      tls.push(`crt.sh attempt ${attempt + 1}: request failed`);
      if (attempt === 0) await new Promise((r) => setTimeout(r, 1500));
    }
  }

  if (ctlData) {
    try {
      const entries = ctlData as Array<{
        issuer_name: string;
        not_before: string;
        not_after: string;
        common_name: string;
        name_value: string;
      }>;
      const matching = entries.filter(
        (e) =>
          e.common_name === hostname ||
          String(e.name_value)
            .split('\n')
            .some((n) => n.trim() === hostname || n.trim() === `*.${hostname}`)
      );
      tls.push(`Certificate Transparency: ${entries.length} total entries, ${matching.length} matching ${hostname}`);

      if (matching.length > 0) {
        const newest = matching.reduce((a, b) => (new Date(a.not_after) > new Date(b.not_after) ? a : b));
        tls.push(
          `Latest certificate: issued ${newest.not_before} → expires ${newest.not_after}, issuer=${newest.issuer_name}`
        );
        const expires = new Date(newest.not_after);
        const daysLeft = Math.floor((expires.getTime() - Date.now()) / 86_400_000);
        if (daysLeft < 0) {
          vulnerabilities.push({
            title: 'Certificate expired',
            severity: 'critical',
            description: `The most recent certificate for ${hostname} expired ${Math.abs(daysLeft)} day(s) ago.`,
            evidence: `crt.sh: not_after=${newest.not_after}, issuer=${newest.issuer_name}`,
            remediation: 'Renew the certificate immediately (ACME/Let\'s Encrypt can automate this).',
          });
        } else if (daysLeft <= 21) {
          vulnerabilities.push({
            title: `Certificate expires in ${daysLeft} day(s)`,
            severity: 'medium',
            description: 'The active certificate is close to expiry.',
            evidence: `crt.sh: not_after=${newest.not_after}, issuer=${newest.issuer_name}`,
            remediation: 'Renew the certificate before expiry.',
          });
        }
      } else {
        tls.push('No certificate entries found for this exact hostname in CT logs');
      }
    } catch {
      tls.push('crt.sh (Certificate Transparency) query failed');
    }
  } else {
    tls.push('crt.sh (Certificate Transparency): no data after retries');
  }

  // Real HTTP→HTTPS redirect verification
  const httpRes = await safeFetch(`http://${hostname}/`, 8000, 'manual');
  if (httpRes) {
    const loc = httpRes.headers.get('location') ?? '';
    if ([301, 302, 303, 307, 308].includes(httpRes.status) && /^https:/i.test(loc)) {
      tls.push(`HTTP→HTTPS redirect OK (HTTP ${httpRes.status} → ${loc})`);
    } else {
      tls.push(`HTTP responds with HTTP ${httpRes.status}${loc ? ` → ${loc}` : ' (no HTTPS redirect)'}`);
      if (!httpsRes) {
        // https down already reported
      } else {
        vulnerabilities.push({
          title: 'HTTP does not redirect to HTTPS',
          severity: 'medium',
          description: 'Port 80 serves content without redirecting to HTTPS, allowing downgrade/cookie interception.',
          evidence: `GET http://${hostname}/ → HTTP ${httpRes.status}, location=${loc || '(none)'}`,
          remediation: 'Configure a 301 redirect from http:// to https:// on port 80.',
        });
      }
    }
  }

  vulnerabilities.push({
    title: 'TLS scan scope',
    severity: 'info',
    description:
      'This scan verified: TLS handshake success + latency, HSTS policy, HTTP→HTTPS redirect, and certificate ' +
      'validity/issuer/expiry from Certificate Transparency logs. Weak-cipher and protocol-version enumeration ' +
      'requires the real sslyze binary — run it from the Termux/Windows agent.',
    evidence: tls.join(' | ').slice(0, 500),
    remediation: 'For cipher-suite and TLS 1.0/1.1 detection, launch sslyze from the agent.',
  });

  return { tls, vulnerabilities };
}

// =====================================================================
// Trivy — dependency versions served on the page (real asset fetches)
// =====================================================================

async function performTrivyScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const url = target.startsWith('http') ? target : `https://${target}`;
  const page = await fetchBody(url, 10000);
  if (!page) {
    vulnerabilities.push({
      title: 'Could not reach target for dependency scan',
      severity: 'info',
      description: 'Unable to fetch the target to analyze dependencies.',
      evidence: `GET ${url} failed`,
      remediation: 'Verify the target URL is accessible.',
    });
    return { findings, vulnerabilities };
  }

  let content = page.body;

  // Also fetch the page's own external scripts (real dependency sources)
  const scriptSrcs = [...content.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => resolveUrl(url, m[1]))
    .filter((u) => u.startsWith('http'))
    .slice(0, 5);
  const scriptBodies = await Promise.all(scriptSrcs.map((u) => fetchBody(u, 8000)));
  for (const sb of scriptBodies) {
    if (sb) content += '\n' + sb.body;
  }
  findings.push(`Fetched ${1 + scriptBodies.filter(Boolean).length} document(s) for dependency analysis`);

  const libChecks = [
    { pattern: /jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)\.js/i, name: 'jQuery', minSafe: '3.5.0' },
    { pattern: /angular[/-]([0-9]+\.[0-9]+\.[0-9]+)\.js/i, name: 'Angular', minSafe: '1.8.0' },
    { pattern: /bootstrap[/-]([0-9]+\.[0-9]+\.[0-9]+)\.(js|css)/i, name: 'Bootstrap', minSafe: '4.5.0' },
    { pattern: /vue[/.@-]([0-9]+\.[0-9]+\.[0-9]+)\.js/i, name: 'Vue.js', minSafe: '2.6.12' },
    { pattern: /lodash[/-]([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Lodash', minSafe: '4.17.21' },
    { pattern: /moment(?:\.min)?\.js[^"']*?\/([0-9]+\.[0-9]+\.[0-9]+)/i, name: 'Moment.js', minSafe: '2.29.4' },
  ];

  for (const check of libChecks) {
    const match = content.match(check.pattern);
    if (match) {
      findings.push(`${check.name} ${match[1]} detected`);
      if (compareVersions(match[1], check.minSafe) < 0) {
        vulnerabilities.push({
          title: `Outdated ${check.name} version ${match[1]}`,
          severity: 'medium',
          description: `${check.name} ${match[1]} is outdated. Current safe version is ${check.minSafe} or later.`,
          evidence: `Found ${check.name} ${match[1]} in served asset(s)`,
          remediation: `Update ${check.name} to version ${check.minSafe} or later.`,
        });
      }
    }
  }

  vulnerabilities.push({
    title: 'Trivy scan scope',
    severity: 'info',
    description:
      'This scan analyzed the JavaScript/CSS assets actually served by the target for known-vulnerable library ' +
      'versions. Container image, filesystem and IaC scans require the real trivy binary — run them from the ' +
      'Termux/Windows agent.',
    evidence: findings.join('; ') || 'No versioned libraries detected',
    remediation: 'For container/IaC scans, launch trivy from the agent.',
  });

  return { findings, vulnerabilities };
}

// =====================================================================
// Semgrep — real analysis of the served page's scripts
// =====================================================================

async function performSemgrepScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const url = target.startsWith('http') ? target : `https://${target}`;
  const page = await fetchBody(url, 10000);
  if (!page) return { findings, vulnerabilities };

  const html = page.body;

  const inlineScripts = html.match(/<script(?![^>]*\ssrc=)[^>]*>[\s\S]+?<\/script>/gi);
  if (inlineScripts && inlineScripts.length > 3) {
    findings.push(`${inlineScripts.length} inline scripts found`);
    vulnerabilities.push({
      title: 'Multiple inline scripts detected',
      severity: 'low',
      description: `${inlineScripts.length} inline scripts found. Inline scripts amplify XSS risk without a CSP.`,
      evidence: `GET ${page.finalUrl} → ${inlineScripts.length} inline <script> blocks in live HTML`,
      remediation: 'Move scripts to external files and use Content Security Policy to restrict inline scripts.',
    });
  }

  if (/[^a-zA-Z]eval\s*\(/.test(html)) {
    findings.push('eval() usage detected');
    vulnerabilities.push({
      title: 'eval() function usage detected',
      severity: 'high',
      description: 'eval() appears in served JavaScript and can enable code injection if input reaches it.',
      evidence: `Live page source contains: ${html.match(/.{0,60}eval\s*\(.{0,60}/)?.[0] ?? 'eval('}`,
      remediation: 'Avoid eval(); use JSON.parse() for data parsing.',
    });
  }

  if (/\.innerHTML\s*=/.test(html)) {
    findings.push('innerHTML assignment detected');
    vulnerabilities.push({
      title: 'innerHTML assignment may lead to XSS',
      severity: 'medium',
      description: 'Direct innerHTML assignment found — unsafe if the value contains user input.',
      evidence: `Live page source contains: ${html.match(/.{0,60}\.innerHTML\s*=\s*[^;]{0,80}/)?.[0] ?? 'innerHTML='}`,
      remediation: 'Use textContent, or sanitize with DOMPurify before assignment.',
    });
  }

  if (/document\.write\s*\(/.test(html)) {
    findings.push('document.write() usage detected');
    vulnerabilities.push({
      title: 'document.write() usage detected',
      severity: 'low',
      description: 'document.write() found in served script; it can overwrite the page and blocks parsing.',
      evidence: `Live page source contains: ${html.match(/.{0,60}document\.write\s*\([^)]{0,60}/)?.[0] ?? 'document.write('}`,
      remediation: 'Replace document.write with DOM APIs.',
    });
  }

  vulnerabilities.push({
    title: 'Semgrep scan scope',
    severity: 'info',
    description:
      'This scan performed pattern analysis on the JavaScript actually served by the target. Full SAST across ' +
      'your repository requires the real semgrep binary — run it from the Termux/Windows agent.',
    evidence: findings.join('; ') || 'No risky patterns found in served scripts',
    remediation: 'For repository-wide SAST, launch semgrep from the agent.',
  });

  return { findings, vulnerabilities };
}

// =====================================================================
// Gitleaks — real secret-pattern scan of served code
// =====================================================================

async function performGitleaksScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const url = target.startsWith('http') ? target : `https://${target}`;
  const page = await fetchBody(url, 10000);
  if (!page) return { findings, vulnerabilities };

  let content = page.body;
  const scriptSrcs = [...content.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => resolveUrl(url, m[1]))
    .filter((u) => u.startsWith('http'))
    .slice(0, 5);
  const scriptBodies = await Promise.all(scriptSrcs.map((u) => fetchBody(u, 8000)));
  for (const sb of scriptBodies) if (sb) content += '\n' + sb.body;

  const secretPatterns = [
    { pattern: /AIza[0-9A-Za-z\-_]{35}/g, name: 'Google API Key' },
    { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key' },
    { pattern: /ghp_[0-9A-Za-z]{36}/g, name: 'GitHub Personal Access Token' },
    { pattern: /sk_live_[0-9a-zA-Z]{24}/g, name: 'Stripe Secret Key' },
    { pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, name: 'Slack Token' },
    { pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, name: 'Private Key' },
  ];

  for (const { pattern, name } of secretPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      findings.push(`${name} found in served code`);
      vulnerabilities.push({
        title: `Exposed ${name}`,
        severity: 'critical',
        description: `A ${name} pattern was found in code served to browsers — anyone viewing source can reuse it.`,
        evidence: `${matches.length} occurrence(s), first: ${matches[0].slice(0, 12)}…${matches[0].slice(-4)}`,
        remediation: `Immediately rotate/revoke the exposed ${name} and remove it from client-side code.`,
      });
    }
  }

  // JWTs: distinguish public anon keys (fine) from privileged keys (critical)
  const jwts = content.match(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g) ?? [];
  for (const jwt of [...new Set(jwts)]) {
    try {
      const payload = JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      if (payload.role === 'service_role') {
        findings.push('service_role JWT exposed in served code');
        vulnerabilities.push({
          title: 'Supabase service_role key exposed',
          severity: 'critical',
          description: 'A JWT with role=service_role is embedded in client code. It bypasses ALL row-level security.',
          evidence: `JWT payload: {"role":"service_role",…} found in ${scriptBodies.filter(Boolean).length > 0 ? 'page or its scripts' : 'page source'}`,
          remediation: 'Rotate the service_role key in Supabase dashboard immediately; never ship it to clients.',
        });
      } else if (payload.role === 'anon') {
        findings.push('Public anon key present (expected, safe by design)');
      }
    } catch {
      /* not decodable */
    }
  }

  const passwordFields = content.match(/password["\s]*[:=]["\s]*["']([^"']{3,64})["']/gi);
  if (passwordFields) {
    findings.push(`${passwordFields.length} potential hardcoded password string(s)`);
    vulnerabilities.push({
      title: 'Potential hardcoded password detected',
      severity: 'high',
      description: 'A password-like literal was found in code served to browsers.',
      evidence: `${passwordFields.length} pattern(s), first: ${passwordFields[0].slice(0, 80)}`,
      remediation: 'Remove any hardcoded credentials from client-side code.',
    });
  }

  vulnerabilities.push({
    title: 'Gitleaks scan scope',
    severity: 'info',
    description:
      'This scan searched code served by the target (HTML + up to 5 external scripts) for real secret patterns, ' +
      'including a privileged-key check on JWT roles. Git-history scanning requires the real gitleaks binary — ' +
      'run it from the Termux/Windows agent.',
    evidence: findings.join('; ') || 'No secrets found in served code',
    remediation: 'For repo history scanning, launch gitleaks from the agent.',
  });

  return { findings, vulnerabilities };
}

// =====================================================================
// YARA — real pattern matching on served content
// =====================================================================

async function performYaraScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const url = target.startsWith('http') ? target : `https://${target}`;
  const page = await fetchBody(url, 10000);
  if (!page) {
    findings.push('Target not reachable over HTTP — file-based YARA scanning requires the Termux agent');
    vulnerabilities.push({
      title: 'YARA scan requires the Termux agent for file scanning',
      severity: 'info',
      description: 'YARA file scanning runs on the Termux agent. Ensure your agent is running (pkg install yara).',
      evidence: `GET ${url} failed`,
      remediation: 'Keep your Termux agent running to process YARA scan tasks.',
    });
    return { findings, vulnerabilities };
  }

  const content = page.body;

  const suspiciousPatterns = [
    { pattern: /CreateProcess|WriteProcessMemory|VirtualAllocEx/gi, name: 'Windows API process manipulation' },
    { pattern: /WinExec|ShellExecute/gi, name: 'Command execution API' },
    { pattern: /cmd\.exe\s+\/c|\/bin\/sh\s+-c/gi, name: 'Shell command execution' },
    { pattern: /powershell\s+(-enc|-e\s+[A-Za-z0-9+/=]+)/gi, name: 'Encoded PowerShell command' },
    { pattern: /atob\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*\)/g, name: 'Large base64 blob decoded at runtime' },
    { pattern: /document\.cookie\s*=\s*[^;]*(?:pass|token|session)/gi, name: 'Cookie write with credential-like name' },
  ];

  for (const { pattern, name } of suspiciousPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      findings.push(`${name}: ${matches.length} occurrence(s)`);
      vulnerabilities.push({
        title: `Suspicious pattern detected: ${name}`,
        severity: 'medium',
        description: `"${name}" matched ${matches.length} time(s) in content served by the target.`,
        evidence: `${matches.length} match(es), first: ${matches[0].slice(0, 100)}`,
        remediation: 'Investigate the detected patterns and remove if malicious.',
      });
    }
  }

  if (findings.length === 0) {
    findings.push('No suspicious patterns detected in served content');
  }
  findings.push('File-based YARA rule matching requires the Termux agent (pkg install yara)');

  return { findings, vulnerabilities };
}
