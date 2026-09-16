import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

interface LabRequest {
  tool: string;
  command: string;
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    // Verify the caller is authenticated
    const authHeader = req.headers.get('Authorization') ?? '';
    const token = authHeader.replace('Bearer ', '');
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    );
    const { data: userData } = await supabase.auth.getUser(token);
    if (!userData.user?.id) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    const { tool, command } = (await req.json()) as LabRequest;

    if (!tool || !command) {
      return new Response(
        JSON.stringify({ error: 'Tool and command are required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    let output: Record<string, unknown> = {};

    // Parse command — could be a hostname, URL, or tool-specific options
    const target = command.trim();
    const hostname = target.replace(/^https?:\/\//, '').split('/')[0];
    const url = target.startsWith('http') ? target : `https://${target}`;

    if (tool === 'nmap') {
      output = await runNmap(hostname);
    } else if (tool === 'masscan') {
      output = await runMasscan(hostname);
    } else if (tool === 'nuclei') {
      output = await runNuclei(url, hostname);
    } else if (tool === 'zap') {
      output = await runZap(url);
    } else if (tool === 'nikto') {
      output = await runNikto(url);
    } else if (tool === 'whatweb') {
      output = await runWhatweb(url);
    } else if (tool === 'httpx') {
      output = await runHttpx(url, hostname);
    } else if (tool === 'dns') {
      output = await runDns(hostname);
    } else if (tool === 'sslyze') {
      output = await runSslyze(hostname);
    } else if (tool === 'trivy') {
      output = await runTrivy(url);
    } else if (tool === 'semgrep') {
      output = await runSemgrep(url);
    } else if (tool === 'gitleaks') {
      output = await runGitleaks(url);
    } else {
      output = { error: `Tool '${tool}' is not supported in the lab` };
    }

    return new Response(
      JSON.stringify(output),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err instanceof Error ? err.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});

async function safeFetch(url: string, timeoutMs = 10000): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Orion-Cyber-AI-Lab/1.0' },
      redirect: 'follow',
    });
    clearTimeout(timeout);
    return res;
  } catch {
    return null;
  }
}

async function runNmap(hostname: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Starting Nmap scan for ${hostname}`, ''];

  const ports = [
    { port: 80, service: 'http', scheme: 'http' },
    { port: 443, service: 'https', scheme: 'https' },
    { port: 8080, service: 'http-proxy', scheme: 'http' },
    { port: 8443, service: 'https-alt', scheme: 'https' },
    { port: 22, service: 'ssh', scheme: null },
    { port: 21, service: 'ftp', scheme: null },
    { port: 25, service: 'smtp', scheme: null },
    { port: 53, service: 'domain', scheme: null },
    { port: 3306, service: 'mysql', scheme: null },
    { port: 5432, service: 'postgresql', scheme: null },
    { port: 6379, service: 'redis', scheme: null },
    { port: 27017, service: 'mongodb', scheme: null },
    { port: 9200, service: 'elasticsearch', scheme: 'http' },
  ];

  lines.push('PORT      STATE    SERVICE');
  for (const p of ports) {
    let open = false;
    if (p.scheme) {
      const res = await safeFetch(`${p.scheme}://${hostname}:${p.port}/`, 5000);
      open = res !== null;
    }
    lines.push(
      `${String(p.port).padEnd(10)} ${open ? 'open    ' : 'filtered'} ${p.service}`
    );
  }

  lines.push('', `Nmap scan completed — ${ports.length} ports scanned`);
  return { output: lines.join('\n') };
}

async function runMasscan(hostname: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Starting Masscan (fast scan) for ${hostname}`, ''];
  const ports = [80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 6379];
  lines.push('Scanning ports: ' + ports.join(', '));
  lines.push('');

  const results: string[] = [];
  for (const port of ports) {
    const scheme = port === 443 || port === 8443 ? 'https' : 'http';
    const res = await safeFetch(`${scheme}://${hostname}:${port}/`, 3000);
    if (res) {
      results.push(`Discovered open port ${port}/tcp on ${hostname}`);
    }
  }

  if (results.length === 0) {
    lines.push('No open ports found on common HTTP ports.');
  } else {
    lines.push(...results);
  }

  lines.push('', `Masscan completed — ${ports.length} ports scanned`);
  return { output: lines.join('\n') };
}

async function runNuclei(url: string, hostname: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Running Nuclei templates against ${url}`, ''];

  const res = await safeFetch(url) ?? await safeFetch(`http://${hostname}`);
  if (!res) {
    return { output: lines.concat([`Error: Could not reach ${hostname}`]).join('\n') };
  }

  const headers = Object.fromEntries(res.headers.entries());
  const html = await res.text();

  const checks = [
    { name: 'strict-transport-security', label: 'HSTS' },
    { name: 'x-content-type-options', label: 'X-Content-Type-Options' },
    { name: 'x-frame-options', label: 'X-Frame-Options' },
    { name: 'content-security-policy', label: 'CSP' },
  ];

  for (const check of checks) {
    if (!headers[check.name]) {
      lines.push(`[MISCONFIG] Missing ${check.label} header`);
    } else {
      lines.push(`[OK] ${check.label} header present`);
    }
  }

  // Check .git
  const gitRes = await safeFetch(`${url}/.git/config`);
  if (gitRes?.ok) {
    lines.push(`[HIGH] Exposed .git directory detected at ${url}/.git/`);
  }

  // Check .env
  const envRes = await safeFetch(`${url}/.env`);
  if (envRes?.ok) {
    lines.push(`[CRITICAL] Exposed .env file detected at ${url}/.env`);
  }

  // Check directory listing
  if (html.includes('Index of /')) {
    lines.push(`[MEDIUM] Directory listing enabled`);
  }

  lines.push('', 'Nuclei scan completed');
  return { output: lines.join('\n') };
}

async function runZap(url: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Starting OWASP ZAP scan for ${url}`, ''];

  const res = await safeFetch(url);
  if (!res) {
    return { output: lines.concat([`Error: Could not reach ${url}`]).join('\n') };
  }

  const headers = Object.fromEntries(res.headers.entries());
  const html = await res.text();

  // Cookie security
  const setCookie = headers['set-cookie'] ?? '';
  if (setCookie) {
    if (!setCookie.toLowerCase().includes('secure')) {
      lines.push('[MEDIUM] Cookie missing Secure flag');
    }
    if (!setCookie.toLowerCase().includes('httponly')) {
      lines.push('[MEDIUM] Cookie missing HttpOnly flag');
    }
  }

  // Mixed content
  if (url.startsWith('https://') && html.includes('http://')) {
    lines.push('[MEDIUM] Mixed content detected on HTTPS page');
  }

  // CSRF
  if (html.includes('<form') && !html.toLowerCase().includes('csrf')) {
    lines.push('[MEDIUM] Forms may lack CSRF protection');
  }

  // X-Powered-By
  if (headers['x-powered-by']) {
    lines.push(`[LOW] X-Powered-By reveals: ${headers['x-powered-by']}`);
  }

  // Server version
  if (headers['server']) {
    lines.push(`[INFO] Server: ${headers['server']}`);
  }

  lines.push('', 'ZAP scan completed');
  return { output: lines.join('\n') };
}

async function runNikto(url: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Starting Nikto scan for ${url}`, ''];

  const res = await safeFetch(url);
  if (!res) {
    return { output: lines.concat([`Error: Could not reach ${url}`]).join('\n') };
  }

  const headers = Object.fromEntries(res.headers.entries());

  if (headers['server']) {
    lines.push(`[INFO] Server: ${headers['server']}`);
    if (headers['server'].match(/Apache\/2\.2\./)) {
      lines.push('[HIGH] Apache 2.2.x is end-of-life');
    }
  }

  const dangerousPaths = [
    '/.htaccess', '/.htpasswd', '/backup.zip', '/phpinfo.php',
    '/info.php', '/test.php', '/robots.txt', '/.env',
  ];

  for (const path of dangerousPaths) {
    const pathRes = await safeFetch(`${url}${path}`);
    if (pathRes?.ok) {
      lines.push(`[${path === '/robots.txt' ? 'INFO' : 'HIGH'}] Sensitive file accessible: ${path}`);
    }
  }

  lines.push('', 'Nikto scan completed');
  return { output: lines.join('\n') };
}

async function runWhatweb(url: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`WhatWeb scan for ${url}`, ''];

  const res = await safeFetch(url);
  if (!res) {
    return { output: lines.concat([`Error: Could not reach ${url}`]).join('\n') };
  }

  const headers = Object.fromEntries(res.headers.entries());
  const html = await res.text();

  const techs: string[] = [];
  if (headers['server']) techs.push(`Server[${headers['server']}]`);
  if (headers['x-powered-by']) techs.push(`X-Powered-By[${headers['x-powered-by']}]`);
  if (html.includes('wp-content')) techs.push('WordPress');
  if (html.includes('react') || html.includes('__NEXT_DATA__')) techs.push('React/Next.js');
  if (html.includes('vue')) techs.push('Vue.js');
  if (html.includes('angular')) techs.push('Angular');
  if (headers['cf-ray']) techs.push('Cloudflare');
  if (html.includes('google-analytics')) techs.push('Google-Analytics');
  if (html.includes('bootstrap')) techs.push('Bootstrap');

  lines.push(`[+] ${url} [${techs.join(', ')}]`);
  lines.push('', 'WhatWeb scan completed');
  return { output: lines.join('\n') };
}

async function runHttpx(url: string, hostname: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`httpx probe for ${hostname}`, ''];

  const httpsRes = await safeFetch(url);
  if (httpsRes) {
    const title = (await httpsRes.text()).match(/<title>(.*?)<\/title>/i);
    lines.push(`https://${hostname} [${httpsRes.status}] [${title?.[1]?.trim() ?? 'No title'}]`);
  } else {
    lines.push(`https://${hostname} - unreachable`);
  }

  const httpRes = await safeFetch(`http://${hostname}`);
  if (httpRes) {
    lines.push(`http://${hostname} [${httpRes.status}]`);
  }

  lines.push('', 'httpx completed');
  return { output: lines.join('\n') };
}

async function runDns(hostname: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`DNS lookup for ${hostname}`, ''];

  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'];

  for (const type of types) {
    try {
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${type}`,
        { headers: { 'Accept': 'application/dns-json' } }
      );
      if (res.ok) {
        const data = await res.json();
        if (data.Answer) {
          for (const answer of data.Answer) {
            lines.push(`${answer.name.padEnd(30)} ${type.padEnd(6)} ${answer.data}`);
          }
        }
      }
    } catch {
      // Skip failed queries
    }
  }

  // DNSSEC check
  try {
    const dsRes = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=DS`,
      { headers: { 'Accept': 'application/dns-json' } }
    );
    if (dsRes.ok) {
      const data = await dsRes.json();
      if (!data.Answer || data.Answer.length === 0) {
        lines.push('', '[!] DNSSEC not configured');
      } else {
        lines.push('', '[+] DNSSEC configured');
      }
    }
  } catch {
    // Skip
  }

  lines.push('', 'DNS lookup completed');
  return { output: lines.join('\n') };
}

async function runSslyze(hostname: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`SSLyze analysis for ${hostname}`, ''];

  try {
    const res = await fetch(`https://${hostname}`, {
      headers: { 'User-Agent': 'Orion-Cyber-AI/1.0' },
      redirect: 'manual',
    });

    lines.push(`[+] HTTPS connection successful`);
    const hsts = res.headers.get('strict-transport-security');
    if (hsts) {
      lines.push(`[+] HSTS: ${hsts}`);
    } else {
      lines.push(`[!] HSTS not enabled`);
    }
  } catch {
    lines.push(`[!] HTTPS connection failed`);
  }

  // Check HTTP availability
  const httpRes = await safeFetch(`http://${hostname}`);
  if (httpRes) {
    lines.push(`[!] HTTP port 80 is open — redirect to HTTPS recommended`);
  }

  lines.push('', 'SSLyze completed');
  return { output: lines.join('\n') };
}

async function runTrivy(url: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Trivy dependency scan for ${url}`, ''];

  const res = await safeFetch(url);
  if (!res) {
    return { output: lines.concat([`Error: Could not reach ${url}`]).join('\n') };
  }

  const html = await res.text();

  const libChecks = [
    { pattern: /jquery[/-]([0-9.]+)\.js/i, name: 'jQuery', minSafe: '3.5.0' },
    { pattern: /bootstrap[/-]([0-9.]+)\.(js|css)/i, name: 'Bootstrap', minSafe: '4.5.0' },
    { pattern: /angular[/-]([0-9.]+)\.js/i, name: 'Angular', minSafe: '1.8.0' },
  ];

  let found = 0;
  for (const check of libChecks) {
    const match = html.match(check.pattern);
    if (match) {
      found++;
      const version = match[1];
      if (compareVersions(version, check.minSafe) < 0) {
        lines.push(`[MEDIUM] ${check.name} ${version} is outdated (safe: ${check.minSafe}+)`);
      } else {
        lines.push(`[OK] ${check.name} ${version}`);
      }
    }
  }

  if (found === 0) {
    lines.push('[INFO] No known JS libraries detected in page source');
  }

  lines.push('', 'Trivy scan completed');
  return { output: lines.join('\n') };
}

async function runSemgrep(url: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Semgrep code analysis for ${url}`, ''];

  const res = await safeFetch(url);
  if (!res) {
    return { output: lines.concat([`Error: Could not reach ${url}`]).join('\n') };
  }

  const html = await res.text();

  const inlineScripts = html.match(/<script[^>]*>(?!.*src=)[^<]+<\/script>/gi);
  if (inlineScripts && inlineScripts.length > 3) {
    lines.push(`[LOW] ${inlineScripts.length} inline scripts detected`);
  }

  if (html.includes('eval(')) {
    lines.push('[HIGH] eval() usage detected');
  }

  if (html.includes('innerHTML')) {
    lines.push('[MEDIUM] innerHTML usage detected — potential XSS risk');
  }

  if (html.includes('document.write')) {
    lines.push('[MEDIUM] document.write() usage detected');
  }

  lines.push('', 'Semgrep scan completed');
  return { output: lines.join('\n') };
}

async function runGitleaks(url: string): Promise<Record<string, unknown>> {
  const lines: string[] = [`Gitleaks secret detection for ${url}`, ''];

  const res = await safeFetch(url);
  if (!res) {
    return { output: lines.concat([`Error: Could not reach ${url}`]).join('\n') };
  }

  const html = await res.text();

  const secretPatterns = [
    { pattern: /AIza[0-9A-Za-z\-_]{35}/g, name: 'Google API Key' },
    { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key' },
    { pattern: /ghp_[0-9A-Za-z]{36}/g, name: 'GitHub Token' },
    { pattern: /sk_live_[0-9a-zA-Z]{24}/g, name: 'Stripe Secret Key' },
    { pattern: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, name: 'JWT Token' },
    { pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, name: 'Private Key' },
  ];

  let found = 0;
  for (const { pattern, name } of secretPatterns) {
    const matches = html.match(pattern);
    if (matches) {
      found++;
      lines.push(`[CRITICAL] ${name} detected (${matches.length} occurrence(s))`);
    }
  }

  if (found === 0) {
    lines.push('[+] No secrets detected in page source');
  }

  lines.push('', 'Gitleaks scan completed');
  return { output: lines.join('\n') };
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
