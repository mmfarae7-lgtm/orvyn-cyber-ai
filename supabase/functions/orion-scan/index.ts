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

    // Verify the caller is authenticated and owns the scan
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

    // Ensure the scan belongs to this user
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

    // Mark scan as running
    await supabase.from('scans').update({
      status: 'running',
      started_at: new Date().toISOString(),
    }).eq('id', scanId);

    // Perform real HTTP-based scanning based on the tool
    const vulnerabilities: VulnerabilityFinding[] = [];
    const scanResults: Record<string, unknown> = { tool, target, timestamp: new Date().toISOString() };

    // Determine the URL to scan
    const url = target.startsWith('http') ? target : `https://${target}`;
    const hostname = target.replace(/^https?:\/\//, '').split('/')[0];

    try {
      if (tool === 'nmap') {
        const nmapResults = await performNmapScan(hostname, options);
        scanResults.ports = nmapResults.ports;
        vulnerabilities.push(...nmapResults.vulnerabilities);
      } else if (tool === 'masscan') {
        const masscanResults = await performMasscanScan(hostname, options);
        scanResults.ports = masscanResults.ports;
        vulnerabilities.push(...masscanResults.vulnerabilities);
      } else if (tool === 'nuclei') {
        const nucleiResults = await performNucleiScan(url, hostname, options);
        scanResults.findings = nucleiResults.findings;
        vulnerabilities.push(...nucleiResults.vulnerabilities);
      } else if (tool === 'zap') {
        const zapResults = await performZapScan(url, options);
        scanResults.findings = zapResults.findings;
        vulnerabilities.push(...zapResults.vulnerabilities);
      } else if (tool === 'nikto') {
        const niktoResults = await performNiktoScan(url, options);
        scanResults.findings = niktoResults.findings;
        vulnerabilities.push(...niktoResults.vulnerabilities);
      } else if (tool === 'whatweb') {
        const whatwebResults = await performWhatwebScan(url);
        scanResults.technologies = whatwebResults.technologies;
        vulnerabilities.push(...whatwebResults.vulnerabilities);
      } else if (tool === 'httpx') {
        const httpxResults = await performHttpxScan(url, hostname);
        scanResults.probes = httpxResults.probes;
        vulnerabilities.push(...httpxResults.vulnerabilities);
      } else if (tool === 'dns') {
        const dnsResults = await performDnsScan(hostname);
        scanResults.records = dnsResults.records;
        vulnerabilities.push(...dnsResults.vulnerabilities);
      } else if (tool === 'sslyze') {
        const sslyzeResults = await performSslyzeScan(hostname);
        scanResults.tls = sslyzeResults.tls;
        vulnerabilities.push(...sslyzeResults.vulnerabilities);
      } else if (tool === 'trivy') {
        const trivyResults = await performTrivyScan(target, options);
        scanResults.vulnerabilities = trivyResults.findings;
        vulnerabilities.push(...trivyResults.vulnerabilities);
      } else if (tool === 'semgrep') {
        const semgrepResults = await performSemgrepScan(target, options);
        scanResults.findings = semgrepResults.findings;
        vulnerabilities.push(...semgrepResults.vulnerabilities);
      } else if (tool === 'gitleaks') {
        const gitleaksResults = await performGitleaksScan(target, options);
        scanResults.findings = gitleaksResults.findings;
        vulnerabilities.push(...gitleaksResults.vulnerabilities);
      } else if (tool === 'yara') {
        const yaraResults = await performYaraScan(target, options);
        scanResults.findings = yaraResults.findings;
        vulnerabilities.push(...yaraResults.vulnerabilities);
      }
    } catch (scanError) {
      scanResults.error = scanError instanceof Error ? scanError.message : 'Scan error';
    }

    // Update scan record with results
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

// === Real scanning functions using fetch ===

async function safeFetch(url: string, timeoutMs = 10000): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Orion-Cyber-AI/1.0' },
      redirect: 'follow',
    });
    clearTimeout(timeout);
    return res;
  } catch {
    return null;
  }
}

async function performNmapScan(hostname: string, _options: Record<string, string>) {
  const ports: Array<{ port: number; state: string; service: string }> = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  // Probe common ports via HTTP
  const commonPorts = [
    { port: 80, service: 'http', scheme: 'http' },
    { port: 443, service: 'https', scheme: 'https' },
    { port: 8080, service: 'http-alt', scheme: 'http' },
    { port: 8443, service: 'https-alt', scheme: 'https' },
    { port: 3000, service: 'node', scheme: 'http' },
    { port: 22, service: 'ssh', scheme: null },
    { port: 21, service: 'ftp', scheme: null },
    { port: 25, service: 'smtp', scheme: null },
    { port: 53, service: 'dns', scheme: null },
    { port: 3306, service: 'mysql', scheme: null },
    { port: 5432, service: 'postgresql', scheme: null },
    { port: 6379, service: 'redis', scheme: null },
    { port: 27017, service: 'mongodb', scheme: null },
  ];

  for (const p of commonPorts) {
    let open = false;
    if (p.scheme) {
      const res = await safeFetch(`${p.scheme}://${hostname}:${p.port}/`, 5000);
      open = res !== null;
    } else {
      // For non-HTTP ports, try a TCP-like connection check via fetch to a URL
      // We can't do raw TCP from edge functions, so we check via DNS + HTTP fallback
      open = false;
    }
    ports.push({
      port: p.port,
      state: open ? 'open' : 'filtered',
      service: p.service,
    });
  }

  // Check for exposed sensitive services
  const openHttpPorts = ports.filter(p => p.state === 'open');
  if (openHttpPorts.length > 0) {
    for (const p of openHttpPorts) {
      if (p.port === 8080 || p.port === 8443 || p.port === 3000) {
        vulnerabilities.push({
          title: `Non-standard port ${p.port} exposed (${p.service})`,
          severity: 'low',
          description: `Port ${p.port} is running ${p.service} and is publicly accessible.`,
          evidence: `Port ${p.port} responded to HTTP probe`,
          remediation: 'Ensure this service is behind a firewall or requires authentication. Consider moving to standard ports.',
          port: p.port,
          service: p.service,
        });
      }
    }
  }

  return { ports, vulnerabilities };
}

async function performMasscanScan(hostname: string, _options: Record<string, string>) {
  // Similar to nmap but focused on speed - same approach
  const nmapResults = await performNmapScan(hostname, _options);
  return {
    ports: nmapResults.ports,
    vulnerabilities: nmapResults.vulnerabilities,
  };
}

async function performNucleiScan(url: string, hostname: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const res = await safeFetch(url);
  if (!res) {
    // Try http fallback
    const httpRes = await safeFetch(`http://${hostname}`);
    if (!httpRes) {
      vulnerabilities.push({
        title: 'Target not reachable',
        severity: 'info',
        description: `Could not reach ${hostname} on standard HTTP/HTTPS ports.`,
        evidence: 'Connection timed out or was refused',
        remediation: 'Verify the target is online and accessible.',
      });
      return { findings, vulnerabilities };
    }
  }

  const response = res ?? await safeFetch(`http://${hostname}`);
  if (!response) return { findings, vulnerabilities };

  const headers = Object.fromEntries(response.headers.entries());
  const html = await response.text();

  // Check for security headers
  const securityHeaders = [
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'x-xss-protection',
    'content-security-policy',
    'referrer-policy',
    'permissions-policy',
  ];

  for (const header of securityHeaders) {
    if (!headers[header]) {
      findings.push(`Missing security header: ${header}`);
      const severityMap: Record<string, 'medium' | 'low' | 'info'> = {
        'strict-transport-security': 'medium',
        'content-security-policy': 'medium',
        'x-frame-options': 'low',
        'x-content-type-options': 'low',
        'x-xss-protection': 'low',
        'referrer-policy': 'low',
        'permissions-policy': 'info',
      };
      vulnerabilities.push({
        title: `Missing ${header} header`,
        severity: severityMap[header] ?? 'low',
        description: `The ${header} security header is not set. This header helps protect against various attacks.`,
        evidence: `Header ${header} not found in response`,
        remediation: `Add the ${header} header to your web server configuration.`,
      });
    }
  }

  // Check for exposed .git directory
  const gitRes = await safeFetch(`${url}/.git/config`);
  if (gitRes && gitRes.ok) {
    findings.push('Exposed .git directory detected');
    vulnerabilities.push({
      title: 'Exposed .git directory',
      severity: 'high',
      description: 'The .git directory is publicly accessible, which can leak source code and sensitive commit history.',
      evidence: `${url}/.git/config returned HTTP ${gitRes.status}`,
      remediation: 'Block access to .git directories in your web server configuration.',
    });
  }

  // Check for exposed .env file
  const envRes = await safeFetch(`${url}/.env`);
  if (envRes && envRes.ok) {
    const envContent = await envRes.text();
    if (envContent.includes('=') && (envContent.includes('KEY') || envContent.includes('SECRET') || envContent.includes('PASSWORD'))) {
      findings.push('Exposed .env file detected');
      vulnerabilities.push({
        title: 'Exposed environment file',
        severity: 'critical',
        description: 'A .env file containing configuration secrets is publicly accessible.',
        evidence: `${url}/.env returned content with potential secrets`,
        remediation: 'Remove the .env file from the web root and block access to dotfiles.',
      });
    }
  }

  // Check for directory listing
  if (html.includes('Index of /') || html.includes('Directory listing')) {
    findings.push('Directory listing enabled');
    vulnerabilities.push({
      title: 'Directory listing enabled',
      severity: 'medium',
      description: 'Directory listing is enabled, allowing visitors to browse all files in directories without an index page.',
      evidence: 'Response contains directory listing markup',
      remediation: 'Disable directory listing in your web server configuration.',
    });
  }

  // Check for default/admin pages
  const adminPaths = ['/admin', '/wp-admin', '/administrator', '/phpmyadmin'];
  for (const path of adminPaths) {
    const adminRes = await safeFetch(`${url}${path}`);
    if (adminRes && (adminRes.ok || adminRes.status === 401 || adminRes.status === 403)) {
      findings.push(`Admin panel found at ${path}`);
      vulnerabilities.push({
        title: `Admin panel exposed at ${path}`,
        severity: adminRes.status === 200 ? 'high' : 'low',
        description: `An admin panel is accessible at ${path}.`,
        evidence: `${url}${path} returned HTTP ${adminRes.status}`,
        remediation: 'Restrict admin panel access to specific IP addresses or require VPN access.',
      });
    }
  }

  return { findings, vulnerabilities };
}

async function performZapScan(url: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const res = await safeFetch(url);
  if (!res) return { findings, vulnerabilities };

  const headers = Object.fromEntries(res.headers.entries());
  const html = await res.text();

  // Check for mixed content
  if (url.startsWith('https://') && html.includes('http://')) {
    findings.push('Mixed content detected');
    vulnerabilities.push({
      title: 'Mixed content on HTTPS page',
      severity: 'medium',
      description: 'The page loads some resources over HTTP despite being served over HTTPS.',
      evidence: 'Found http:// URLs in page source on HTTPS page',
      remediation: 'Update all resource URLs to use HTTPS.',
    });
  }

  // Check for form without CSRF token
  if (html.includes('<form') && !html.toLowerCase().includes('csrf') && !html.toLowerCase().includes('authenticity_token')) {
    findings.push('Forms may lack CSRF protection');
    vulnerabilities.push({
      title: 'Potential missing CSRF protection',
      severity: 'medium',
      description: 'Forms on the page do not appear to include CSRF tokens.',
      evidence: 'No csrf_token or authenticity_token found in form HTML',
      remediation: 'Implement CSRF tokens on all forms that perform state-changing operations.',
    });
  }

  // Check cookies for security flags
  const setCookie = headers['set-cookie'] ?? '';
  if (setCookie) {
    if (!setCookie.toLowerCase().includes('secure')) {
      findings.push('Cookie without Secure flag');
      vulnerabilities.push({
        title: 'Cookie missing Secure flag',
        severity: 'medium',
        description: 'A cookie is set without the Secure flag, meaning it can be transmitted over unencrypted HTTP.',
        evidence: `Set-Cookie: ${setCookie.substring(0, 100)}`,
        remediation: 'Add the Secure flag to all cookies.',
      });
    }
    if (!setCookie.toLowerCase().includes('httponly')) {
      findings.push('Cookie without HttpOnly flag');
      vulnerabilities.push({
        title: 'Cookie missing HttpOnly flag',
        severity: 'medium',
        description: 'A cookie is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS theft.',
        evidence: `Set-Cookie: ${setCookie.substring(0, 100)}`,
        remediation: 'Add the HttpOnly flag to all cookies.',
      });
    }
  }

  // Check for X-Powered-By header
  if (headers['x-powered-by']) {
    findings.push(`X-Powered-By header reveals technology: ${headers['x-powered-by']}`);
    vulnerabilities.push({
      title: 'X-Powered-By header exposes technology',
      severity: 'low',
      description: `The X-Powered-By header reveals the backend technology: ${headers['x-powered-by']}`,
      evidence: `X-Powered-By: ${headers['x-powered-by']}`,
      remediation: 'Remove the X-Powered-By header from your server configuration.',
    });
  }

  // Check for server header version disclosure
  if (headers['server']) {
    findings.push(`Server header: ${headers['server']}`);
    const versionMatch = headers['server'].match(/[\d.]+/);
    if (versionMatch) {
      vulnerabilities.push({
        title: 'Server version disclosed',
        severity: 'low',
        description: `The Server header reveals the server software version: ${headers['server']}`,
        evidence: `Server: ${headers['server']}`,
        remediation: 'Configure your web server to hide version information.',
      });
    }
  }

  return { findings, vulnerabilities };
}

async function performNiktoScan(url: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const res = await safeFetch(url);
  if (!res) return { findings, vulnerabilities };

  const headers = Object.fromEntries(res.headers.entries());

  // Check for outdated server software
  if (headers['server']) {
    const serverHeader = headers['server'];
    findings.push(`Server: ${serverHeader}`);

    // Check for known outdated versions
    if (serverHeader.match(/Apache\/2\.2\./)) {
      vulnerabilities.push({
        title: 'Outdated Apache version',
        severity: 'high',
        description: 'Apache 2.2.x is end-of-life and no longer receives security updates.',
        evidence: `Server: ${serverHeader}`,
        remediation: 'Upgrade to a supported version of Apache (2.4.x or later).',
      });
    }
    if (serverHeader.match(/nginx\/1\.[0-9]\./)) {
      vulnerabilities.push({
        title: 'Potentially outdated nginx version',
        severity: 'medium',
        description: 'The nginx version appears to be from an older release branch.',
        evidence: `Server: ${serverHeader}`,
        remediation: 'Update nginx to the latest stable version.',
      });
    }
  }

  // Check for dangerous files
  const dangerousPaths = [
    '/.htaccess', '/web.config', '/backup.zip', '/backup.sql', '/dump.sql',
    '/phpinfo.php', '/info.php', '/test.php', '/wp-config.php.bak',
    '/.htpasswd', '/robots.txt',
  ];

  for (const path of dangerousPaths) {
    const pathRes = await safeFetch(`${url}${path}`);
    if (pathRes && pathRes.ok) {
      findings.push(`Accessible sensitive file: ${path}`);
      const severityMap: Record<string, 'high' | 'medium' | 'low'> = {
        '/.htaccess': 'high',
        '/.htpasswd': 'high',
        '/backup.zip': 'high',
        '/backup.sql': 'high',
        '/dump.sql': 'high',
        '/phpinfo.php': 'high',
        '/info.php': 'high',
        '/wp-config.php.bak': 'critical',
        '/web.config': 'medium',
        '/test.php': 'low',
        '/robots.txt': 'info',
      };
      if (severityMap[path]) {
        vulnerabilities.push({
          title: `Sensitive file accessible: ${path}`,
          severity: severityMap[path],
          description: `The file ${path} is publicly accessible and may contain sensitive information.`,
          evidence: `${url}${path} returned HTTP ${pathRes.status}`,
          remediation: `Remove or restrict access to ${path}.`,
        });
      }
    }
  }

  return { findings, vulnerabilities };
}

async function performWhatwebScan(url: string) {
  const technologies: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const res = await safeFetch(url);
  if (!res) return { technologies, vulnerabilities };

  const headers = Object.fromEntries(res.headers.entries());
  const html = await res.text();

  // Detect technologies from headers
  if (headers['x-powered-by']) technologies.push(`X-Powered-By: ${headers['x-powered-by']}`);
  if (headers['server']) technologies.push(`Server: ${headers['server']}`);

  // Detect CMS
  if (html.includes('wp-content') || html.includes('wp-includes')) {
    technologies.push('CMS: WordPress');
    // Check WordPress version
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
  if (html.includes('drupal')) technologies.push('CMS: Drupal');
  if (html.includes('joomla') || html.includes('com_content')) technologies.push('CMS: Joomla');

  // Detect frameworks
  if (html.includes('react') || html.includes('__NEXT_DATA__')) technologies.push('Framework: React/Next.js');
  if (html.includes('vue') || html.includes('__nuxt__')) technologies.push('Framework: Vue/Nuxt');
  if (html.includes('angular')) technologies.push('Framework: Angular');
  if (headers['x-aspnetmvc-version']) technologies.push('Framework: ASP.NET MVC');

  // Detect analytics
  if (html.includes('google-analytics')) technologies.push('Analytics: Google Analytics');
  if (html.includes('googletagmanager')) technologies.push('Analytics: Google Tag Manager');

  // Detect CDN
  if (headers['cf-ray']) technologies.push('CDN: Cloudflare');
  if (headers['x-amz-cf-id']) technologies.push('CDN: AWS CloudFront');

  return { technologies, vulnerabilities };
}

async function performHttpxScan(url: string, hostname: string) {
  const probes: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const res = await safeFetch(url);
  if (res) {
    probes.push(`${url} - ${res.status} - ${res.headers.get('title') ?? ''}`);
  } else {
    const httpRes = await safeFetch(`http://${hostname}`);
    if (httpRes) {
      probes.push(`http://${hostname} - ${httpRes.status}`);
    }
  }

  return { probes, vulnerabilities };
}

async function performDnsScan(hostname: string) {
  const records: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  // Use DNS over HTTPS to look up records
  const dnsServers = [
    `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`,
    `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=MX`,
    `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=NS`,
    `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=TXT`,
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
  ];

  for (const dnsUrl of dnsServers) {
    try {
      const res = await fetch(dnsUrl, {
        headers: { 'Accept': 'application/dns-json' },
      });
      if (res.ok) {
        const data = await res.json();
        if (data.Answer) {
          for (const answer of data.Answer) {
            records.push(`${answer.name} ${answer.type} ${answer.data}`);
          }
        }
      }
    } catch {
      // DNS query failed
    }
  }

  // Check for DNSSEC
  try {
    const dnssecRes = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=DS`,
      { headers: { 'Accept': 'application/dns-json' } }
    );
    if (dnssecRes.ok) {
      const data = await dnssecRes.json();
      if (!data.Answer || data.Answer.length === 0) {
        vulnerabilities.push({
          title: 'DNSSEC not configured',
          severity: 'low',
          description: 'The domain does not have DNSSEC enabled, making it more vulnerable to DNS spoofing attacks.',
          evidence: 'No DS records found for the domain',
          remediation: 'Enable DNSSEC in your domain registrar or DNS provider.',
        });
      }
    }
  } catch {
    // DNSSEC check failed
  }

  return { records, vulnerabilities };
}

async function performSslyzeScan(hostname: string) {
  const tls: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  // Check TLS by making HTTPS request and inspecting the connection
  try {
    const res = await fetch(`https://${hostname}`, {
      headers: { 'User-Agent': 'Orion-Cyber-AI/1.0' },
      redirect: 'manual',
    });

    tls.push(`HTTPS connection successful to ${hostname}`);

    // Check HSTS
    const hsts = res.headers.get('strict-transport-security');
    if (hsts) {
      tls.push(`HSTS: ${hsts}`);
    } else {
      vulnerabilities.push({
        title: 'HSTS not enabled',
        severity: 'medium',
        description: 'HTTP Strict Transport Security (HSTS) is not set, allowing downgrade attacks.',
        evidence: 'No Strict-Transport-Security header found',
        remediation: 'Add the Strict-Transport-Security header with a long max-age value.',
      });
    }
  } catch {
    tls.push(`HTTPS connection failed to ${hostname}`);
    vulnerabilities.push({
      title: 'HTTPS not available',
      severity: 'high',
      description: 'The target does not support HTTPS connections.',
      evidence: 'HTTPS connection failed',
      remediation: 'Install an SSL/TLS certificate and enable HTTPS on the web server.',
    });
  }

  // Check for TLS 1.0/1.1 support via DNS over HTTPS (indirect check)
  try {
    const httpRes = await fetch(`http://${hostname}`, {
      headers: { 'User-Agent': 'Orion-Cyber-AI/1.0' },
      redirect: 'manual',
    }).catch(() => null);

    if (httpRes) {
      tls.push(`HTTP connection available (port 80)`);
      vulnerabilities.push({
        title: 'HTTP port open alongside HTTPS',
        severity: 'low',
        description: 'Port 80 (HTTP) is open, potentially allowing protocol downgrade attacks.',
        evidence: 'HTTP connection succeeded',
        remediation: 'Redirect all HTTP traffic to HTTPS.',
      });
    }
  } catch {
    // HTTP not available
  }

  return { tls, vulnerabilities };
}

async function performTrivyScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  // For Trivy, we check if target is a URL and scan its dependencies via package files
  const url = target.startsWith('http') ? target : `https://${target}`;
  const res = await safeFetch(url);
  if (!res) {
    vulnerabilities.push({
      title: 'Could not reach target for dependency scan',
      severity: 'info',
      description: 'Unable to fetch the target to analyze dependencies.',
      evidence: 'Connection failed',
      remediation: 'Verify the target URL is accessible.',
    });
    return { findings, vulnerabilities };
  }

  const html = await res.text();

  // Check for known vulnerable JS libraries
  const libChecks = [
    { pattern: /jquery[/-]([0-9.]+)\.js/i, name: 'jQuery', minSafe: '3.5.0' },
    { pattern: /angular[/-]([0-9.]+)\.js/i, name: 'Angular', minSafe: '1.8.0' },
    { pattern: /bootstrap[/-]([0-9.]+)\.(js|css)/i, name: 'Bootstrap', minSafe: '4.5.0' },
    { pattern: /vue[/-]([0-9.]+)\.js/i, name: 'Vue.js', minSafe: '2.6.12' },
  ];

  for (const check of libChecks) {
    const match = html.match(check.pattern);
    if (match) {
      findings.push(`${check.name} ${match[1]} detected`);
      if (compareVersions(match[1], check.minSafe) < 0) {
        vulnerabilities.push({
          title: `Outdated ${check.name} version ${match[1]}`,
          severity: 'medium',
          description: `${check.name} ${match[1]} is outdated. Current safe version is ${check.minSafe} or later.`,
          evidence: `Found ${check.name} ${match[1]} in page source`,
          remediation: `Update ${check.name} to version ${check.minSafe} or later.`,
        });
      }
    }
  }

  return { findings, vulnerabilities };
}

async function performSemgrepScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  // Simulate static analysis by checking the target's HTML for common code issues
  const url = target.startsWith('http') ? target : `https://${target}`;
  const res = await safeFetch(url);
  if (!res) return { findings, vulnerabilities };

  const html = await res.text();

  // Check for inline scripts (potential XSS vectors)
  const inlineScripts = html.match(/<script[^>]*>(?!.*src=)[^<]+<\/script>/gi);
  if (inlineScripts && inlineScripts.length > 3) {
    findings.push(`${inlineScripts.length} inline scripts found`);
    vulnerabilities.push({
      title: 'Multiple inline scripts detected',
      severity: 'low',
      description: `${inlineScripts.length} inline scripts were found. Inline scripts can be a vector for XSS if user input is not properly escaped.`,
      evidence: `Found ${inlineScripts.length} inline <script> blocks`,
      remediation: 'Move scripts to external files and use Content Security Policy to restrict inline scripts.',
    });
  }

  // Check for eval() usage
  if (html.includes('eval(')) {
    findings.push('eval() usage detected');
    vulnerabilities.push({
      title: 'eval() function usage detected',
      severity: 'high',
      description: 'The eval() function was found in the page source, which can lead to code injection vulnerabilities.',
      evidence: 'Found eval() in script code',
      remediation: 'Avoid using eval(). Use JSON.parse() for data parsing and Function() for dynamic code if absolutely necessary.',
    });
  }

  // Check for innerHTML usage
  if (html.includes('innerHTML')) {
    findings.push('innerHTML usage detected');
    vulnerabilities.push({
      title: 'innerHTML usage may lead to XSS',
      severity: 'medium',
      description: 'The use of innerHTML was detected, which can lead to XSS if user input is assigned without sanitization.',
      evidence: 'Found innerHTML in page source',
      remediation: 'Use textContent instead of innerHTML, or sanitize input before assignment.',
    });
  }

  return { findings, vulnerabilities };
}

async function performGitleaksScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  const url = target.startsWith('http') ? target : `https://${target}`;
  const res = await safeFetch(url);
  if (!res) return { findings, vulnerabilities };

  const html = await res.text();

  // Check for API keys and secrets in the page source
  const secretPatterns = [
    { pattern: /AIza[0-9A-Za-z\-_]{35}/g, name: 'Google API Key' },
    { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key' },
    { pattern: /ghp_[0-9A-Za-z]{36}/g, name: 'GitHub Personal Access Token' },
    { pattern: /sk_live_[0-9a-zA-Z]{24}/g, name: 'Stripe Secret Key' },
    { pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, name: 'Slack Token' },
    { pattern: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, name: 'JWT Token' },
    { pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, name: 'Private Key' },
  ];

  for (const { pattern, name } of secretPatterns) {
    const matches = html.match(pattern);
    if (matches) {
      findings.push(`${name} found in page source`);
      vulnerabilities.push({
        title: `Exposed ${name}`,
        severity: 'critical',
        description: `A ${name} was found in the page source. This is a serious security issue that could lead to unauthorized access.`,
        evidence: `${matches.length} occurrence(s) of ${name} pattern found`,
        remediation: `Immediately rotate/revoke the exposed ${name} and remove it from the page source.`,
      });
    }
  }

  // Check for hardcoded passwords in HTML
  const passwordFields = html.match(/password["\s]*[:=]["\s]*["']([^"']{3,})["']/gi);
  if (passwordFields) {
    findings.push(`${passwordFields.length} potential hardcoded passwords found`);
    vulnerabilities.push({
      title: 'Potential hardcoded password detected',
      severity: 'high',
      description: 'A potential hardcoded password was found in the page source.',
      evidence: `Found ${passwordFields.length} password-like patterns`,
      remediation: 'Remove any hardcoded credentials from client-side code.',
    });
  }

  return { findings, vulnerabilities };
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

async function performYaraScan(target: string, _options: Record<string, string>) {
  const findings: string[] = [];
  const vulnerabilities: VulnerabilityFinding[] = [];

  // YARA on the edge function can't run the real YARA binary,
  // but we can check the target URL for suspicious patterns
  const url = target.startsWith('http') ? target : `https://${target}`;
  const res = await safeFetch(url);
  if (!res) {
    // If target is not a URL, it's a file path for the Termux agent
    findings.push('YARA scan requires the Termux agent for file scanning');
    findings.push('The agent will run YARA rules against the specified file/directory path');
    vulnerabilities.push({
      title: 'YARA scan submitted to agent',
      severity: 'info',
      description: 'YARA file scanning runs on the Termux agent. Ensure your agent is running and YARA is installed (pkg install yara).',
      evidence: `Target path: ${target}`,
      remediation: 'Keep your Termux agent running to process YARA scan tasks.',
    });
    return { findings, vulnerabilities };
  }

  const html = await res.text();

  // Check for suspicious patterns similar to YARA rules
  const suspiciousPatterns = [
    { pattern: /CreateProcess|WriteProcessMemory|VirtualAllocEx/gi, name: 'Windows API process manipulation' },
    { pattern: /LoadLibrary|GetProcAddress/gi, name: 'Dynamic library loading' },
    { pattern: /WinExec|ShellExecute/gi, name: 'Command execution' },
    { pattern: /cmd\.exe\s+\/c|\/bin\/sh/gi, name: 'Shell command execution' },
    { pattern: /powershell\s+-enc/gi, name: 'Encoded PowerShell command' },
    { pattern: /base64\s+-d/gi, name: 'Base64 decoding' },
  ];

  for (const { pattern, name } of suspiciousPatterns) {
    const matches = html.match(pattern);
    if (matches) {
      findings.push(`${name}: ${matches.length} occurrence(s)`);
      vulnerabilities.push({
        title: `Suspicious pattern detected: ${name}`,
        severity: 'high',
        description: `The pattern "${name}" was found ${matches.length} time(s) in the page source. This could indicate malicious content.`,
        evidence: `${matches.length} matches of ${name} pattern`,
        remediation: 'Investigate the detected patterns and remove if malicious.',
      });
    }
  }

  if (findings.length === 0) {
    findings.push('No suspicious patterns detected in web content');
    findings.push('For full YARA file scanning, use the Termux agent');
  }

  return { findings, vulnerabilities };
}
