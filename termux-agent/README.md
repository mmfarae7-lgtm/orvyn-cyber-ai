# Orion Cyber AI - Agent Setup Guide

## What is the Orion Agent?

The Orion Agent is a lightweight script that runs on your device (Android/Termux, Kali Linux, Windows, or macOS) and connects to the Orion Cyber AI backend. It picks up scan tasks from the web app and runs real security tools locally, then sends the results back.

## Files

| File | Platform | Description |
|------|----------|-------------|
| `orion-agent.sh` | Termux / Kali Linux / macOS / Linux | Universal Bash agent |
| `orion-agent-windows.ps1` | Windows (PowerShell) | PowerShell agent |
| `orion-agent-windows.bat` | Windows (CMD) | CMD launcher for the PowerShell script |

---

## Installation

### Android (Termux)

```bash
# Install Termux from F-Droid (recommended) or Google Play
# Then install required tools:
pkg update
pkg install curl jq nmap nikto whatweb yara git

# Optional tools:
pip install httpx sslyze semgrep

# Make the agent executable:
chmod +x orion-agent.sh

# Run:
./orion-agent.sh
```

### Kali Linux

```bash
# Install required tools:
sudo apt update
sudo apt install curl jq nmap nikto whatweb yara git

# Optional tools:
sudo apt install masscan zaproxy trivy gitleaks
pip install httpx sslyze semgrep
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Make the agent executable:
chmod +x orion-agent.sh

# Run:
./orion-agent.sh
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install curl jq nmap nikto whatweb yara git
pip install httpx sslyze semgrep

chmod +x orion-agent.sh
./orion-agent.sh
```

### macOS (Homebrew)

```bash
brew install curl jq nmap nikto whatweb yara git
pip3 install httpx sslyze semgrep

chmod +x orion-agent.sh
./orion-agent.sh
```

### Windows

1. Install tools you want:
   - **Nmap**: https://nmap.org/download.html
   - **Python**: https://python.org (for pip tools)
   - **YARA**: https://github.com/VirusTotal/yara/releases
   - **Nuclei**: https://github.com/projectdiscovery/nuclei/releases
   - **Gitleaks**: https://github.com/gitleaks/gitleaks/releases
   - **Trivy**: https://github.com/aquasecurity/trivy/releases
   - **Semgrep**: `pip install semgrep`
   - **SSLyze**: `pip install sslyze`
   - **httpx**: `pip install httpx`

2. Add all installed tools to your Windows PATH

3. Run from CMD:
   ```
   orion-agent-windows.bat
   ```

   Or from PowerShell:
   ```
   powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1
   ```

---

## Available Security Tools

| Tool | What it does | Termux | Kali | Windows |
|------|-------------|--------|------|---------|
| Nmap | Port scanning & service detection | pkg install nmap | apt install nmap | nmap.org |
| Masscan | Fast port scanning | pkg install masscan | apt install masscan | - |
| Nuclei | Vulnerability scanner | nuclei install | go install | GitHub releases |
| Nikto | Web server scanner | pkg install nikto | apt install nikto | - |
| WhatWeb | Technology fingerprinting | pkg install whatweb | apt install whatweb | - |
| httpx | HTTP probing | pip install httpx | pip install httpx | pip install httpx |
| DNS | DNS enumeration | built-in (dig) | built-in (dig) | built-in (nslookup) |
| SSLyze | TLS/SSL analysis | pip install sslyze | pip install sslyze | pip install sslyze |
| ZAP | Web app scanner | pkg install zaproxy | apt install zaproxy | zaproxy.org |
| Trivy | Dependency scanner | - | apt install trivy | GitHub releases |
| Semgrep | Code analysis | pip install semgrep | pip install semgrep | pip install semgrep |
| Gitleaks | Secret detection | GitHub releases | apt install gitleaks | GitHub releases |
| YARA | Malware detection | pkg install yara | apt install yara | GitHub releases |

---

## YARA Setup

YARA is a pattern matching tool used for malware detection. The agent comes with built-in default rules that detect:

- Generic malware indicators (Windows API calls)
- Suspicious strings (shell commands, encoded payloads)
- Base64 encoded content
- C2 communication indicators

### Custom YARA Rules

You can provide your own YARA rules file:

**Termux/Linux/macOS:**
```bash
export ORION_YARA_RULES=/path/to/your/rules.yar
./orion-agent.sh
```

**Windows (PowerShell):**
```powershell
$env:ORION_YARA_RULES = "C:\path\to\your\rules.yar"
powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1
```

### Installing YARA

- **Termux**: `pkg install yara`
- **Kali**: `sudo apt install yara`
- **macOS**: `brew install yara`
- **Windows**: Download from https://github.com/VirusTotal/yara/releases

---

## Configuration

All settings have defaults but can be overridden with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ORION_SUPABASE_URL` | Orion backend URL | Backend URL |
| `ORION_ANON_KEY` | Pre-configured key | Supabase anon key |
| `ORION_AGENT_ID` | hostname-timestamp | Unique agent identifier |
| `ORION_POLL_INTERVAL` | 5 | Seconds between polls |
| `ORION_YARA_RULES` | ~/orion-yara-rules.yar | Custom YARA rules path |

---

## How It Works

1. The agent connects to the Orion backend
2. It polls for new scan tasks every 5 seconds
3. When a task arrives, it runs the specified security tool
4. Results are sent back to the backend
5. Results appear in the Orion web app under Vulnerabilities

You can launch scans from the Orion web app, and the agent on your device will execute them in real-time.

---

## Troubleshooting

**"jq not found"**
- Termux: `pkg install jq`
- Kali: `sudo apt install jq`
- macOS: `brew install jq`
- Windows: jq is not needed (PowerShell handles JSON natively)

**"curl not found"**
- Termux: `pkg install curl`
- Kali: `sudo apt install curl`
- macOS: `brew install curl`
- Windows: Included in Windows 10+

**Tool shows "not installed"**
- The agent checks if each tool is available before running it
- Install the tool using the commands in the table above
- Make sure the tool is in your PATH

**Cannot connect to backend**
- Check your internet connection
- Verify the backend URL is correct
- The default URL is pre-configured and should work

**YARA scan shows "Path not found"**
- For YARA scans, the target field should be a file or directory path on your device
- Example: `/sdcard/Download/` (Termux) or `C:\Users\Downloads\` (Windows)

---

## دليل الاستخدام بالعربية (Arabic Quick Start)

### كيف يعمل النظام كاملاً؟

1. سجّل دخولك على الموقع `orvyn.is-great.org` (أو من تطبيق أندرويد).
2. من صفحة **New Scan** اختر أداة (مثل Nmap أو WhatWeb)، أدخل الهدف (رابط أو IP)، ثم اضغط Launch.
3. المهمة تُحفظ في الخادم، وأساس **الـ Agent** المثبّت على جهازك يلتقطها خلال ثوانٍ وينفّذها بأدوات حقيقية.
4. النتائج تعود تلقائياً وتظهر في صفحة **Vulnerabilities**.

> **مهم**: الـ Agent يشغّل أدوات الفحص على **جهازك أنت** (موبايل/كمبيوتر)، بينما الموقع يدير المهام ويعرض النتائج. لا يمكن تنفيذ Nmap/Nikto وغيرها من الخادم مباشرة — لذلك تحتاج الـ Agent ليعمل فعلياً في حال اخترت هذه الأدوات.

---

### 📱 تشغيل الـ Agent من الجوال (Termux) — خطوة بخطوة

1. **نزّل تطبيق Termux** من F-Droid (النسخة الرسمية): https://f-droid.org/en/packages/com.termux/
2. افتحه وحدّث الحزم:
   ```bash
   pkg update && pkg upgrade
   ```
3. ثبّت الأدوات المطلوبة:
   ```bash
   pkg install curl jq nmap nikto whatweb yara git
   ```
4. انسخ ملف `orion-agent.sh` إلى الجوال (نزّله من GitHub هذا المجلد أو انقله عبر USB/بلوتوث).
5. اجعل الملف قابلاً للتنفيذ وشغّله:
   ```bash
   chmod +x orion-agent.sh
   ./orion-agent.sh
   ```
6. سترى رسالة "Agent started" ثم يبقى مفتوحاً ينتظر المهام. **لا تغلق Termux** أثناء انتظارك المسح.
7. عد للموقع، أطلق مسحاً، وشاهد النتيجة تظهر في صفحة **Vulnerabilities**.

> تلميح: إن أردته يعمل في الخلفية جرب داخل Termux:
> ```bash
> pkg install termux-services
> ```

---

### 💻 تشغيل الـ Agent من الكمبيوتر (Windows CMD) — خطوة بخطوة

1. نزّل الملفين التاليين إلى مجلد واحد:
   - `orion-agent-windows.bat`
   - `orion-agent-windows.ps1`
2. ثبّت الأدوات التي تريدها وأضفها لـ PATH:
   - **Nmap**: https://nmap.org/download.html
   - **Python**: https://python.org (لتثبيت httpx/sslyze وغيرها بـ `pip`)
   - **Git**: https://git-scm.com/download/win
3. افتح **CMD** في نفس المجلد (اختر المجلد ثم اكتب `cmd` في شريط العنوان واضغط Enter).
4. شغّل الأمر:
   ```cmd
   orion-agent-windows.bat
   ```
5. اترك النافذة مفتوحة — الـ Agent يتصل بالخادم وينتظر المهام كل 5 ثوانٍ.
6. أطلق مسحاً من الموقع وشاهد النتيجة في صفحة **Vulnerabilities**.

> إن أحببت PowerShell بدل CMD:
> ```powershell
> powershell -ExecutionPolicy Bypass -File orion-agent-windows.ps1
> ```

---

### 🖥️ Linux / Kali / macOS

```bash
curl -sL https://raw.githubusercontent.com/mmfarae7-lgtm/orvyn-cyber-ai/main/termux-agent/orion-agent.sh -o orion-agent.sh
chmod +x orion-agent.sh
./orion-agent.sh
```
(مع تثبيت الأدوات حسب README أعلاه)

---

### ⚙️ ما تحتاجه في حسابك

- حسابات المستخدمين تُنشأ بالبريد وكلمة السر من صفحة Sign Up.
- الـ Agent لا يحتاج تسجيل دخول — يعمل بمفتاح عمومي (public anon key) معدّ مسبقاً داخل الملف، ولا يرفع أي بيانات حساسة.
