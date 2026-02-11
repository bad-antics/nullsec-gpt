# NullSec GPT Wiki

Welcome to **NullSec GPT** — an AI-powered vulnerability scanner using GPT models.

## Navigation

- [[Getting Started]] — Setup API keys and scan
- [[Scan Modes]] — Static, dynamic, and hybrid analysis
- [[AI Models]] — Supported LLM backends
- [[Custom Rules]] — Define custom vulnerability patterns
- [[API]] — Python API reference

## How It Works

```
Source Code → Tokenization → GPT Analysis → Vulnerability Report
     ↓              ↓              ↓               ↓
  File Parser    Chunking     Pattern Match    JSON/HTML Output
```

## Features

| Feature | Description |
|---------|-------------|
| 🤖 GPT-4 Analysis | AI-powered code review |
| 📊 CVSS Scoring | Automated severity rating |
| 🔄 Multi-Language | Python, JS, Go, Rust, C/C++ |
| 📝 Reports | HTML, JSON, SARIF output |
| 🔌 CI/CD | GitHub Actions integration |
