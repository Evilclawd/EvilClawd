# EvilClawd

AI-powered penetration testing assistant that combines LLM intelligence with battle-tested security tools. Message a target and get back real, validated findings with full engagement memory.

## Features

- **Reconnaissance Pipeline** - Subdomain enumeration (subfinder), port scanning (nmap), technology fingerprinting (whatweb)
- **Vulnerability Detection** - SQL injection (sqlmap), XSS (xsser), command injection (commix), security header analysis
- **Guided Exploitation** - Multi-step exploit chains with blast radius display and user approval at each destructive step
- **Evidence Validation** - "No exploit, no report" policy prevents hallucinated findings. Only tool-confirmed vulnerabilities make it into reports
- **Professional Reporting** - Markdown and HTML reports with CVSS severity scoring, reproducible PoCs, raw tool output, and remediation guidance
- **Safety First** - Scope enforcement, three-tier risk classification (safe/moderate/destructive), immutable audit logging

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager

### Security Tools (install separately)

| Tool | Purpose | Install |
|------|---------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [nmap](https://nmap.org/) | Port scanning | `brew install nmap` / `apt install nmap` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Technology fingerprinting | `brew install whatweb` / `gem install whatweb` |
| [sqlmap](https://sqlmap.org/) | SQL injection testing | `pip install sqlmap` |
| [xsser](https://github.com/epsylon/xsser) | XSS testing | `pip install xsser` |
| [commix](https://github.com/commixproject/commix) | Command injection testing | `pip install commix` |

Tools are optional - EvilClawd gracefully reports which tools are missing and continues with what's available.

## Installation

```bash
git clone https://github.com/Evilclawd/EvilClawd.git
cd EvilClawd

# Install dependencies
uv sync

# Set your Anthropic API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

## Usage

### 1. Authorize a target

```bash
uv run evilclawd add-target example.com
```

### 2. Run reconnaissance

```bash
uv run evilclawd scan example.com
```

### 3. Scan for vulnerabilities

```bash
uv run evilclawd vuln-scan example.com
```

### 4. Run guided exploitation

```bash
# Uses session ID from vuln-scan output
uv run evilclawd exploit example.com --session-id <session-id>
```

### 5. Generate report

```bash
uv run evilclawd report <session-id>
uv run evilclawd report <session-id> --html  # Also generate HTML
```

### Check status

```bash
uv run evilclawd status --session-id <session-id>
```

## Architecture

```
src/scanner/
  agents/          # AI-driven orchestration (ReconAgent, VulnAgent, ExploitAgent)
  cli/             # AsyncClick CLI interface
  core/
    llm/           # LLM abstraction layer (Claude, extensible to other providers)
    persistence/   # SQLite database, audit logging, checkpointing
    reporting/     # Jinja2 report templates, HTML export
    safety/        # Scope enforcement, risk classification, approval workflow
    severity.py    # CVSS v3.1 scoring and confidence classification
  tools/           # Security tool wrappers (nmap, sqlmap, xsser, etc.)
```

### Key Design Principles

- **Guided mode** - AI suggests, user approves. No autonomous exploitation
- **Evidence-based** - Every finding must have tool-confirmed evidence. AI interpretation is labeled separately
- **Scope-enforced** - Only scans explicitly authorized targets
- **Audit trail** - SHA-256 hash-chained logs of all actions and approval decisions
- **Async-first** - Built on asyncio throughout for concurrent tool execution

## Running Tests

```bash
uv run pytest tests/ -v
```

All 137 tests use mocked tool outputs - no real security tools or network access needed.

## Disclaimer

This tool is intended for **authorized security testing only**. Always obtain explicit written permission before testing any target. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this software.

## License

MIT
