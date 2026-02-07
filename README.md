# EvilClawd

AI-powered penetration testing assistant that combines LLM intelligence with battle-tested security tools. Message a target URL to your own private Telegram bot and get back real, validated findings — or use the CLI directly.

**Self-hosted.** You run it on your machine, with your API keys, against your authorized targets. No shared servers, no cloud dependency, no data leaving your network.

## Features

- **Reconnaissance Pipeline** - Subdomain enumeration (subfinder), port scanning (nmap), technology fingerprinting (whatweb)
- **Vulnerability Detection** - SQL injection (sqlmap), XSS (xsser), command injection (commix), security header analysis
- **Guided Exploitation** - Multi-step exploit chains with blast radius display and user approval at each destructive step
- **Evidence Validation** - "No exploit, no report" policy prevents hallucinated findings. Only tool-confirmed vulnerabilities make it into reports
- **Professional Reporting** - Markdown and HTML reports with CVSS severity scoring, reproducible PoCs, raw tool output, and remediation guidance
- **Telegram Bot** - Message URLs to your own private bot from your phone, get results back in chat with inline approval buttons
- **Safety First** - Scope enforcement, three-tier risk classification (safe/moderate/destructive), immutable audit logging

## How It Works

EvilClawd runs entirely on your machine. Each user sets up their own instance:

1. Clone the repo and install dependencies
2. Install whichever security tools you want (all optional — the scanner uses what's available)
3. Add your own API keys (Anthropic for LLM, optionally your own Telegram bot token)
4. Scan targets you're authorized to test

There is no shared infrastructure. Your scans, your findings, your data — all local.

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager
- An [Anthropic API key](https://console.anthropic.com/) for LLM-powered analysis

### Security Tools (install separately)

| Tool | Purpose | Install |
|------|---------|---------|
| [nmap](https://nmap.org/) | Port scanning | `brew install nmap` / `apt install nmap` |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `brew install subfinder` / `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Technology fingerprinting | Clone from GitHub (see below) |
| [sqlmap](https://sqlmap.org/) | SQL injection testing | `pipx install sqlmap` |
| [xsser](https://github.com/epsylon/xsser) | XSS testing | Clone from GitHub (see below) |
| [commix](https://github.com/commixproject/commix) | Command injection testing | `pipx install commix` |

Tools are optional — EvilClawd gracefully reports which tools are missing and continues with what's available. Install the ones you need.

<details>
<summary><strong>Quick install (macOS)</strong></summary>

```bash
# Homebrew packages
brew install nmap subfinder

# Python tools (via pipx to avoid system conflicts)
brew install pipx
pipx install sqlmap
pipx install commix

# Tools installed from source
git clone https://github.com/urbanadventurer/WhatWeb.git ~/.local/share/whatweb
ln -sf ~/.local/share/whatweb/whatweb ~/.local/bin/whatweb

git clone https://github.com/epsylon/xsser-public.git ~/.local/share/xsser
ln -sf ~/.local/share/xsser/xsser ~/.local/bin/xsser

# Make sure ~/.local/bin is on your PATH
export PATH="$HOME/.local/bin:$PATH"  # Add to ~/.zshrc or ~/.bashrc
```

</details>

<details>
<summary><strong>Quick install (Linux/Debian)</strong></summary>

```bash
sudo apt install nmap
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
pipx install sqlmap commix

# whatweb and xsser: same git clone steps as macOS
git clone https://github.com/urbanadventurer/WhatWeb.git ~/.local/share/whatweb
ln -sf ~/.local/share/whatweb/whatweb ~/.local/bin/whatweb

git clone https://github.com/epsylon/xsser-public.git ~/.local/share/xsser
ln -sf ~/.local/share/xsser/xsser ~/.local/bin/xsser

export PATH="$HOME/.local/bin:$PATH"  # Add to ~/.bashrc
```

</details>

## Installation

```bash
git clone https://github.com/Evilclawd/EvilClawd.git
cd EvilClawd

# Install Python dependencies
uv sync

# Configure your API keys
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

## Usage (CLI)

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

## Usage (Telegram Bot)

Each user creates and runs their own private bot. Your bot, your machine, your scans.

### Setup

1. Message [@BotFather](https://t.me/BotFather) on Telegram and send `/newbot`
2. Follow the prompts to name your bot and get a token
3. Add the token to your `.env` file:
   ```
   TELEGRAM_BOT_TOKEN=your-token-here
   ```
4. (Optional) Register commands with BotFather for autocomplete — send `/setcommands` and paste:
   ```
   scan - Run recon scan on a target
   vulnscan - Run vulnerability scan
   exploit - Guided exploitation
   report - Generate report
   status - Check scan status
   queue - Show queued scans
   ```

### Start the bot

```bash
uv run python -c "
from scanner.telegram_bot import create_bot_app
from dotenv import load_dotenv
import os
load_dotenv()
app = create_bot_app(os.environ['TELEGRAM_BOT_TOKEN'])
app.run_polling()
"
```

### Bot commands

- **Send any URL** — runs full pipeline (recon + vuln scan), pauses before exploitation
- `/scan <url>` — recon only (subdomains, ports, technologies)
- `/vulnscan <url>` — recon + vulnerability scan
- `/exploit <session-id>` — guided exploitation with inline approval buttons
- `/report <session-id>` — summary report
- `/status <session-id>` — check scan progress
- `/queue` — view scan queue

Exploitation steps display full blast radius and require inline button approval for moderate/destructive actions. Safe steps auto-execute. Unapproved steps auto-deny after 15 minutes.

## Architecture

```
src/scanner/
  agents/          # AI-driven orchestration (ReconAgent, VulnAgent, ExploitAgent)
  cli/             # AsyncClick CLI interface
  telegram_bot/    # Telegram interface (handlers, formatters, approval callbacks)
  core/
    llm/           # LLM abstraction layer (Claude, extensible to other providers)
    persistence/   # SQLite database, audit logging, checkpointing
    reporting/     # Jinja2 report templates, HTML export
    safety/        # Scope enforcement, risk classification, approval workflow
    severity.py    # CVSS v3.1 scoring and confidence classification
  tools/           # Security tool wrappers (nmap, sqlmap, xsser, etc.)
```

### Key Design Principles

- **Self-hosted** - Runs on your machine. No cloud, no shared servers, no data exfiltration
- **Guided mode** - AI suggests, user approves. No autonomous exploitation
- **Evidence-based** - Every finding must have tool-confirmed evidence. AI interpretation is labeled separately
- **Scope-enforced** - Only scans explicitly authorized targets
- **Audit trail** - SHA-256 hash-chained logs of all actions and approval decisions
- **Async-first** - Built on asyncio throughout for concurrent tool execution

## Running Tests

```bash
uv run pytest tests/ -v
```

All 157 tests use mocked tool outputs — no real security tools or network access needed.

## Disclaimer

This tool is intended for **authorized security testing only**. Always obtain explicit written permission before testing any target. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this software.

## License

MIT
