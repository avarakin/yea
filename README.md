# yea - Yet Another AUR Installer

A terminal TUI application for managing Arch Linux AUR packages with AI-powered security review.

## Features

- **Upgrade mode**: Detect and upgrade all installed AUR packages
- **Install mode**: Install specific AUR packages by name
- **AI Security Review**: Uses OpenAI-compatible API (local llama.cpp or any provider) to analyze PKGBUILDs for security risks
- **Vulnerability Detection**: Checks against known compromised packages and out-of-date warnings
- **Interactive TUI**: Checkbox selection, one-by-one review, and confirmation flow
- **Zero dependencies**: Uses only Python standard library

## Installation

```bash
# Clone and make executable
chmod +x yea.py

# Optionally install system-wide
sudo cp yea.py /usr/local/bin/yea
```

## Configuration

Create `~/.config/yea/config.json`:

```json
{
    "api_url": "http://localhost:8080/v1/chat/completions",
    "api_model": "llama3",
    "api_key": "",
    "cache_dir": "~/.cache/yea",
    "prompt_template_path": "config/security_review.md",
    "vulnerability_check": true
}
```

### Local AI Setup (llama.cpp)

Start a local server with llama.cpp:

```bash
llama-server -m your-model.gguf --port 8080
```

Then point `api_url` to `http://localhost:8080/v1/chat/completions`.

## Usage

### Upgrade Mode (no arguments)

```bash
yea
```

1. Lists all installed AUR packages (from `pacman -Qm`)
2. Shows checkboxes for each — select which to upgrade
3. Clones/pulls each package repo to `~/.cache/yea`
4. Checks for known vulnerabilities
5. Runs AI security review on each package
6. Presents results one-by-one for approval
7. Installs confirmed packages with `makepkg -si`

### Install Mode

```bash
yea package1 package2 package3
```

Same flow as upgrade mode, but for the specified packages.

## TUI Controls

| Key | Action |
|-----|--------|
| ↑/↓ | Navigate list |
| Space | Toggle checkbox |
| a | Select all |
| n | Deselect all |
| y | Yes / Continue / Install |
| n | No / Skip |
| q | Quit |
| Enter | Confirm selection |

## Security Review

The AI review analyzes:

1. **Supply chain risks** — source trustworthiness, checksums
2. **Privilege escalation** — arbitrary root execution in PKGBUILD hooks
3. **Network requests** — internet downloads during install
4. **Hidden payloads** — obfuscated commands, base64
5. **Maintainer trust** — recent maintainer changes, abandoned packages
6. **Build reproducibility** — verified sources, safe patching
7. **Post-install hooks** — post-install scripts

Output: JSON with `risk_score` (1-100), `rating` (low/medium/high), `summary`, and `details`.

## File Structure

```
yea/
├── yea.py                          # Main TUI application
├── config/
│   ├── config.json                 # Default configuration
│   └── security_review.md          # AI prompt template
├── .config/yea/config.json         # User configuration (created on first run)
└── ~/.cache/yea/                   # Cloned AUR repositories
```

## Requirements

- Python 3.10+
- Arch Linux (pacman, makepkg, git)
- sudo access (for installation)
- (Optional) OpenAI-compatible API server for AI review
