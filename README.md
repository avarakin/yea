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


## External Communications

`yea` communicates externally via HTTP(S) API calls and local subprocess invocations. Below is a complete chronological sequence of all external communications.

### Startup Phase

| # | Type | Target | Direction | Details |
|---|------|--------|-----------|---------|
| 1 | File read | `~/.config/yea/config.json` | Inbound | Loads user config. Falls back to `DEFAULT_CONFIG` if missing. |
| 2 | File read | `config/security_review.md` | Inbound | Loads AI prompt template. Fallback inline template used if missing. |
| 3 | Directory create | `~/.cache/yea/` | Outbound | Created automatically if it doesn't exist. |

### Upgrade Mode — Package Detection

| # | Type | Target | Direction | Details |
|---|------|--------|-----------|---------|
| 4 | Subprocess | `pacman -Qm` | Outbound (local) | Detects installed AUR packages. `PACMAN_COLOR=0` disables color output. |

### Per-Package Data Fetching

| # | Type | Target | Direction | Details |
|---|------|--------|-----------|---------|
| 5 | Subprocess | `git clone` / `git pull` | Outbound (local) | Clones or pulls the AUR git repo (`https://aur.archlinux.org/{pkgname}.git`) into `~/.cache/yea/{pkgname}/`. |
| 6 | HTTP POST | `https://aur.archlinux.org/rpc?v=5&type=info` | Outbound | Sends package name(s) as form data. Returns JSON metadata (Name, Version, Description, OutOfDate). Timeout: 30s. |
| 7 | Subprocess | `git log -1 --format=%cd --date=iso` | Outbound (local) | Gets last commit date. |
| 8 | Subprocess | `git log --format=%cd --date=iso --reverse` | Outbound (local) | Gets all commit dates in reverse order. |
| 9 | Subprocess | `git log --format=%an --reverse` | Outbound (local) | Gets all authors to detect maintainer changes. |
| 10 | Subprocess | `git log -1 --format=%cd --date=iso <i>..HEAD` | Outbound (local) | Gets date when maintainer changed (only if multiple unique authors found). |
| 11 | HTTP GET | `https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkgname}` | Outbound | Fetches raw PKGBUILD content. Checks cache first. Timeout: 30s. Caches to `~/.cache/yea/{pkgname}/PKGBUILD`. |
| 12 | HTTP POST | `https://aur.archlinux.org/rpc?v=5&type=info` | Outbound | Re-used for vulnerability check (OutOfDate flag). Timeout: 30s. |
| 13 | Hardcoded list | In-memory | — | Checks against known compromised packages: `xerohdm`, `ntfy-bin`. |

### AI Security Review (per package)

| # | Type | Target | Direction | Details |
|---|------|--------|-----------|---------|
| 14 | HTTP POST | `{api_url}` (default: `http://localhost:8080/v1/chat/completions`) | Outbound | Sends JSON with `model`, `messages` (system + user prompt with PKGBUILD), `temperature: 0.1`. Headers: `Content-Type: application/json`, `Authorization: Bearer {api_key}` (if configured). Timeout: 120s. Expects JSON with `risk_score`, `rating`, `summary`, `details`. |

### Package Installation (per confirmed package)

| # | Type | Target | Direction | Details |
|---|------|--------|-----------|---------|
| 15 | Subprocess | `makepkg -si --noconfirm` | Outbound (local, requires sudo) | Builds and installs the package from the cloned repo. Exits curses mode first to free the terminal for `sudo`. |

### Summary Table

| # | Communication | Protocol/Method | Target | When |
|---|--------------|-----------------|--------|------|
| 1 | File read | Local FS | `~/.config/yea/config.json` | Startup |
| 2 | File read | Local FS | `config/security_review.md` | Startup |
| 3 | Directory create | Local FS | `~/.cache/yea/` | Startup |
| 4 | Subprocess | Local | `pacman -Qm` | Upgrade mode only |
| 5 | Subprocess | Local | `git clone` / `git pull` | Per package |
| 6 | HTTP POST | HTTPS | `aur.archlinux.org/rpc?v=5&type=info` | Per package (metadata) |
| 7–10 | Subprocess | Local | `git log` commands | Per package (git metadata) |
| 11 | HTTP GET | HTTPS | `aur.archlinux.org/cgit/aur.git/plain/PKGBUILD` | Per package |
| 12 | HTTP POST | HTTPS | `aur.archlinux.org/rpc` (re-use) | Per package (vuln check) |
| 13 | Hardcoded | In-memory | `xerohdm`, `ntfy-bin` | Per package |
| 14 | HTTP POST | HTTP/HTTPS | `{api_url}` (local LLM server) | Per package (AI review) |
| 15 | Subprocess | Local | `makepkg -si --noconfirm` | Per confirmed package |

### External Network Destinations

| Domain | Protocol | Purpose |
|--------|----------|---------|
| `aur.archlinux.org` | HTTPS (POST + GET) | AUR RPC API (package metadata), PKGBUILD fetch |
| `{api_url}` (default `localhost:8080`) | HTTP/HTTPS | AI/LLM inference endpoint (OpenAI-compatible) |

### Local External Programs Invoked

| Program | Purpose |
|---------|---------|
| `pacman` (`-Qm`) | Detect installed AUR packages |
| `git` (`clone`, `pull`, `log`) | Clone/fetch AUR repos, extract commit metadata |
| `makepkg` (`-si --noconfirm`) | Build and install packages (with `sudo`) |

### Security Notes

- **AI endpoint** is configurable — defaults to local `localhost:8080` but can point to any URL. API key is sent as a Bearer token if configured.
- **AUR data** is cached to `~/.cache/yea/` to avoid redundant network calls.
- **PKGBUILD execution** runs `makepkg -si` which invokes `sudo` for actual installation — the user must trust the reviewed PKGBUILD.
- No other external APIs, telemetry, or "phone-home" behavior exists in the codebase.


- Python 3.10+
- Arch Linux (pacman, makepkg, git)
- sudo access (for installation)
- (Optional) OpenAI-compatible API server for AI review
