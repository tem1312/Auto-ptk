# Auto-PTK

An automated penetration testing toolkit that orchestrates Docker-based security scanners,
stores findings in SQLite, and produces colour-coded CLI output and HTML reports.
Includes both a command-line interface and a graphical (Tkinter) GUI.

---

## Requirements

### Python
Python **3.10 or newer** is required.

Check your version:
```bash
python --version
```

### Docker
Docker Desktop must be installed and **running** before you launch Auto-PTK.

- **Windows / macOS** — [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- **Linux** — Docker Engine via your package manager, e.g.:
  ```bash
  sudo apt install docker.io
  sudo systemctl start docker
  sudo usermod -aG docker $USER   # lets you run docker without sudo (re-login after)
  ```

### Python packages
Install the only required third-party package:
```bash
pip install docker
```

Tkinter (needed for the GUI) is included with the standard Python installer on Windows and macOS.
On Linux you may need to install it separately:
```bash
# Debian / Ubuntu
sudo apt install python3-tk

# Fedora / RHEL
sudo dnf install python3-tkinter
```

---

## Folder structure

```
Auto-PTK/
├── Auto-ptk.py          # CLI backend — run this for command-line usage
├── Ptk_Gui.py           # Tkinter GUI — run this for the graphical interface
├── report.py            # HTML report generator (used automatically after each run)
├── auto_ptk.db          # SQLite database (created on first run)
├── gui_settings.json    # GUI preferences (created on first run)
│
├── modules/
│   ├── recon/           # Reconnaissance module descriptors (.json)
│   ├── vuln/            # Vulnerability scan module descriptors (.json)
│   └── Web/             # Web audit module descriptors (.json)
│
├── Profiles/
│   └── profiles.json    # Named scan profiles (editable)
│
├── reports/
│   ├── raw/             # Raw tool output (.txt files, one folder per run)
│   └── run_<id>.html    # Generated HTML reports
│
└── cve_watchlists/
    └── watchlist.txt    # Optional CVE IDs to focus on
```

---

## Platform notes

| Feature | Linux | Windows / macOS |
|---------|-------|-----------------|
| Full port scanning | Host network mode | Bridge mode — may miss ports on LAN targets |
| Nuclei reaching local targets | Works against local IPs | May return no results on local IPs |
| GUI | y | y |
| CLI | y | y |

> **Tip:** For the most reliable results when scanning local/lab targets, run Auto-PTK
> from a **Linux machine** or a Linux VM with Docker installed.

---

## Running the CLI

```bash
python Auto-ptk.py --help
```

### Common commands

```bash
# List all available modules and profiles
python Auto-ptk.py --list-modules

# Quick port scan against a single IP
python Auto-ptk.py --run --target 10.10.10.10 --profile quick

# Full IP-based recon with 4 parallel workers
python Auto-ptk.py --run --target 10.10.10.10 --profile full --workers 4

# Web audit with interactive follow-up menu after the scan
python Auto-ptk.py --run --target 10.10.10.10 --profile web --interactive

# Domain enumeration (use a hostname or domain, not a bare IP)
python Auto-ptk.py --run --target example.com --profile domain

# Run specific modules only
python Auto-ptk.py --run --target 10.10.10.10 --modules nmap-top-tcp,nuclei-scanner

# Run with a custom tag and save the HTML report to a specific folder
python Auto-ptk.py --run --target 10.10.10.10 --profile quick --tag my-lab --report-dir ./out

# Skip HTML report generation
python Auto-ptk.py --run --target 10.10.10.10 --profile quick --report none
```

### All CLI flags

| Flag | Description |
|------|-------------|
| `--run` | Start a scan |
| `--target <IP\|hostname>` | Target to scan (required with `--run`) |
| `--profile <name>` | Named scan profile (see Profiles section) |
| `--modules <n1,n2>` | Comma-separated list of specific modules to run |
| `--workers <N>` | Number of modules to run in parallel (default: 1) |
| `--tag <name>` | Custom label for this run (auto-generated if omitted) |
| `--interactive` | After the scan, open the interactive follow-up menu |
| `--report html\|none` | Generate an HTML report after the run (default: html) |
| `--report-dir <path>` | Where to write the HTML report (default: `reports/`) |
| `--list-modules` | Print all discovered modules and available profiles |

---

## Running the GUI

```bash
python Ptk_Gui.py
```

The GUI provides:
- Target and tag input fields
- Profile dropdown and module multi-select list
- Worker count selector for parallel scanning
- Live log output streamed in real time
- Parsed findings panel with severity colour coding
- Run summary tab (total modules, findings, open ports, CVEs, severity breakdown)
- Interactive follow-up tab (suggested modules based on detected services)
- Export findings to JSON
- Automatic HTML report generation after each scan (toggle with "Generate HTML report")
- One-click "Open Last Report" button to view the HTML report in the default browser
- Light / Dark / System theme switcher

---

## Profiles

Profiles are defined in `Profiles/profiles.json` and can be edited freely.
The following profiles are built in:

| Profile | Modules included | Best used for |
|---------|------------------|---------------|
| `quick` | rustscan-fast, nmap-top-tcp | Fast first look at a host |
| `full` | rustscan-fast, nmap-full, nuclei-scanner | General IP recon |
| `web` | nmap-top-tcp, whatweb-fingerprint, ffuf-dir, nikto-web-scan, nuclei-scanner, nmap-vuln | HTTP target auditing |
| `web-deep` | All of `web` + wpscan, sslscan | Thorough web audit including WordPress and TLS |
| `smb` | nmap-top-tcp, nmap-full, enum4linux-ng, smbmap, nmap-vuln | SMB / Windows share enumeration |
| `cve` | nmap-vuln, nuclei-scanner | Focused CVE detection |
| `domain` | amass-enum, dnsrecon | Domain/subdomain enumeration (**use a domain name, not a bare IP**) |

---

## Modules

All modules run inside Docker containers — no tools need to be installed locally.

| Module | Docker image | What it does |
|--------|--------------|--------------|
| `rustscan-fast` | `rustscan/rustscan` | Fast TCP port discovery, passes results to nmap |
| `nmap-top-tcp` | `instrumentisto/nmap` | Top 1000 TCP ports with service/script detection |
| `nmap-full` | `instrumentisto/nmap` | All 65535 TCP ports with service/version/OS detection |
| `nmap-vuln` | `instrumentisto/nmap` | Nmap vuln NSE scripts, extracts CVE IDs |
| `nuclei-scanner` | `projectdiscovery/nuclei` | Template-based vulnerability scanner |
| `whatweb-fingerprint` | `secsi/whatweb` | Web technology fingerprinting |
| `nikto-web-scan` | `secsi/nikto` | Web server vulnerability scanner |
| `wpscan-wordpress` | `wpscanteam/wpscan` | WordPress plugin/theme/user enumeration |
| `ffuf-dir` | `ghcr.io/ffuf/ffuf` | Directory and file brute-forcing |
| `sslscan` | `rbsec/sslscan` | TLS/SSL cipher and certificate analysis |
| `enum4linux-ng` | `cytopia/enum4linux-ng` | SMB/NetBIOS enumeration (users, shares, domains) |
| `smbmap` | `rflathers/smbmap` | SMB share permissions mapping |
| `amass-enum` | `caffix/amass` | Subdomain and asset discovery (domain targets only) |
| `dnsrecon` | `bettercyber/dnsrecon` | DNS record enumeration (domain targets only) |

Docker images are pulled automatically on first use if not already present locally.

---

## Reports

After every scan, Auto-PTK automatically:

1. Writes raw tool output to `reports/raw/<tag>/`
2. Writes a parsed findings summary to `reports/raw/<tag>/<tag>-findings.txt`
3. Writes detected CVE IDs to `reports/raw/<tag>/<tag>-cves.txt`
4. Generates an HTML report at `reports/run_<id>.html`

The HTML report can be opened in any browser and printed to PDF using the browser's
built-in print function.

---

## CVE watchlist

Place CVE IDs you want to track in `cve_watchlists/watchlist.txt`, one per line.
Lines starting with `#` are treated as comments.

```
# My lab watchlist
CVE-2021-41773
CVE-2018-10245
```

Supported file formats: `.txt`, `.json`, `.csv`

After each scan, any matching CVEs found in findings are looked up against the
CIRCL CVE API and cached locally in `auto_ptk.db` for enriched display (CVSS score,
title, published date).

---

## Adding custom modules

Create a `.json` file in `modules/recon/`, `modules/vuln/`, or `modules/Web/`:

```json
{
  "name": "my-scanner",
  "image": "dockerhub/image-name",
  "cli": "--some-flag {TARGET}",
  "parser": "nmap-xml",
  "tags": ["recon", "tcp"]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | y | Unique module identifier used in `--modules` and profiles |
| `image` | y | Docker Hub image name |
| `cli` | y | Command passed to the container; `{TARGET}` is replaced at runtime |
| `parser` | n | How to extract findings from output (see list below) |
| `tags` | n | Service tags used by the interactive follow-up to suggest modules |

**Available parsers:** `nmap-xml`, `nmap-open-ports`, `nmap-vuln-cves`, `nuclei-jsonl`,
`nuclei-findings`, `amass-json`, `amass-domains`, `dnsrecon-csv`, `dnsrecon-records`,
`whatweb-json`, `whatweb-tech`, `nikto-json`, `nikto-issues`, `wpscan-json`,
`wpscan-issues`, `ffuf-json`, `sslscan-text`, `enum4linux-text`, `smbmap-text`

---

## Troubleshooting

**`docker` module not found**
```bash
pip install docker
```

**Docker daemon not running**
Auto-PTK exits with error code `-3` and the message:
`[error -3] Cannot connect to the Docker daemon. Docker is installed but the daemon is not running or is unreachable.`

Start Docker Desktop, or on Linux:
```bash
sudo systemctl start docker
```

Other pre-flight error codes:
- `-1` — `docker` Python package not installed (`pip install docker`)
- `-2` — no module descriptors found under `modules/`
- `-3` — Docker daemon not reachable (this case)

**Image pull fails (404 / access denied)**
The Docker image name in the module descriptor may be wrong or require authentication.
Check the `image` field in the relevant `.json` file under `modules/`.

**Nuclei / nmap returns no results on a local IP (Windows/macOS)**
Docker containers use bridge network mode on non-Linux hosts and cannot reach LAN
targets directly. Run Auto-PTK from a Linux machine for reliable local network scanning.

**`amass-enum` or `dnsrecon` fails with status=1 on an IP target**
Both tools are designed for domain names. Use the `domain` profile only with a
hostname or domain (e.g. `example.com`), not a bare IP address.

**GUI won't start — `_tkinter` not found (Linux)**
```bash
sudo apt install python3-tk
```
