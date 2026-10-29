# WebShield

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/Security-Scanner-FF6B6B?style=for-the-badge" alt="Security Scanner" />
  <img src="https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite" />
</p>

<p align="center">
  <strong>Website Vulnerability Scanner</strong>
</p>

WebShield is a local web reconnaissance and security assessment tool built with Python and Flask. It helps you inspect a public website or domain for common information leakage points, DNS records, HTTP response behavior, TLS certificate metadata, and missing security headers. It is designed for security learning, research, and authorized testing only.

This project is a lightweight scanner and not a replacement for a full enterprise-grade security platform. It is ideal for understanding how a target site exposes configuration details and what security-related issues may be worth investigating further.

## Why WebShield?

- Quick website reconnaissance from a browser
- DNS, HTTP, TLS, and header analysis in one interface
- Optional common TCP port check for authorized targets only
- JSON and PDF report generation
- Local SQLite scan history
- Beginner-friendly and easy to run on multiple operating systems

## Features

- DNS record lookup for:
  - A
  - AAAA
  - MX
  - NS
  - TXT
  - CNAME
- Public IP resolution
- HTTP response and redirect tracking
- TLS certificate inspection
- Security header review and recommendations
- Cookie attribute checks
- Optional port scan of common TCP ports
- Saved scan history in SQLite
- Downloadable JSON and PDF reports

## Supported Platforms

WebShield is designed to run on:

- Linux
- macOS
- Windows 10 / 11

## Requirements

Before installing, make sure you have:

- Python 3.10 or newer
- pip (Python package installer)
- Internet access for DNS and HTTP lookups
- A browser to open the local dashboard
- Permission to test only domains you own or are authorized to assess

Optional:

- Nmap (not required for the built-in lightweight scanner, but useful for advanced work)

## Project Structure

```text
WebShield/
├── app.py                  # Flask backend and scan logic
├── requirements.txt        # Python dependencies
├── scans.db               # SQLite database for saved scans
├── static/
│   ├── app.js             # Frontend logic
│   ├── style.css         # UI styling
│   └── ...
├── templates/
│   └── index.html         # Web UI
├── README.md              # Project documentation
└── .gitignore             # Common repo ignore rules
```

## Installation Guide

Choose the instructions for your operating system.

### 1) Linux Installation

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd ~
git clone https://github.com/VishvijayPS/WebShield.git
cd WebShield
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Then open in your browser:

```text
http://127.0.0.1:5000
```

#### Fedora / RHEL / CentOS

```bash
sudo dnf install -y python3 python3-pip python3-virtualenv
cd ~
git clone https://github.com/VishvijayPS/WebShield.git
cd WebShield
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

#### Arch Linux

```bash
sudo pacman -Syu
sudo pacman -S python python-pip
cd ~
git clone https://github.com/VishvijayPS/WebShield.git
cd WebShield
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

### 2) macOS Installation

#### Using Homebrew

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python git
cd ~
git clone https://github.com/VishvijayPS/WebShield.git
cd WebShield
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If `python3` is not found, use:

```bash
python --version
```

Then open:

```text
http://127.0.0.1:5000
```

### 3) Windows Installation

#### Option A: PowerShell

```powershell
cd $HOME
git clone https://github.com/VishvijayPS/WebShield.git
cd WebShield
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

#### Option B: Command Prompt

```cmd
cd %USERPROFILE%
git clone https://github.com/VishvijayPS/WebShield.git
cd WebShield
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Then visit:

```text
http://127.0.0.1:5000
```

### 4) Install Without Git

If Git is not installed, download the project as a ZIP file from GitHub and extract it:

1. Open the GitHub repository
2. Click Code > Download ZIP
3. Extract the archive
4. Open the extracted folder in a terminal
5. Run the virtual environment and install commands shown above

## Running the Application

From the project folder:

```bash
cd WebShield
```

If using a virtual environment:

### Linux/macOS

```bash
source .venv/bin/activate
python app.py
```

### Windows

```powershell
.\.venv\Scripts\Activate.ps1
python app.py
```

The Flask app starts locally and listens on:

```text
http://127.0.0.1:5000
```

## Using WebShield

### Step 1: Open the dashboard

Visit the local URL in your browser:

```text
http://127.0.0.1:5000
```

### Step 2: Enter a target

Use:

- a domain like `example.com`
- or a full URL like `https://example.com`

The input is validated and normalized automatically.

### Step 3: Choose scanning options

The tool allows:

- normal scan of DNS, HTTP, TLS, and headers
- optional common port check for authorized targets only

### Step 4: Review results

The dashboard shows:

- resolved IP addresses
- HTTP status and redirect trail
- security findings and recommendations
- DNS records
- TLS certificate details
- port scan summary (if enabled)

### Step 5: Download reports

After a scan completes, you can export:

- JSON report
- PDF report

Reports are saved from the scan history section and can be downloaded directly from the interface.

## Example Workflow

```bash
# 1. Clone the repo
git clone https://github.com/VishvijayPS/WebShield.git
cd WebShield

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the app
python app.py
```

Then in a browser, enter a target such as:

```text
https://example.com
```

Review the scan output and downloaded report for security observations.

## What WebShield Checks

### DNS

- A records
- AAAA records
- MX records
- NS records
- TXT records
- CNAME records

### HTTP

- Final URL
- Status code
- Redirect chain
- Response headers
- Security header presence
- Cookies and secure attribute checks

### TLS

- Certificate subject
- Issuer
- Expiration
- Negotiated TLS version
- HTTPS status

### Port Scan

The tool performs a lightweight TCP check against a small set of common ports. It is intentionally limited and should only be used on targets you own or are explicitly authorized to assess.

## API Endpoints

WebShield includes a few REST-style routes:

- `GET /` — dashboard frontend
- `POST /api/scan` — start a scan
- `GET /api/history` — list previous scans
- `GET /api/report/<scan_id>.json` — download JSON report
- `GET /api/report/<scan_id>.pdf` — download PDF report

Example request:

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","port_scan":true}'
```

## Important Security Notice

WebShield is intended for:

- authorized security research
- learning and educational purposes
- internal testing on systems you own or are permitted to evaluate

It should not be used for:

- unauthorized probing
- malicious exploitation
- testing systems without explicit permission

WebShield can reveal configuration weaknesses and metadata that may be useful during legitimate security reviews, but those findings are not proof of active exploitation.

## Troubleshooting

### App won't start

Check if Python is installed:

```bash
python --version
```

If dependencies fail, reinstall them:

```bash
pip install -r requirements.txt
```

### Browser cannot connect

Confirm the server is running and use the correct URL:

```text
http://127.0.0.1:5000
```

If the port is blocked or in use, stop the current process and rerun:

```bash
python app.py
```

### Domain validation errors

Use a real public domain or full URL. For example:

```text
example.com
https://example.com
```

Private IPs, localhost values, and invalid hostnames are not accepted in the public scanner flow.

### Missing packages

On Linux/macOS:

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

On Windows:

```powershell
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

## License

This project is distributed under an open-source license as defined by the repository. Please review the repository's license file before commercial or production use.

## Contributing

Contributions are welcome. If you want to improve the project:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally
5. Open a pull request

## Contact / Repository

- GitHub: https://github.com/VishvijayPS/WebShield

## Summary

WebShield is a practical and beginner-friendly website reconnaissance tool that gives you a polished local dashboard for scanning common web security signals. It is built for learning, responsible assessment, and structured reporting.

If you are testing a website you own or have permission to evaluate, WebShield provides a straightforward way to collect technical intelligence and review security posture.

---

<p align="center">
  <strong>Built for learning, analysis, and responsible security testing.</strong>
</p>
