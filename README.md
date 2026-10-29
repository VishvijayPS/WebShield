# CyberRecon Intelligence

A Flask-based website reconnaissance and security-configuration mini-project. It collects public DNS records, HTTP response details, TLS certificate information, checks selected security headers, stores scan history in SQLite, and exports PDF/JSON reports.

## Requirements
- Ubuntu/Linux, Python 3.10+, pip/venv
- Internet access for public DNS and HTTP checks
- Optional Nmap installation (this first version uses a small built-in TCP connect check for common ports)

## Install and run
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap
cd ~/CyberRecon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 in your browser. The app is intentionally bound to localhost.

## Features
- DNS: A, AAAA, MX, NS, TXT and CNAME records
- Public IP resolution
- HTTP response status, redirect chain, selected metadata and headers
- TLS certificate issuer, expiry and negotiated TLS version
- Basic missing-header observations with recommendations
- Optional check of a small list of common TCP ports
- SQLite scan history
- PDF and JSON exports

## Notes
- Missing headers are observations, not proof of an exploitable vulnerability. Review each finding in context.
- CDN, WAF, reverse proxy, DNS load balancing and network filtering can affect results.
- The port check only tests a fixed list of common TCP ports and is not a full port scan. Run active checks only for systems you own or are authorized to assess.
- This is a learning project, not a production-grade scanner. Before public deployment, add authentication, CSRF protections, job queue/timeouts, audit logging, stronger SSRF defenses, and deployment hardening.
