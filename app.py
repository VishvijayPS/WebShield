import io, json, os, socket, ssl, sqlite3, ipaddress, subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import requests
from flask import Flask, jsonify, render_template, request, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, 'scans.db')
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

SECURITY_HEADERS = {
    'Strict-Transport-Security': ('Medium', 'Configure HSTS on HTTPS after confirming all required subdomains support HTTPS.'),
    'Content-Security-Policy': ('Medium', 'Define a Content Security Policy appropriate for the application.'),
    'X-Content-Type-Options': ('Low', 'Set X-Content-Type-Options: nosniff.'),
    'X-Frame-Options': ('Low', 'Set an appropriate X-Frame-Options policy or use frame-ancestors in CSP.'),
    'Referrer-Policy': ('Low', 'Set a suitable Referrer-Policy, such as strict-origin-when-cross-origin.'),
    'Permissions-Policy': ('Info', 'Consider limiting browser features with Permissions-Policy.')
}
COMMON_PORTS = [21,22,25,53,80,110,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017]


def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )''')
init_db()


def normalize_target(raw):
    raw = (raw or '').strip()
    if not raw or len(raw) > 253:
        raise ValueError('Enter a valid domain name or website URL.')
    if '://' not in raw:
        raw = 'https://' + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Use a domain name or an http/https URL.')
    if parsed.username or parsed.password:
        raise ValueError('URLs containing usernames or passwords are not supported.')
    host = parsed.hostname.rstrip('.').lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Validate a DNS hostname and reject local-only names.
        if '.' not in host or any(not label or len(label) > 63 for label in host.split('.')):
            raise ValueError('Enter a fully qualified domain such as example.com.')
        if any(not (label[0].isalnum() and label[-1].isalnum() and all(c.isalnum() or c == '-' for c in label)) for label in host.split('.')):
            raise ValueError('The domain contains invalid characters.')
    return host, raw


def resolve_public_ips(host):
    ips = set()
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            ip = item[4][0].split('%')[0]
            addr = ipaddress.ip_address(ip)
            if addr.is_global:
                ips.add(ip)
    except socket.gaierror:
        pass
    return sorted(ips)


def dns_records(host):
    out = {}
    for kind in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
        try:
            answers = dns.resolver.resolve(host, kind, lifetime=3)
            vals = []
            for r in answers:
                if kind == 'MX': vals.append({'priority': r.preference, 'host': str(r.exchange).rstrip('.')})
                elif kind == 'TXT': vals.append(''.join(part.decode(errors='replace') for part in r.strings))
                else: vals.append(str(r).rstrip('.'))
            out[kind] = vals
        except Exception:
            out[kind] = []
    return out


def tls_info(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                def fmt(name):
                    return ' '.join(x[0][1] for x in cert.get(name, []))
                not_after = cert.get('notAfter')
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc).isoformat() if not_after else None
                return {'valid': True, 'subject': fmt('subject'), 'issuer': fmt('issuer'), 'expires_at': expiry, 'tls_version': ssock.version()}
    except Exception as e:
        return {'valid': False, 'error': str(e)[:180]}


def http_check(url):
    # Requests follows normal redirects but blocks redirects to non-public destinations.
    session = requests.Session()
    session.headers['User-Agent'] = 'CyberRecon-Student-Project/1.0'
    current = url
    history = []
    response = None
    for _ in range(6):
        parsed = urlparse(current)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Invalid redirect URL.')
        ips = resolve_public_ips(parsed.hostname)
        if not ips:
            raise ValueError('The host did not resolve to a public IP address.')
        response = session.get(current, timeout=7, allow_redirects=False, stream=True)
        history.append({'url': current, 'status': response.status_code})
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get('Location')
            response.close()
            if not location: break
            from urllib.parse import urljoin
            current = urljoin(current, location)
            continue
        break
    if response is None:
        raise ValueError('No HTTP response received.')
    headers = {k: v for k, v in response.headers.items()}
    data = {'requested_url': url, 'final_url': current, 'status_code': response.status_code,
            'reason': response.reason, 'server_header': headers.get('Server', 'Not disclosed'),
            'content_type': headers.get('Content-Type', 'Not disclosed'), 'redirects': history,
            'headers': headers, 'https': urlparse(current).scheme == 'https'}
    response.close()
    findings = []
    for header, (severity, fix) in SECURITY_HEADERS.items():
        present = header in headers
        if not present and (header != 'Strict-Transport-Security' or data['https']):
            findings.append({'severity': severity, 'title': f'Missing {header}', 'evidence': f'{header} response header was not observed.', 'recommendation': fix})
    if not data['https']:
        findings.append({'severity': 'Medium', 'title': 'HTTP URL used', 'evidence': 'The final URL does not use HTTPS.', 'recommendation': 'Serve the site over HTTPS and redirect HTTP requests to HTTPS.'})
    cookie_headers = [v for k, v in headers.items() if k.lower() == 'set-cookie']
    for cookie in cookie_headers:
        missing = []
        if 'secure' not in cookie.lower(): missing.append('Secure')
        if 'httponly' not in cookie.lower(): missing.append('HttpOnly')
        if 'samesite' not in cookie.lower(): missing.append('SameSite')
        if missing:
            findings.append({'severity': 'Low', 'title': 'Cookie attributes not observed', 'evidence': 'A Set-Cookie header lacks: ' + ', '.join(missing), 'recommendation': 'Review cookie scope and set Secure, HttpOnly and SameSite where appropriate.'})
    return data, findings


def scan_ports(host, enabled):
    if not enabled:
        return {'status': 'Skipped', 'message': 'Active port scan was not selected.', 'ports': []}
    ips = resolve_public_ips(host)
    if not ips:
        return {'status': 'Unavailable', 'message': 'No public IP address resolved.', 'ports': []}
    # This is a deliberately small TCP connect scan of common ports, not a full-range scan.
    ip = ips[0]
    found = []
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=0.45):
                found.append({'port': port, 'state': 'open', 'service': socket.getservbyport(port, 'tcp') if port < 1024 else 'unknown'})
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return {'status': 'Completed', 'target_ip': ip, 'ports_checked': len(COMMON_PORTS), 'ports': found,
            'message': 'Only the listed common TCP ports were tested. An absent result does not prove a port is closed.'}


def make_findings_summary(findings):
    counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for item in findings:
        if item['severity'] in counts: counts[item['severity']] += 1
    return counts


@app.get('/')
def index():
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute('SELECT id,target,created_at FROM scans ORDER BY id DESC LIMIT 8').fetchall()
    return render_template('index.html', history=rows)


@app.post('/api/scan')
def api_scan():
    body = request.get_json(silent=True) or {}
    try:
        host, original_url = normalize_target(body.get('target'))
        # Prevent direct probing of private, loopback, link-local and reserved IP literals.
        try:
            literal = ipaddress.ip_address(host)
            if not literal.is_global:
                return jsonify({'error': 'Private, loopback and reserved IP targets are not supported by this public-domain scanner.'}), 400
        except ValueError:
            pass
        ips = resolve_public_ips(host)
        if not ips:
            return jsonify({'error': 'The domain did not resolve to a public IP address.'}), 400
        dns = dns_records(host)
        http_data, findings = http_check(original_url)
        tls = tls_info(host) if http_data['https'] or host else {'valid': False, 'error': 'HTTPS not selected'}
        port_result = scan_ports(host, bool(body.get('port_scan')))
        findings.extend([
            {'severity': 'Info', 'title': 'Public IP addresses resolved', 'evidence': ', '.join(ips), 'recommendation': 'Compare DNS answers with the expected hosting and CDN configuration.'}
        ])
        if port_result['ports']:
            findings.append({'severity': 'Info', 'title': 'Common TCP ports responded', 'evidence': ', '.join(str(p['port']) for p in port_result['ports']), 'recommendation': 'Confirm that each exposed service is required and appropriately protected.'})
        result = {'target': host, 'scan_time': datetime.now(timezone.utc).isoformat(), 'ip_addresses': ips,
                  'dns': dns, 'http': http_data, 'tls': tls, 'port_scan': port_result,
                  'findings': findings, 'severity_counts': make_findings_summary(findings)}
        with sqlite3.connect(DB_PATH) as con:
            cur = con.execute('INSERT INTO scans(target,created_at,result_json) VALUES(?,?,?)', (host, result['scan_time'], json.dumps(result)))
            result['scan_id'] = cur.lastrowid
            con.commit()
        return jsonify(result)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except requests.RequestException as e:
        return jsonify({'error': f'HTTP request failed: {str(e)[:180]}'}), 502
    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)[:180]}'}), 500


@app.get('/api/history')
def api_history():
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute('SELECT id,target,created_at FROM scans ORDER BY id DESC LIMIT 30').fetchall()
    return jsonify([{'id': r[0], 'target': r[1], 'created_at': r[2]} for r in rows])


@app.get('/api/report/<int:scan_id>.json')
def json_report(scan_id):
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute('SELECT result_json FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not row: return jsonify({'error': 'Report not found'}), 404
    return app.response_class(row[0], mimetype='application/json', headers={'Content-Disposition': f'attachment; filename=cyberrecon-{scan_id}.json'})


@app.get('/api/report/<int:scan_id>.pdf')
def pdf_report(scan_id):
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute('SELECT result_json FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not row: return jsonify({'error': 'Report not found'}), 404
    data = json.loads(row[0])
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=38, leftMargin=38, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story = [Paragraph('CyberRecon Intelligence — Scan Report', styles['Title']), Spacer(1, 10),
             Paragraph(f"Target: {data['target']}", styles['Heading2']),
             Paragraph(f"Scan time (UTC): {data['scan_time']}", styles['Normal']),
             Paragraph('IP addresses: ' + ', '.join(data['ip_addresses']), styles['Normal']), Spacer(1, 12),
             Paragraph('HTTP and TLS', styles['Heading2']),
             Paragraph(f"HTTP status: {data['http']['status_code']} | Final URL: {data['http']['final_url']}", styles['Normal']),
             Paragraph('TLS: ' + json.dumps(data['tls'], ensure_ascii=True), styles['Normal']), Spacer(1, 12),
             Paragraph('DNS records', styles['Heading2'])]
    dns_rows = [['Record', 'Values']]
    for k, v in data['dns'].items(): dns_rows.append([k, json.dumps(v, ensure_ascii=True)[:500] or 'None observed'])
    tbl = Table(dns_rows, colWidths=[70, 430])
    tbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#172033')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),0.4,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),8),('WORDWRAP',(0,0),(-1,-1),True)]))
    story += [tbl, Spacer(1, 12), Paragraph('Findings', styles['Heading2'])]
    finding_rows = [['Severity', 'Finding', 'Evidence / recommendation']]
    for f in data['findings']:
        finding_rows.append([f['severity'], f['title'], (f['evidence'] + ' Recommendation: ' + f['recommendation'])[:700]])
    ft = Table(finding_rows, colWidths=[55, 130, 315], repeatRows=1)
    ft.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#172033')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),0.4,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),7)]))
    story += [ft, Spacer(1, 12), Paragraph('Port scan: ' + json.dumps(data['port_scan'], ensure_ascii=True)[:1200], styles['Normal'])]
    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=f'cyberrecon-{scan_id}.pdf')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
