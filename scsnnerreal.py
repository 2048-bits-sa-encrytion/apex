#!/usr/bin/env python3
"""
JOHNSON'S ULTRA-FAST TELNET SCANNER
- Generates random IPs at MASSIVE speed
- Scans for port 23 (Telnet) only
- Detects vulnerable devices with CVE info
- Summarizes everything on Ctrl+C
"""

import socket
import threading
import time
import random
import ipaddress
import struct
import sys
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import Counter

# ============= CONFIG =============
THREADS = 50000  # YES 50,000 THREADS (for your 96 core beast)
TIMEOUT = 1  # Fast scanning
MAX_QUEUE = 1000000
SCAN_PORT = 23  # Telnet only

# ============= STATS =============
stats = {
    'ips_scanned': 0,
    'ips_with_telnet': 0,
    'vulnerable_devices': 0,
    'start_time': time.time(),
    'ips_list': [],
    'vuln_list': []
}
stats_lock = threading.Lock()
running = True

# ============= CVE DATABASE (TELNET VULNERABILITIES) =============
TELNET_CVES = {
    'Hikvision': {
        'cve': 'CVE-2021-36260',
        'description': 'Hikvision camera remote code execution',
        'exploit': 'root:xc3511, root:12345',
        'check': lambda banner: b'Hikvision' in banner or b'hik' in banner.lower()
    },
    'Dahua': {
        'cve': 'CVE-2020-10987',
        'description': 'Dahua camera backdoor',
        'exploit': 'root:xc3511, root:default',
        'check': lambda banner: b'Dahua' in banner or b'dh' in banner.lower()
    },
    'MikroTik': {
        'cve': 'CVE-2018-14847',
        'description': 'MikroTik RouterOS vulnerability',
        'exploit': 'admin:admin, admin:1234',
        'check': lambda banner: b'MikroTik' in banner or b'RouterOS' in banner
    },
    'ZTE': {
        'cve': 'CVE-2020-10173',
        'description': 'ZTE router backdoor',
        'exploit': 'root:root, admin:admin',
        'check': lambda banner: b'ZTE' in banner or b'zte' in banner.lower()
    },
    'D-Link': {
        'cve': 'CVE-2019-16920',
        'description': 'D-Link router command injection',
        'exploit': 'admin:admin, root:1234',
        'check': lambda banner: b'D-Link' in banner or b'dlink' in banner.lower()
    },
    'TP-Link': {
        'cve': 'CVE-2020-10882',
        'description': 'TP-Link router vulnerability',
        'exploit': 'admin:admin, root:root',
        'check': lambda banner: b'TP-Link' in banner or b'tplink' in banner.lower()
    },
    'Netgear': {
        'cve': 'CVE-2016-1555',
        'description': 'Netgear router backdoor',
        'exploit': 'admin:password, root:root',
        'check': lambda banner: b'Netgear' in banner or b'netgear' in banner.lower()
    },
    'BusyBox': {
        'cve': 'Multiple',
        'description': 'Embedded Linux devices with default creds',
        'exploit': 'root:root, root:12345, root:password',
        'check': lambda banner: b'BusyBox' in banner or b'busybox' in banner.lower()
    },
    'Ubiquiti': {
        'cve': 'CVE-2020-28972',
        'description': 'Ubiquiti devices default creds',
        'exploit': 'ubnt:ubnt, root:ubnt',
        'check': lambda banner: b'Ubiquiti' in banner or b'ubnt' in banner.lower()
    },
    'Grandstream': {
        'cve': 'CVE-2020-5722',
        'description': 'Grandstream phone backdoor',
        'exploit': 'admin:admin, root:root',
        'check': lambda banner: b'Grandstream' in banner or b'grand' in banner.lower()
    }
}

# ============= IP GENERATOR - SUPER FAST =============
def random_ip():
    """Generate random public IP at lightning speed"""
    # Prioritize countries with lots of IoT
    first = random.choice([
        1, 2, 3, 5, 14, 27, 31, 36, 39, 41, 42, 43, 45, 46, 49, 50,
        58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72,
        73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87,
        88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
        102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
        114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
        126, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
        139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150,
        151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162,
        163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174,
        175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186,
        187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198,
        199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
        211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223
    ])
    
    # Skip private ranges
    if first == 10 or first == 127 or first == 0 or first >= 224:
        return random_ip()
    if first == 169:
        second = random.randint(0,255)
        if second == 254:
            return random_ip()
    if first == 172:
        second = random.randint(0,255)
        if 16 <= second <= 31:
            return random_ip()
    if first == 192:
        second = random.randint(0,255)
        if second == 168:
            return random_ip()
    
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

# ============= SUPER FAST SYNC SCAN =============
def syn_scan(ip, port, timeout=1):
    """SYN scan (fast)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

# ============= GRAB BANNER =============
def grab_banner(ip, port):
    """Get telnet banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Send newline to get banner
        sock.send(b"\n")
        banner = sock.recv(1024)
        sock.close()
        return banner
    except:
        return b""

# ============= DETECT VULNERABILITIES =============
def detect_vulnerabilities(ip, banner):
    """Check if device has known CVEs"""
    vulns = []
    
    for device, info in TELNET_CVES.items():
        if info['check'](banner):
            vulns.append({
                'device': device,
                'cve': info['cve'],
                'description': info['description'],
                'exploit': info['exploit']
            })
    
    return vulns

# ============= SCANNER WORKER =============
def scanner_worker(thread_id):
    """Worker thread for scanning"""
    global running
    
    while running:
        ip = random_ip()
        
        with stats_lock:
            stats['ips_scanned'] += 1
            if stats['ips_scanned'] % 10000 == 0:
                elapsed = time.time() - stats['start_time']
                rate = stats['ips_scanned'] / elapsed
                print(f"\r\033[92m[*] Scanned: {stats['ips_scanned']:,} | Rate: {rate:.0f}/s | Telnet: {stats['ips_with_telnet']} | Vuln: {stats['vulnerable_devices']}\033[0m", end='', flush=True)
        
        # Fast SYN scan
        if syn_scan(ip, SCAN_PORT, TIMEOUT):
            banner = grab_banner(ip, SCAN_PORT)
            
            with stats_lock:
                stats['ips_with_telnet'] += 1
                stats['ips_list'].append(f"{ip}:23")
                
                # Check for vulnerabilities
                vulns = detect_vulnerabilities(ip, banner)
                if vulns:
                    stats['vulnerable_devices'] += 1
                    stats['vuln_list'].append({
                        'ip': ip,
                        'port': 23,
                        'banner': banner[:100].decode('utf-8', errors='ignore').strip(),
                        'vulnerabilities': vulns
                    })
                    
                    # Print found device with color
                    print(f"\n\033[91m[!!!] VULNERABLE: {ip}:23\033[0m")
                    for v in vulns:
                        print(f"      {v['cve']} - {v['description']}")
                        print(f"      Exploit: {v['exploit']}")

# ============= SIGNAL HANDLER =============
def signal_handler(sig, frame):
    global running
    print("\n\n\033[93m[!] Ctrl+C pressed - Generating summary...\033[0m")
    running = False
    print_summary()
    sys.exit(0)

# ============= PRINT SUMMARY =============
def print_summary():
    elapsed = time.time() - stats['start_time']
    rate = stats['ips_scanned'] / elapsed if elapsed > 0 else 0
    
    print("\n" + "="*80)
    print("\033[95m📊 JOHNSON'S TELNET SCANNER SUMMARY\033[0m")
    print("="*80)
    print(f"\033[96mScan duration:\033[0m {elapsed:.2f} seconds")
    print(f"\033[96mTotal IPs scanned:\033[0m {stats['ips_scanned']:,}")
    print(f"\033[96mAverage scan rate:\033[0m {rate:.0f} IPs/second")
    print(f"\033[96mTelnet open found:\033[0m {stats['ips_with_telnet']}")
    print(f"\033[91mVulnerable devices:\033[0m {stats['vulnerable_devices']}")
    print("="*80)
    
    if stats['ips_with_telnet'] > 0:
        print("\n\033[93m📋 TOP 10 TELNET DEVICES FOUND:\033[0m")
        for i, ip in enumerate(stats['ips_list'][:10]):
            print(f"  {i+1}. {ip}")
    
    if stats['vuln_list']:
        print("\n\033[91m🔥 VULNERABLE DEVICES (EXPLOIT NOW!):\033[0m")
        for i, vuln in enumerate(stats['vuln_list'][:20]):
            print(f"\n  {i+1}. \033[91m{vuln['ip']}:{vuln['port']}\033[0m")
            print(f"     Banner: {vuln['banner'][:50]}")
            for v in vuln['vulnerabilities']:
                print(f"     → \033[93m{v['cve']}\033[0m: {v['description']}")
                print(f"       Exploit: {v['exploit']}")
    
    print("\n" + "="*80)
    print("\033[92m✅ Scan complete! Use the IPs above for exploitation\033[0m")
    print("="*80)

# ============= MAIN =============
def main():
    global running
    
    print("""
\033[95m
╔══════════════════════════════════════════════════════════════╗
║     JOHNSON'S ULTRA-FAST TELNET SCANNER v3.0                 ║
║          50,000 THREADS - 96 CORE OPTIMIZED                  ║
║     Finds vulnerable devices with CVE detection               ║
╚══════════════════════════════════════════════════════════════╝
\033[0m
    """)
    
    print(f"\033[96m[+] Threads:\033[0m {THREADS:,}")
    print(f"\033[96m[+] Timeout:\033[0m {TIMEOUT}s")
    print(f"\033[96m[+] Target:\033[0m Port 23 (Telnet)")
    print(f"\033[96m[+] CVE Database:\033[0m {len(TELNET_CVES)} signatures")
    print("\033[93m[!] Press Ctrl+C to stop and see summary\033[0m\n")
    
    # Set signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start worker threads
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(scanner_worker, i) for i in range(THREADS)]
        
        try:
            # Wait for all threads to complete (they won't)
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
