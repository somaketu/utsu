import requests
import urllib3
import socket
import ipaddress
import time
import sys
import threading
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
from utsu.core.logger import log

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TokenBucket:
    def __init__(self, rps: float):
        self._rps = rps
        self._tokens = rps
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        sleep_time = 0.0
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            
            # Refill tokens based on elapsed time, capped at max RPS
            self._tokens = min(self._rps, self._tokens + elapsed * self._rps)
            self._last_refill = now
            
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return  # Fast path: Token acquired, no sleep needed
                
            # Calculate exact sleep required to generate 1 full token
            sleep_time = (1.0 - self._tokens) / self._rps
            
            # Pre-consume the token and advance the refill timer
            self._tokens = 0.0
            self._last_refill = now + sleep_time
            
        # Sleep OUTSIDE the lock to prevent thread contention
        if sleep_time > 0:
            time.sleep(sleep_time)

class LiveProber:
    def __init__(self, threads: int = 10, rps: int = 10, custom_headers: Optional[Dict[str, str]] = None):
        self.threads = threads
        self.rps = rps
        self.bucket = TokenBucket(float(self.rps))
        self.timeout = 7
        self.max_redirects = 3
        
        self.custom_headers: Dict[str, str] = custom_headers if custom_headers is not None else {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def _rate_limited_get(self, url: str, host_header: str):
        # Enforce strict cryptographic-grade pacing
        self.bucket.acquire()
        
        headers = self.custom_headers.copy()
        headers["Host"] = host_header
        return requests.get(url, headers=headers, verify=False, timeout=self.timeout, allow_redirects=False)

    def _probe_single(self, subdomain_id: int, subdomain: str) -> Dict[str, Any]:
        for scheme in ["https", "http"]:
            current_url = f"{scheme}://{subdomain}"
            redirects = 0

            while redirects <= self.max_redirects:
                try:
                    hostname = urlparse(current_url).hostname
                    
                    if not hostname:
                        break

                    ip_str = socket.gethostbyname(hostname)
                    ip_obj = ipaddress.ip_address(ip_str)
                    
                    if not ip_obj.is_global:
                        log.warning(f"[-] SSRF Blocked: Dropping request to unsafe host -> {current_url} ({ip_str})")
                        break
                    
                    ip_url = current_url.replace(hostname, ip_str)
                    response = self._rate_limited_get(ip_url, host_header=hostname)
                    
                    if 300 <= response.status_code < 400 and 'Location' in response.headers:
                        current_url = urljoin(current_url, response.headers['Location'])
                        redirects += 1
                        continue
                    
                    title = ""
                    if "<title>" in response.text.lower():
                        try:
                            title = response.text.lower().split("<title>")[1].split("</title>")[0][:50]
                        except Exception: pass

                    return {
                        "subdomain_id": subdomain_id,
                        "url": current_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "title": title.strip()
                    }

                except Exception:
                    break
        return {}

    def run(self, targets: Dict[int, str]) -> List[Dict[str, Any]]:
        live_services = []
        total = len(targets)
        completed = 0
        
        sys.stdout.write(f"\r[*] Initializing concurrent probe across {total} targets...\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self._probe_single, sub_id, sub): sub for sub_id, sub in targets.items()}
            
            for future in as_completed(future_to_target):
                completed += 1
                result = future.result()
                if result:
                    live_services.append(result)
                
                sys.stdout.write(f"\r    ├── Progress: [{completed}/{total}] | Live Targets Discovered: {len(live_services)}")
                sys.stdout.flush()
                
        print()
        return live_services