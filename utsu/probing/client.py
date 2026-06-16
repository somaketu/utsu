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
            
            self._tokens = min(self._rps, self._tokens + elapsed * self._rps)
            self._last_refill = now
            
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
                
            sleep_time = (1.0 - self._tokens) / self._rps
            self._tokens = 0.0
            self._last_refill = now + sleep_time
            
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
        self.bucket.acquire()
        headers = self.custom_headers.copy()
        headers["Host"] = host_header
        return requests.get(url, headers=headers, verify=False, timeout=self.timeout, allow_redirects=False)

    def _probe_single(self, target: Dict[str, Any]) -> Dict[str, Any]:
        subdomain_id = target["id"]
        current_url = target["url"]
        redirects = 0

        while redirects <= self.max_redirects:
            try:
                parsed = urlparse(current_url)
                hostname = parsed.hostname
                port = parsed.port
                
                if not hostname:
                    break

                ip_str = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(ip_str)
                
                if not ip_obj.is_global:
                    log.warning(f"[-] SSRF Blocked: Dropping request to unsafe host -> {current_url} ({ip_str})")
                    break
                
                # Reconstruct netloc for the internal IP request, preserving custom ports
                netloc = f"{ip_str}:{port}" if port else ip_str
                ip_url = current_url.replace(parsed.netloc, netloc)
                
                # Standard HTTP requests require the port in the Host header if non-standard
                host_header = f"{hostname}:{port}" if port else hostname
                
                response = self._rate_limited_get(ip_url, host_header=host_header)
                
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

            except Exception as e:
                # Silently catch timeouts/refusals as the port might be open but not speaking HTTP
                break
                
        return {}

    def run(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        live_services = []
        total = len(targets)
        completed = 0
        
        sys.stdout.write(f"\r[*] Initializing concurrent probe across {total} verified targets...\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self._probe_single, target): target for target in targets}
            
            for future in as_completed(future_to_target):
                completed += 1
                result = future.result()
                if result:
                    live_services.append(result)
                
                sys.stdout.write(f"\r    ├── Progress: [{completed}/{total}] | Live Targets Discovered: {len(live_services)}")
                sys.stdout.flush()
                
        print()
        return live_services