import requests
import urllib3
import socket
import ipaddress
import time
import sys
from urllib.parse import urlparse
from threading import Semaphore
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
from utsu.core.logger import log

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LiveProber:
    def __init__(self, threads: int = 10, rps: int = 10, custom_headers: Dict[str, str] = None):
        self.threads = threads
        self.rps = rps
        self._rate_semaphore = Semaphore(self.rps)
        self._last_request_time = 0.0
        self.timeout = 7
        self.custom_headers = custom_headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def _rate_limited_get(self, url: str, host_header: str):
        with self._rate_semaphore:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < 1.0 / self.rps:
                time.sleep((1.0 / self.rps) - elapsed)
            self._last_request_time = time.monotonic()
            
            headers = self.custom_headers.copy()
            headers["Host"] = host_header
            return requests.get(url, headers=headers, verify=False, timeout=self.timeout, allow_redirects=True)

    def _probe_single(self, subdomain_id: int, subdomain: str) -> Dict:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                hostname = urlparse(url).hostname
                # This is the blocking DNS call causing the delay on dead domains
                ip_str = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(ip_str)
                
                if not ip_obj.is_global:
                    log.debug(f"Skipping local/private IP for {url}: {ip_str}")
                    continue
                
                ip_url = url.replace(hostname, ip_str)
                response = self._rate_limited_get(ip_url, host_header=hostname)
                
                title = ""
                if "<title>" in response.text.lower():
                    try:
                        title = response.text.split("<title>")[1].split("</title>")[0][:50]
                    except IndexError as e:
                        log.debug(f"Failed to parse title on {url}: {str(e)}")

                return {
                    "subdomain_id": subdomain_id,
                    "url": url,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "title": title.strip()
                }

            except socket.gaierror:
                log.debug(f"DNS resolution failed for {hostname}")
                continue
            except requests.exceptions.Timeout:
                log.debug(f"Connection timeout probing {url}")
                continue
            except requests.exceptions.RequestException as e:
                log.debug(f"Request failed for {url}: {str(e)}")
                continue
            except ValueError as e:
                log.debug(f"Value error probing {url}: {str(e)}")
                continue
            except Exception as e:
                log.debug(f"Unexpected error probing {url}: {str(e)}", exc_info=True)
                continue
        return {}

    def run(self, targets: Dict[int, str]) -> List[Dict]:
        live_services = []
        total = len(targets)
        completed = 0
        
        # Clear the line and setup the telemetry display
        sys.stdout.write(f"\r[*] Initializing concurrent probe across {total} targets...\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self._probe_single, sub_id, sub): sub for sub_id, sub in targets.items()}
            
            for future in as_completed(future_to_target):
                completed += 1
                result = future.result()
                if result:
                    live_services.append(result)
                
                # Dynamic terminal output (overwrites the same line)
                sys.stdout.write(f"\r    ├── Progress: [{completed}/{total}] | Live Targets Discovered: {len(live_services)}")
                sys.stdout.flush()
                
        print() # Drop to a new line when finished
        return live_services