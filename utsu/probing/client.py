import requests
import urllib3
import socket
import ipaddress
import time
import sys
from urllib.parse import urlparse, urljoin
from threading import Semaphore
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
from utsu.core.logger import log

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LiveProber:
    def __init__(self, threads: int = 10, rps: int = 10, custom_headers: Optional[Dict[str, str]] = None):
        self.threads = threads
        self.rps = rps
        self._rate_semaphore = Semaphore(self.rps)
        self._last_request_time = 0.0
        self.timeout = 7
        self.max_redirects = 3 # Hard limit to prevent infinite loops
        
        self.custom_headers: Dict[str, str] = custom_headers if custom_headers is not None else {
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
            # FATAL FLAW FIXED: We trap redirects manually instead of letting requests bypass validation
            return requests.get(url, headers=headers, verify=False, timeout=self.timeout, allow_redirects=False)

    def _probe_single(self, subdomain_id: int, subdomain: str) -> Dict[str, Any]:
        for scheme in ["https", "http"]:
            current_url = f"{scheme}://{subdomain}"
            redirects = 0

            while redirects <= self.max_redirects:
                try:
                    hostname = urlparse(current_url).hostname
                    
                    if not hostname:
                        log.debug(f"Could not parse valid hostname from URL: {current_url}")
                        break # Break the redirect loop, try next scheme

                    # DNS resolution & SSRF check executed on EVERY hop
                    ip_str = socket.gethostbyname(hostname)
                    ip_obj = ipaddress.ip_address(ip_str)
                    
                    if not ip_obj.is_global:
                        log.warning(f"[-] SSRF Blocked: Dropping request to unsafe host -> {current_url} ({ip_str})")
                        break # Kill the request completely
                    
                    ip_url = current_url.replace(hostname, ip_str)
                    response = self._rate_limited_get(ip_url, host_header=hostname)
                    
                    # Manual Redirect Interception
                    if 300 <= response.status_code < 400 and 'Location' in response.headers:
                        next_url = urljoin(current_url, response.headers['Location'])
                        log.debug(f"[*] Validating and following redirect: {current_url} -> {next_url}")
                        current_url = next_url
                        redirects += 1
                        continue # Re-run the loop to validate the next hop's IP
                    
                    title = ""
                    if "<title>" in response.text.lower():
                        try:
                            title_split = response.text.lower().split("<title>")
                            if len(title_split) > 1:
                                title = title_split[1].split("</title>")[0][:50]
                        except Exception as e:
                            log.debug(f"Failed to parse title on {current_url}: {str(e)}")

                    return {
                        "subdomain_id": subdomain_id,
                        "url": current_url, # Save the final URL, not just the starting one
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "title": title.strip()
                    }

                except socket.gaierror:
                    log.debug(f"DNS resolution failed for {hostname if 'hostname' in locals() and hostname else current_url}")
                    break
                except requests.exceptions.Timeout:
                    log.debug(f"Connection timeout probing {current_url}")
                    break
                except requests.exceptions.RequestException as e:
                    log.debug(f"Request failed for {current_url}: {str(e)}")
                    break
                except ValueError as e:
                    log.debug(f"Value error probing {current_url}: {str(e)}")
                    break
                except Exception as e:
                    log.debug(f"Unexpected error probing {current_url}: {str(e)}", exc_info=True)
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