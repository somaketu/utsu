import logging
import requests
import re
import urllib3
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from utsu import utsu_rust_core # type: ignore
    RUST_CORE_ACTIVE = True
except ImportError:
    RUST_CORE_ACTIVE = False
    logging.warning("[!] utsu_rust_core missing. Falling back to slow Python regex.")

# Disable SSL warnings for noisy environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class JSAnalyzer:
    def __init__(self, custom_headers: Optional[Dict[str, str]] = None, threads: int = 10):
        self.headers = custom_headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.timeout = 10
        self.threads = threads

    def _analyze_single(self, target: Dict[str, Any]) -> Dict[str, Any]:
        url = target.get("url", "")
        ws_id = target.get("ws_id")
        intel = {"ws_id": ws_id, "url": url, "paths": [], "secrets": []}
        
        if not url:
            return intel

        try:
            response = requests.get(url, headers=self.headers, verify=False, timeout=self.timeout)
            if response.status_code != 200:
                return intel
            
            content = response.text

            if RUST_CORE_ACTIVE:
                try:
                    # FIXED: Corrected the legacy namespace call
                    rust_paths, rust_secrets = utsu_rust_core.extract_security_intel(content)
                    intel["paths"] = rust_paths
                    intel["secrets"] = [{"type": s[0], "value": s[1], "location": url} for s in rust_secrets]
                    return intel
                except Exception as e:
                    logging.error(f"[-] Rust core analysis crashed on {url}: {e}. Falling back to Python.")

            # Fallback Python Regex
            path_pattern = re.compile(r'(?:"|\')(((?:[a-zA-Z]{1,10}://|/)[^"\'\s]+|([a-zA-Z0-9_\-]+/)+[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9]+)?))(?:"|\')')
            secret_pattern = re.compile(r'(?i)(?:api_key|access_token|secret)[\s:=]+["\']([a-zA-Z0-9_\-]{16,})["\']')

            paths = path_pattern.findall(content)
            intel["paths"] = list(set([p[0] for p in paths]))

            secrets = secret_pattern.findall(content)
            intel["secrets"] = [{"type": "HEURISTIC_SECRET", "value": s, "location": url} for s in set(secrets)]

        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logging.debug(f"[-] JS Analysis failed on {url}: {e}")

        return intel

    def run(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Executes concurrent static code analysis across all target URLs."""
        results = []
        if not targets:
            return results

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self._analyze_single, t): t for t in targets}
            
            for future in as_completed(future_to_target):
                try:
                    data = future.result()
                    results.append(data)
                except Exception as e:
                    logging.debug(f"[-] Thread failure during JS Analysis: {e}")
                    
        return results