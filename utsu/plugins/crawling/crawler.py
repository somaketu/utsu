import sys
from typing import Dict, List, Any
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utsu.storage.repository import DeltaDB
from utsu.core.logger import log
from utsu.core.config import ConfigManager

try:
    from utsu import utsu_rust_core  # type: ignore
except ImportError:
    utsu_rust_core = None

class DeepCrawler:
    def __init__(self, db: DeltaDB, threads: int = 10, max_depth: int = 1):
        self.db = db
        # Instantiate globally for the class ONCE to preserve thread performance
        self.cfg = ConfigManager()  
        self.threads = threads
        
        # Override depth dynamically if defined in the active profile, else fallback to default
        self.max_depth = getattr(self.cfg, "crawl_depth", max_depth)
        
        # The Gatekeeper: Do not waste DB rows or AI context on these
        self.noise_extensions = (
            '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', 
            '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.wav', 
            '.mp3', '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z'
        )

    def _is_viable_target(self, url: str) -> bool:
        """Deterministic filter to drop static assets before they hit the AI."""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            if path.endswith(self.noise_extensions):
                return False
            return True
        except Exception:
            return False

    def _crawl_single(self, ws_id: int, url: str) -> Dict[str, Any]:
        if not utsu_rust_core:
            return {"ws_id": ws_id, "url": url, "error": "Rust core missing"}
        
        try:
            # 1. Extract raw headers
            raw_headers = getattr(self.cfg, "custom_headers", None)
            
            # 2. Bulletproof Type Sanitizer: Rust strictly expects a List of Strings
            custom_headers = None
            if isinstance(raw_headers, dict):
                custom_headers = [f"{k}: {v}" for k, v in raw_headers.items()]
            elif isinstance(raw_headers, list):
                custom_headers = [str(h) for h in raw_headers]
            
            # 3. Pass the sanitized state to the Rust engine
            result = utsu_rust_core.crawl_url(url, self.max_depth, custom_headers)
            
            # 4. Append context to the returned dictionary
            result["ws_id"] = ws_id
            result["url"] = url
            
            return result
            
        except Exception as e:
            return {"ws_id": ws_id, "url": url, "error": str(e)}

    def run(self, targets: List[Dict[str, Any]]):
        if not targets:
            return
            
        completed = 0
        total = len(targets)
        total_endpoints = 0
        
        sys.stdout.write(f"[*] Launching Native Rust Crawler across {total} targets (Depth: {self.max_depth})...\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._crawl_single, t["ws_id"], t["url"]): t for t in targets}
            
            for future in as_completed(futures):
                completed += 1
                res = future.result()
                
                if "error" in res:
                    log.debug(f"Crawler failed on {res['url']}: {res['error']}")
                    continue
                    
                ws_id = res["ws_id"]
                
                raw_endpoints = set(res.get("links", [])) | set(res.get("forms", []))
                raw_scripts = set(res.get("scripts", []))
                
                # Filter general links through the heuristic gatekeeper
                viable_endpoints = {ep for ep in raw_endpoints if self._is_viable_target(ep)}
                
                # We strictly keep scripts because they contain API keys and routing logic
                for ep in viable_endpoints:
                    self.db.add_endpoint(web_service_id=ws_id, path=ep, source="rust_crawler")
                for script in raw_scripts:
                    self.db.add_endpoint(web_service_id=ws_id, path=script, source="rust_crawler_script")
                    
                total_endpoints += len(viable_endpoints) + len(raw_scripts)
                
                sys.stdout.write(f"\r    ├── Crawl Progress: [{completed}/{total}] | Viable Endpoints Extracted: {total_endpoints}")
                sys.stdout.flush()
        print()