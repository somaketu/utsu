import sys
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from utsu.storage.repository import DeltaDB
from utsu.core.logger import log

try:
    from utsu import utsu_rust_core  # type: ignore
except ImportError:
    utsu_rust_core = None

class DeepCrawler:
    def __init__(self, db: DeltaDB, threads: int = 10, max_depth: int = 1):
        self.db = db
        self.threads = threads
        self.max_depth = max_depth

    def _crawl_single(self, ws_id: int, url: str) -> Dict[str, Any]:
        if not utsu_rust_core:
            return {"ws_id": ws_id, "url": url, "error": "Rust core missing"}
        
        try:
            # The Rust core releases the Python GIL during the network request
            results = utsu_rust_core.crawl_url(url, self.max_depth)
            results["ws_id"] = ws_id
            results["url"] = url
            return results
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
                
                # Combine standard links and form endpoints into a unified attack surface mapping
                endpoints = set(res.get("links", [])) | set(res.get("forms", []))
                scripts = set(res.get("scripts", []))
                
                for ep in endpoints:
                    self.db.add_endpoint(web_service_id=ws_id, path=ep, source="rust_crawler")
                for script in scripts:
                    self.db.add_endpoint(web_service_id=ws_id, path=script, source="rust_crawler_script")
                    
                total_endpoints += len(endpoints) + len(scripts)
                
                sys.stdout.write(f"\r    ├── Crawl Progress: [{completed}/{total}] | Deep Endpoints Extracted: {total_endpoints}")
                sys.stdout.flush()
        print()