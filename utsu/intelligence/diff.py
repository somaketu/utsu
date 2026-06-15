import json
from typing import Dict, Any
from utsu.storage.repository import DeltaDB
from utsu.core.logger import log

class DiffEngine:
    def __init__(self, db_path: str = "data/utsu.db"):
        self.db = DeltaDB(db_path)

    def calculate_delta(self, domain: str, scan_start_utc: str) -> Dict[str, Any]:
        """
        Compares the current scan's findings against the historical baseline.
        Returns a strictly structured JSON delta of net-new attack surface assets.
        """
        log.info(f"[*] Calculating attack surface delta for {domain} since {scan_start_utc}")
        
        new_subdomains = self.db.get_new_subdomains(domain, scan_start_utc)
        new_endpoints = self.db.get_new_endpoints(domain, scan_start_utc)
        new_secrets = self.db.get_new_secrets(domain, scan_start_utc)

        delta = {
            "domain": domain,
            "baseline_timestamp": scan_start_utc,
            "summary": {
                "new_subdomains_count": len(new_subdomains),
                "new_endpoints_count": len(new_endpoints),
                "new_secrets_count": len(new_secrets)
            },
            "net_new_assets": {
                "subdomains": new_subdomains,
                "endpoints": new_endpoints,
                "secrets": new_secrets
            }
        }
        
        total_new_assets = sum(delta["summary"].values())
        if total_new_assets > 0:
            log.info(f"[+] Diff Engine isolated {total_new_assets} net-new assets.")
        else:
            log.info("[-] No net-new assets discovered in this scan cycle.")
            
        return delta