from typing import Set, Dict, Any
from utsu.core.logger import log
from utsu.storage.repository import DeltaDB

class StateEngine:
    def __init__(self, db: DeltaDB):
        self.db = db

    def process_subdomains(self, domain: str, current_subs: Set[str]) -> Dict[str, Any]:
        """
        Calculates the delta between current recon and historical state.
        Updates the database and returns only actionable, net-new targets.
        """
        # Ensure the root domain exists and get its ID
        domain_id = self.db.add_domain(domain)
        
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            
            # Fetch historical subdomains
            cursor.execute('SELECT subdomain FROM subdomains WHERE domain_id = ?', (domain_id,))
            historical_subs = {row[0] for row in cursor.fetchall()}
            
            # The Diffing Logic
            new_subs = current_subs - historical_subs
            dead_subs = historical_subs - current_subs
            unchanged_subs = current_subs.intersection(historical_subs)
            
            # 1. Insert new subdomains
            if new_subs:
                cursor.executemany(
                    'INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)',
                    [(domain_id, sub) for sub in new_subs]
                )
            
            # 2. Update 'last_seen' timestamp for existing subdomains
            if unchanged_subs:
                cursor.executemany(
                    'UPDATE subdomains SET last_seen = CURRENT_TIMESTAMP WHERE domain_id = ? AND subdomain = ?',
                    [(domain_id, sub) for sub in unchanged_subs]
                )
            
            # 3. Retrieve the database IDs for the newly inserted subdomains
            # The LiveProber requires a dictionary of {id: subdomain} to map results later
            new_sub_ids = {}
            if new_subs:
                placeholders = ','.join(['?'] * len(new_subs))
                query = f"SELECT id, subdomain FROM subdomains WHERE domain_id = ? AND subdomain IN ({placeholders})"
                cursor.execute(query, [domain_id] + list(new_subs))
                new_sub_ids = {row[1]: row[0] for row in cursor.fetchall()}
            
        log.info(
            f"[State Engine] Diff complete for {domain} | "
            f"New: {len(new_subs)} | "
            f"Dead: {len(dead_subs)} | "
            f"Unchanged: {len(unchanged_subs)}"
        )
        
        return {
            "new_subs_list": new_subs,
            "new_subs_map": new_sub_ids, # Pass this directly to LiveProber
            "dead_subs": dead_subs,
            "unchanged_subs": unchanged_subs
        }