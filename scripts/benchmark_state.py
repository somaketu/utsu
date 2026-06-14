import time
import uuid
import os
import sys

# Add the parent directory to the path so we can import utsu
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utsu.storage.repository import DeltaDB
from utsu.intelligence.diff import StateEngine

def run_benchmark():
    db_path = "workspace/benchmark.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    db = DeltaDB(db_path)
    engine = StateEngine(db)
    domain = "enterprise-target.internal"

    print("=== UTSU State Engine Benchmark ===")
    print(f"[*] Generating 50,000 synthetic subdomains (Simulating a massive enterprise attack surface)...")
    base_subs = {f"asset-{uuid.uuid4().hex[:8]}.{domain}" for _ in range(50000)}

    print("\n[*] RUN 1: Initial Recon Ingestion (Amnesiac Scanner Behavior)")
    start = time.perf_counter()
    res1 = engine.process_subdomains(domain, base_subs)
    duration1 = time.perf_counter() - start
    print(f"[+] Ingested {len(res1['new_subs_list'])} records.")
    print(f"[+] Time taken: {duration1:.4f} seconds.")

    print("\n[*] Simulating a second scan 24 hours later...")
    print("[*] Generating 5 net-new subdomains (Simulating shadow IT deployment)...")
    new_subs = {f"shadow-api-{i}.{domain}" for i in range(5)}
    
    # The new scan finds the original 50,000 + the 5 new ones
    scan_2_subs = base_subs.union(new_subs)

    print("\n[*] RUN 2: UTSU Diff Engine Execution (Stateful Behavior)")
    start = time.perf_counter()
    res2 = engine.process_subdomains(domain, scan_2_subs)
    duration2 = time.perf_counter() - start

    print(f"[+] Diff Engine isolated exactly {len(res2['new_subs_list'])} new assets.")
    print(f"[+] Time taken: {duration2:.4f} seconds.")
    
    if duration2 < duration1:
        multiplier = duration1 / duration2
        print(f"\n[!] CONCLUSION: State Engine is {multiplier:.2f}x faster than raw ingestion.")
        print("[!] This is the exact time saved by NOT probing 50,000 dead assets.")
    else:
        print("\n[-] Performance degradation detected. Investigate SQLite indexing.")

if __name__ == "__main__":
    run_benchmark()