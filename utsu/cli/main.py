import argparse
import sys
import os
import time
import sqlite3
from datetime import datetime
from utsu.storage.repository import DeltaDB
from utsu.core.config import ConfigManager
from utsu.ai.pipeline import TriageAgent
from utsu.ai.delta_agent import DeltaAgent
from utsu.plugins.subdomain.recon import ReconEngine
from utsu.probing.client import LiveProber
from utsu.plugins.js_analysis.analyzer import JSAnalyzer
from utsu.plugins.crawling.crawler import DeepCrawler
from utsu.plugins.vulnerability.scanner import NucleiEngine
from utsu.core.reporting import ReportManager
from utsu.intelligence.diff import DiffEngine
from utsu.core.logger import log

try:
    from utsu import utsu_rust_core  # type: ignore
    RUST_CORE_ACTIVE = True
except ImportError:
    RUST_CORE_ACTIVE = False

def initialize_profile(profile_path: str):
    cfg = ConfigManager()
    cfg.load_profile(profile_path)

def cmd_scan(args):
    if not RUST_CORE_ACTIVE:
        log.error("FATAL: Native Rust core (utsu_rust_core) is not installed or failed to load.")
        log.error("Please run ./install.sh to compile the extraction engine.")
        sys.exit(1)

    initialize_profile(args.profile)
    cfg = ConfigManager()
    target_domain = args.target

    # Capture the exact start time to calculate the Attack Surface Delta later
    scan_start_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    if args.force:
        log.info(f"--force flag detected. Wiping operational database at {cfg.db_path}...")
        if os.path.exists(cfg.db_path):
            os.remove(cfg.db_path)
            
    db = DeltaDB(cfg.db_path)
    
    log.info(f"Target: {target_domain}")
    log.info("Phase 1: Gathering passive intelligence...")

    engine = ReconEngine(target_domain)
    discovered_assets = engine.run_all()
    discovered_assets.add(target_domain)

    log.info("Phase 2: Syncing assets with local state repository...")
    new_assets_to_probe = {}
    domain_id = db.add_domain(target_domain)
    
    # Safely ingest subdomains and extract only the net-new ones for probing
    with db._get_connection() as conn:
        cursor = conn.cursor()
        for sub in discovered_assets:
            try:
                cursor.execute("INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)", (domain_id, sub))
                sub_id = cursor.lastrowid
                new_assets_to_probe[sub_id] = sub
            except sqlite3.IntegrityError:
                pass # Asset already exists in historical state
                
    log.info(f"Found {len(new_assets_to_probe)} net-new assets targeting execution queue.")
    
    live_urls = []

    if new_assets_to_probe:
        log.info("Phase 3: Launching Live Prober on Targets...")
        prober = LiveProber(threads=cfg.prober_threads, rps=cfg.rate_limit_rps, custom_headers=cfg.custom_headers)
        live_services = prober.run(new_assets_to_probe)

        log.info("Phase 4: Committing verified web services to State Engine...")
        crawler_targets = []
        
        for service in live_services:
            live_urls.append(service["url"])
            db.add_web_service(
                subdomain_id=service["subdomain_id"],
                url=service["url"],
                status_code=service["status_code"],
                content_length=service["content_length"],
                title=service["title"]
            )
            
            service_id = db.get_web_service_id_by_url(service["url"])
            if service_id:
                crawler_targets.append({"ws_id": service_id, "url": service["url"]})
                db.mark_scanned(service["subdomain_id"])

        if crawler_targets:
            log.info("Phase 5: Engaging Rust Engine for Deep DOM Extraction...")
            crawler = DeepCrawler(db, threads=cfg.prober_threads, max_depth=1)
            crawler.run(crawler_targets)

            log.info("Phase 6: Executing Static Code Analysis (JS Secrets)...")
            sys.stdout.write(f"[*] Parsing scripts across {len(crawler_targets)} targets...\n")
            completed = 0
            
            for target in crawler_targets:
                completed += 1
                analyzer = JSAnalyzer(target["url"], custom_headers=cfg.custom_headers)
                intel = analyzer.analyze()

                if intel["paths"]:
                    for path in intel["paths"]:
                        db.add_endpoint(web_service_id=target["ws_id"], path=path, source="js_analyzer")

                if intel["secrets"]:
                    log.warning(f"\n[!] CRITICAL: Found {len(intel['secrets'])} potential credentials on {target['url']}!")
                    for secret in intel["secrets"]:
                        # Encrypted safely via the Vault under the hood
                        db.add_secret(web_service_id=target["ws_id"], secret_type=secret["type"], value=secret["value"], location=secret["location"])
                
                sys.stdout.write(f"\r    ├── Analysis Progress: [{completed}/{len(crawler_targets)}]")
                sys.stdout.flush()
            print()
    else:
        log.info("No new assets require probing or static code analysis.")

    # ==========================================
    # PHASE 3 ARCHITECTURE: INTELLIGENCE ENGINE
    # ==========================================
    log.info("Phase 7: Calculating Attack Surface Delta...")
    diff_engine = DiffEngine(db_path=cfg.db_path)
    delta = diff_engine.calculate_delta(target_domain, scan_start_utc)

    # ==========================================
    # PHASE 7.5: TARGETED VULNERABILITY SCANNING
    # ==========================================
    log.info("Phase 7.5: Executing Stealth Vulnerability Scanning (Nuclei)...")
    if live_urls:
        nuclei_engine = NucleiEngine()
        vulnerability_findings = nuclei_engine.scan(live_urls)
        # Append findings directly into the state dictionary to pass to the Groq context window
        delta["verified_vulnerabilities"] = vulnerability_findings
    else:
        log.info("[*] Zero net-new live services isolated in this cycle. Bypassing Nuclei.")
        delta["verified_vulnerabilities"] = []

    log.info("Phase 8: Executing AI Threat Modeling on Delta...")
    delta_agent = DeltaAgent()
    threat_report = delta_agent.analyze(delta)
    
    print("\n" + "="*50)
    print("      ATTACK SURFACE THREAT REPORT (GROQ 70B)      ")
    print("="*50)
    print(threat_report)
    print("="*50 + "\n")

    if live_urls:
        reporter = ReportManager()
        target_file = reporter.save_scan_targets(target_domain, live_urls)
        log.info(f"Flat target list exported to: {target_file}")
        
    log.info(f"Processing complete. Attack surface data fully structured inside {cfg.db_path}")

def cmd_triage(args):
    initialize_profile(args.profile)
    cfg = ConfigManager()
    target = args.target
    scope_rules = ""
    if cfg.scope_file:
        try:
            with open(cfg.scope_file, "r", encoding="utf-8") as f:
                scope_rules = f.read()
        except Exception:
            pass

    db = DeltaDB(cfg.db_path)
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, url FROM web_services WHERE url LIKE ?', (f"%{target}%",))
        result = cursor.fetchone()
        if not result:
            log.error(f"Target '{target}' not found in database.")
            return

    ws_id, exact_url = result[0], result[1]
    
    log.info(f"Initiating Cloud AI Triage (Groq 70B) for target: {exact_url}...")
    agent = TriageAgent()
    reporter = ReportManager()
    
    report = agent.run(web_service_id=ws_id, url=exact_url, scope_rules=scope_rules)
    if report:
        print(f"\n{report}")
        reporter.save_triage_report(exact_url, report)
        log.info(f"Output appended to {reporter.master_hunt_log}")

def cmd_hunt(args):
    initialize_profile(args.profile)
    cfg = ConfigManager()
    scope_rules = ""
    if cfg.scope_file:
        try:
            with open(cfg.scope_file, "r", encoding="utf-8") as f:
                scope_rules = f.read()
        except Exception:
            pass

    db = DeltaDB(cfg.db_path)
    reporter = ReportManager()
    
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT w.id, w.url 
            FROM web_services w
            LEFT JOIN endpoints e ON w.id = e.web_service_id
            LEFT JOIN leaked_secrets s ON w.id = s.web_service_id
            WHERE w.status_code IN (200, 401, 403) 
            AND (e.id IS NOT NULL OR s.id IS NOT NULL)
        ''')
        viable_targets = cursor.fetchall()

    if not viable_targets:
        log.info("No viable targets with extracted intelligence found for hunting.")
        return

    log.info(f"Hunt Execution Started. {len(viable_targets)} viable targets in AI queue.")
    agent = TriageAgent()
    
    for index, (ws_id, exact_url) in enumerate(viable_targets, 1):
        log.info(f"[{index}/{len(viable_targets)}] Processing {exact_url} through Groq 70B engine...")
        try:
            report = agent.run(web_service_id=ws_id, url=exact_url, scope_rules=scope_rules)
            if report:
                print(f"\n{report}\n")
                reporter.save_triage_report(exact_url, report)
            
            time.sleep(1) 
            
        except Exception as e:
            log.error(f"    └── [!] Triage failed on {exact_url}: {e}")
            continue
            
    log.info(f"Hunt phase complete. Review your findings in {reporter.master_hunt_log}")

def main():
    parser = argparse.ArgumentParser(description="Asymmetric Attack Surface Management Framework")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--profile", "-p", required=True)
    scan_parser.add_argument("--force", action="store_true", help="Wipe database and force a fresh scan")
    scan_parser.set_defaults(func=cmd_scan)

    triage_parser = subparsers.add_parser("triage")
    triage_parser.add_argument("target")
    triage_parser.add_argument("--profile", "-p", required=True)
    triage_parser.set_defaults(func=cmd_triage)

    hunt_parser = subparsers.add_parser("hunt")
    hunt_parser.add_argument("--profile", "-p", required=True)
    hunt_parser.set_defaults(func=cmd_hunt)

    args = parser.parse_args()
    try:
        args.func(args)
    except ValueError as e:
        log.error(f"CONFIGURATION ERROR: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user. Exiting cleanly.")
        sys.exit(0)
    except Exception as e:
        log.error(f"UNEXPECTED FATAL ERROR: {e}", exc_info=True)
        log.error("Please ensure your environment is configured correctly.")
        sys.exit(1)

if __name__ == "__main__":
    main()