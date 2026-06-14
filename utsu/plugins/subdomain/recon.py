import subprocess
import json
import requests
from utsu.core.logger import log

class ReconEngine:
    def __init__(self, domain: str):
        self.domain = domain

    def _hacker_target(self) -> set:
        try:
            res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=10)
            if res.status_code == 200 and "error" not in res.text:
                return {line.split(',')[0] for line in res.text.split('\n') if line}
            else:
                log.debug(f"HackerTarget returned non-200 status or error for {self.domain}: {res.status_code}")
        except requests.exceptions.Timeout:
            log.warning(f"Timeout occurred while querying HackerTarget for {self.domain}")
        except Exception as e:
            log.debug(f"Unexpected failure querying HackerTarget for {self.domain}: {str(e)}", exc_info=True)
        return set()

    def _subfinder(self) -> set:
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent", "-oJ"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            subdomains = set()
            for line in proc.stdout.splitlines():
                if line.strip():
                    subdomains.add(json.loads(line).get("host"))
            return subdomains
        except FileNotFoundError:
            log.warning(f"Subfinder binary not found in PATH. Skipping subfinder execution.")
        except subprocess.TimeoutExpired:
            log.warning(f"Subfinder execution timed out for {self.domain}.")
        except Exception as e:
            log.debug(f"Unexpected failure during Subfinder execution for {self.domain}: {str(e)}", exc_info=True)
        return set()

    def run_all(self) -> set:
        log.info(f"Querying HackerTarget for {self.domain}...")
        ht_subs = self._hacker_target()
        log.info(f"Running subfinder for {self.domain}...")
        sf_subs = self._subfinder()
        total = ht_subs.union(sf_subs)
        log.info(f"Total aggregated subdomains for {self.domain}: {len(total)}")
        return total