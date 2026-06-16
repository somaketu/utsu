import subprocess
import json
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utsu.core.logger import log

class ReconEngine:
    def __init__(self, domain: str):
        self.domain = domain.lower()
        self.timeout = 15

    def _hacker_target(self) -> set:
        subs = set()
        try:
            res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=self.timeout)
            if res.status_code == 200 and "error" not in res.text:
                subs = {line.split(',')[0].lower() for line in res.text.split('\n') if line and line.endswith(self.domain)}
        except Exception as e:
            log.debug(f"HackerTarget failed for {self.domain}: {str(e)}")
        return subs

    def _crt_sh(self) -> set:
        subs = set()
        try:
            res = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=self.timeout)
            if res.status_code == 200:
                for entry in res.json():
                    name = entry.get("name_value", "")
                    for n in name.split('\n'):
                        if n.endswith(self.domain) and '*' not in n:
                            subs.add(n.strip().lower())
        except Exception as e:
            log.debug(f"crt.sh failed for {self.domain}: {str(e)}")
        return subs

    def _certspotter(self) -> set:
        subs = set()
        try:
            res = requests.get(f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names", timeout=self.timeout)
            if res.status_code == 200:
                for entry in res.json():
                    for name in entry.get("dns_names", []):
                        if name.endswith(self.domain) and '*' not in name:
                            subs.add(name.strip().lower())
        except Exception as e:
            log.debug(f"CertSpotter failed for {self.domain}: {str(e)}")
        return subs

    def _jldc(self) -> set:
        subs = set()
        try:
            res = requests.get(f"https://jldc.me/anubis/subdomains/{self.domain}", timeout=self.timeout)
            if res.status_code == 200:
                for name in res.json():
                    if isinstance(name, str) and name.endswith(self.domain):
                        subs.add(name.strip().lower())
        except Exception as e:
            log.debug(f"JLDC failed for {self.domain}: {str(e)}")
        return subs

    def _archive(self) -> set:
        subs = set()
        try:
            res = requests.get(f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey", timeout=self.timeout)
            if res.status_code == 200:
                data = res.json()
                if len(data) > 1:
                    for row in data[1:]:
                        host = urlparse(row[0]).hostname
                        if host and host.endswith(self.domain):
                            subs.add(host.lower())
        except Exception as e:
            log.debug(f"Web Archive failed for {self.domain}: {str(e)}")
        return subs

    def _alienvault(self) -> set:
        subs = set()
        try:
            res = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns", timeout=self.timeout)
            if res.status_code == 200:
                for entry in res.json().get("passive_dns", []):
                    name = entry.get("hostname", "")
                    if name.endswith(self.domain) and '*' not in name:
                        subs.add(name.lower())
        except Exception as e:
            log.debug(f"AlienVault OTX failed for {self.domain}: {str(e)}")
        return subs

    def _subfinder(self) -> set:
        subs = set()
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent", "-oJ"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        host = json.loads(line).get("host", "")
                        if host.endswith(self.domain):
                            subs.add(host.lower())
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            log.warning("Subfinder binary not found in PATH. Skipping.")
        except subprocess.TimeoutExpired:
            log.warning(f"Subfinder execution timed out for {self.domain}.")
        except Exception as e:
            log.debug(f"Subfinder failed: {str(e)}")
        return subs

    def run_all(self) -> set:
        total_subdomains = set()
        
        # Define all intelligence sources
        sources = {
            "HackerTarget": self._hacker_target,
            "crt.sh": self._crt_sh,
            "CertSpotter": self._certspotter,
            "JLDC Anubis": self._jldc,
            "Web Archive": self._archive,
            "AlienVault OTX": self._alienvault,
            "Subfinder": self._subfinder
        }

        log.info(f"[*] Launching concurrent intelligence gathering across {len(sources)} sources for {self.domain}...")

        # Fire all requests simultaneously
        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            future_to_source = {executor.submit(func): name for name, func in sources.items()}
            
            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    result = future.result()
                    if result:
                        log.debug(f"[+] {source_name} yielded {len(result)} assets.")
                        total_subdomains.update(result)
                    else:
                        log.debug(f"[-] {source_name} yielded 0 assets.")
                except Exception as e:
                    log.debug(f"[!] Source {source_name} generated an exception: {e}")

        log.info(f"[+] Total aggregated subdomains for {self.domain}: {len(total_subdomains)}")
        return total_subdomains