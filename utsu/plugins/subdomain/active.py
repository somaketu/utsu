import subprocess
import os
import urllib.request
import ssl
from utsu.core.logger import log

class ActiveReconEngine:
    def __init__(self, domain: str, wordlist: str, resolvers: str):
        self.domain = domain
        base_dir = os.path.expanduser("~/.utsu/wordlists")
        self.wordlist = wordlist if wordlist else os.path.join(base_dir, "subdomains.txt")
        self.resolvers = resolvers if resolvers else os.path.join(base_dir, "resolvers.txt")

    def _ensure_dependencies(self):
        os.makedirs(os.path.dirname(self.wordlist), exist_ok=True)
        os.makedirs(os.path.dirname(self.resolvers), exist_ok=True)

        # Bypass macOS Python SSL certificate missing-issuer flaws
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            if not os.path.exists(self.wordlist):
                log.info(f"[*] Auto-fetching default subdomain wordlist to {self.wordlist}...")
                with urllib.request.urlopen("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt", context=ctx) as response, open(self.wordlist, 'wb') as out_file:
                    out_file.write(response.read())
            
            if not os.path.exists(self.resolvers):
                log.info(f"[*] Auto-fetching trusted resolvers to {self.resolvers}...")
                with urllib.request.urlopen("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt", context=ctx) as response, open(self.resolvers, 'wb') as out_file:
                    out_file.write(response.read())
        except Exception as e:
            log.warning(f"[-] Dependency auto-fetch failed: {e}. Active DNS may be skipped.")

    def bruteforce(self) -> set:
        self._ensure_dependencies()

        if not os.path.exists(self.wordlist) or not os.path.exists(self.resolvers):
            log.warning("[-] Critical DNS intelligence missing. Skipping active DNS brute-forcing.")
            return set()

        log.info(f"[*] Launching high-velocity DNS bruteforce (puredns) against {self.domain}...")
        subs = set()
        output_file = f"/tmp/utsu_puredns_{self.domain}.txt"
        
        cmd = [
            "puredns", "bruteforce", self.wordlist, self.domain,
            "-r", self.resolvers, "-w", output_file, "--quiet"
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=False)
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        sub = line.strip().lower()
                        if sub.endswith(self.domain):
                            subs.add(sub)
        except FileNotFoundError:
            log.error("[-] puredns binary not found in PATH. Install it via: go install github.com/d3mondev/puredns/v2@latest")
        except Exception as e:
            log.debug(f"[-] Active DNS bruteforce failed: {e}")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
                
        log.info(f"[+] Active DNS yielded {len(subs)} valid subdomains.")
        return subs