import subprocess
import json
import os
from typing import List, Dict, Any
from utsu.core.logger import log

class PortScanner:
    def __init__(self, threads: int = 25):
        self.threads = threads
        # Focus on high-yield web ports, avoiding full 65k scans to maintain speed
        self.ports = "80,443,8000,8080,8443,8888,9000,9001,9443"

    def scan(self, hosts: List[str]) -> List[str]:
        if not hosts:
            return []

        log.info(f"[*] Launching Naabu port scan across {len(hosts)} targets on ports: {self.ports}...")
        
        input_file = "/tmp/utsu_naabu_in.txt"
        output_file = "/tmp/utsu_naabu_out.json"
        
        with open(input_file, "w") as f:
            for h in hosts:
                f.write(f"{h}\n")
                
        cmd = [
            "naabu", "-l", input_file,
            "-p", self.ports, 
            "-c", str(self.threads),
            "-silent", "-json", "-o", output_file
        ]
        
        discovered_urls = []
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=False)
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            host = data.get("host")
                            port = str(data.get("port"))
                            if host and port:
                                # Assign standard schemes based on port convention
                                scheme = "https" if port in ["443", "8443", "9443"] else "http"
                                # Standard ports don't need explicit declarations in the URL
                                if port == "80":
                                    discovered_urls.append(f"http://{host}")
                                elif port == "443":
                                    discovered_urls.append(f"https://{host}")
                                else:
                                    discovered_urls.append(f"{scheme}://{host}:{port}")
                        except json.JSONDecodeError:
                            continue
                            
        except FileNotFoundError:
            log.error("[-] Naabu binary not found in PATH. Install it via: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
        except Exception as e:
            log.debug(f"[-] Port scan failed: {e}")
        finally:
            if os.path.exists(input_file): os.remove(input_file)
            if os.path.exists(output_file): os.remove(output_file)
            
        log.info(f"[+] Port scan complete. Discovered {len(discovered_urls)} open web services.")
        return discovered_urls