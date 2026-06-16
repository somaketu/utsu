import os
import logging
import yaml
from typing import Optional, Dict, List, Any

class ConfigManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._load_defaults()
        return cls._instance

    def _load_defaults(self):
        self._load_env_file()
        self.db_path: str = os.getenv("DATABASE_PATH", "data/uro.db")
        
        # AI & Triage Configurations
        self.ai_provider: str = os.getenv("AI_PROVIDER", "groq") # Default to cloud, can be 'ollama'
        self.ollama_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.ai_model: str = os.getenv("DEFAULT_AI_MODEL", "llama3.2")
        
        # Network & Concurrency
        self.prober_threads: int = int(os.getenv("DEFAULT_PROBER_THREADS", "10"))
        self.rate_limit_rps: int = 10
        
        # Recon & Discovery Paths
        self.wordlist_path: str = ""
        self.resolvers_path: str = ""
        
        # Vulnerability Scanning Defaults
        self.nuclei_templates: List[str] = ["cves/", "vulnerabilities/", "exposed-panels/", "misconfiguration/"]
        
        self.scope_file: Optional[str] = None
        self.profile_name: str = "Default Profile"
        self.custom_headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def _load_env_file(self):
        if os.path.exists(".env"):
            with open(".env", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        os.environ.setdefault(key.strip(), val.strip())

    def load_profile(self, profile_path: str):
        if not os.path.exists(profile_path):
            logging.error(f"[-] Profile layout missing at path: {profile_path}. Using system environment variables.")
            return

        try:
            with open(profile_path, 'r') as f:
                raw_data = yaml.safe_load(f)
                
                # Strict Type Enforcement: Block malformed YAML arrays
                if not isinstance(raw_data, dict):
                    logging.error(f"[-] Invalid YAML structure in {profile_path}. Expected a key-value dictionary.")
                    return
                    
                config_data: Dict[str, Any] = raw_data
                
                self.profile_name = str(config_data.get("name", "Unknown Target"))
                
                # Sandbox the scope_file to prevent path traversal
                raw_scope = config_data.get("scope_file")
                if raw_scope and isinstance(raw_scope, str):
                    raw_scope = os.path.expanduser(raw_scope)
                    
                    if os.path.isabs(raw_scope):
                        self.scope_file = raw_scope
                    else:
                        base_dir = os.path.dirname(os.path.abspath(profile_path))
                        resolved = os.path.realpath(os.path.join(base_dir, raw_scope))
                        if resolved.startswith(base_dir):
                            self.scope_file = resolved
                        else:
                            logging.error("[-] SECURITY: scope_file path traversal attempt blocked.")
                
                if "threads" in config_data:
                    self.prober_threads = int(config_data["threads"])
                
                # Parse network rate limits
                network_rules = config_data.get("network_rules", {})
                if isinstance(network_rules, dict) and "rate_limit_rps" in network_rules:
                    self.rate_limit_rps = int(network_rules["rate_limit_rps"])
                
                # Extract arbitrary compliance headers dynamically
                custom_headers = config_data.get("custom_headers")
                if isinstance(custom_headers, dict):
                    self.custom_headers.update(custom_headers)
                    
                # ==========================================
                # DYNAMIC INGESTION PROTOCOL
                # ==========================================
                ignore_keys = {"name", "scope_file", "threads", "network_rules", "custom_headers"}
                for key, value in config_data.items():
                    if key not in ignore_keys:
                        # Ensures paths containing ~ are expanded dynamically (e.g., ~/wordlists/subs.txt)
                        if isinstance(value, str) and value.startswith("~/"):
                            value = os.path.expanduser(value)
                        setattr(self, key, value)
                    
                logging.info(f"[*] Activated operational profile: {self.profile_name}")
        except Exception as e:
            logging.error(f"[-] Operational profile parsing failure on {profile_path}: {e}")