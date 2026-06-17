import json
from typing import Dict, Any
from utsu.storage.repository import DeltaDB
from utsu.core.config import ConfigManager
from utsu.core.logger import log
from utsu.ai.provider import ProviderFactory
from utsu.ai.composer import PromptComposer

class TriageAgent:
    def __init__(self):
        self.cfg = ConfigManager()
        self.db = DeltaDB(self.cfg.db_path)
        
        try:
            self.provider = ProviderFactory.get_provider(self.cfg)
        except ValueError as e:
            log.error(f"[-] FATAL AI Initialization: {e}")
            self.provider = None

        # ==========================================
        # MISSION OBJECTIVE COMPOSITION
        # ==========================================
        objectives = getattr(self.cfg, "triage_objectives", ["default"])
        
        try:
            composer = PromptComposer()
            self.system_prompt = composer.build_system_prompt("triage", objectives)
        except Exception as e:
            log.error(f"[-] Triage Prompt Composition Failed: {e}")
            self.system_prompt = "" 
            
    def run(self, web_service_id: int, url: str, scope_rules: str = "") -> str:
        if not self.provider or not self.system_prompt:
            log.warning(f"[-] TriageAgent offline: Missing provider or valid system prompt for {url}.")
            return ""

        log.info(f"Extracting intelligence for {url} via Repository layer...")
        
        endpoints = self.db.get_endpoints_by_service(web_service_id)
        secrets = self.db.get_encrypted_secrets_by_service(web_service_id)
        
        if not endpoints and not secrets:
            log.warning(f"No viable intelligence assets found for {url}. Skipping inference.")
            return ""

        # Construct a structured dictionary instead of a raw string to allow the OPSECSanitizer to traverse it cleanly
        user_payload = {
            "target": url,
            "scope_rules": scope_rules,
            "extracted_endpoints": endpoints[:1000],
            "leaked_secrets": secrets
        }

        log.info(f"Dispatching payload to AI Engine...")
        
        # The provider handles sanitization, formatting, exponential backoff, and execution
        response = self.provider.generate(self.system_prompt, user_payload)
        
        if response.error:
            log.error(f"[-] AI inference failed for {url}: {response.error}")
            return ""
            
        log.debug(f"[+] Triage completed via {response.provider} ({response.model}) in {response.latency_seconds:.2f}s")
            
        try:
            parsed = json.loads(response.content)
            return json.dumps(parsed, indent=4)
        except json.JSONDecodeError:
            log.error(f"[-] AI provider {response.provider} returned malformed JSON for {url}")
            return ""