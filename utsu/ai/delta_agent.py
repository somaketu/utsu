import json
from typing import Dict, Any
from utsu.core.logger import log
from utsu.core.config import ConfigManager
from utsu.ai.provider import ProviderFactory
from utsu.ai.composer import PromptComposer

class DeltaAgent:
    def __init__(self):
        self.cfg = ConfigManager()
        
        try:
            self.provider = ProviderFactory.get_provider(self.cfg)
        except ValueError as e:
            log.error(f"[-] FATAL AI Initialization: {e}")
            self.provider = None

        # ==========================================
        # MISSION OBJECTIVE COMPOSITION
        # ==========================================
        objectives = getattr(self.cfg, "delta_objectives", ["default"])
        
        try:
            composer = PromptComposer()
            self.system_prompt = composer.build_system_prompt("delta", objectives)
        except Exception as e:
            log.error(f"[-] Delta Prompt Composition Failed: {e}")
            self.system_prompt = ""

    def analyze(self, delta: Dict[str, Any]) -> str:
        if not self.provider or not self.system_prompt:
            log.warning("[-] DeltaAgent offline: Missing provider or valid system prompt.")
            return ""
            
        summary = delta.get("summary", {})
        total_new = sum(summary.values()) if summary else 0
        
        if not delta.get("net_new_assets") or total_new == 0:
            log.info("[*] Delta is empty. Bypassing AI inference.")
            return json.dumps({
                "risk_level": "INFO", 
                "risk_score_1_to_100": 0,
                "executive_summary": "No net-new assets discovered. Threat landscape unchanged.",
                "emerging_attack_paths": []
            }, indent=4)

        log.info(f"[*] Dispatching delta payload to AI Factory for threat modeling...")

        response = self.provider.generate(self.system_prompt, delta)
        
        if response.error:
            log.error(f"[-] AI inference failed during delta analysis: {response.error}")
            return ""
            
        log.info(f"[+] Threat model generated via {response.provider} ({response.model}) in {response.latency_seconds:.2f}s")
            
        try:
            parsed = json.loads(response.content)
            return json.dumps(parsed, indent=4)
        except json.JSONDecodeError:
            log.error(f"[-] AI provider {response.provider} returned malformed JSON during delta analysis.")
            return ""