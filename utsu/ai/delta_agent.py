import os
import json
from typing import Dict, Any
from groq import Groq
from utsu.core.logger import log
from utsu.core.config import ConfigManager

class DeltaAgent:
    def __init__(self):
        # Dynamically pull the model from the active YAML profile configuration
        cfg = ConfigManager()
        self.model_name = getattr(cfg, "ai_model", None) or "llama-3.3-70b-versatile"
        
        self.api_key = os.getenv("GROQ_API_KEY")
        if not self.api_key:
            log.error("[-] FATAL: GROQ_API_KEY environment variable is missing.")
            
        self.client = Groq(api_key=self.api_key) if self.api_key else None

        self.system_prompt = """You are a Principal Application Security Architect.
You will receive an Attack Surface Delta representing net-new assets (subdomains, endpoints, secrets) discovered on a target domain since the last scan.
Your objective is to analyze these new assets and assign a concrete risk score based strictly on the changes.

Output strict JSON exactly matching this schema:
{
    "risk_level": "CRITICAL, HIGH, MEDIUM, LOW, or INFO",
    "risk_score_1_to_100": int,
    "executive_summary": "string explaining why the new assets alter the threat landscape",
    "emerging_attack_paths": [
        {
            "path": "string",
            "evidence": "string"
        }
    ]
}"""

    def analyze(self, delta: Dict[str, Any]) -> str:
        """Pipes the calculated delta into the Groq model for threat modeling."""
        if not self.client: 
            return ""
            
        summary = delta.get("summary", {})
        total_new = sum(summary.values()) if summary else 0
        
        if not delta.get("net_new_assets") or total_new == 0:
            log.info("[*] Delta is empty. Bypassing AI inference.")
            return json.dumps({
                "risk_level": "INFO", 
                "risk_score_1_to_100": 0,
                "executive_summary": "No net-new assets discovered. Threat landscape unchanged."
            }, indent=4)

        log.info(f"[*] Dispatching delta payload to Groq ({self.model_name}) for threat modeling...")

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": json.dumps(delta, indent=2)}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            
            raw_response = response.choices[0].message.content
            if not raw_response:
                return ""
            
            parsed = json.loads(raw_response)
            return json.dumps(parsed, indent=4)
            
        except Exception as e:
            log.error(f"[-] Groq API inference failed during delta analysis: {e}")
            return ""