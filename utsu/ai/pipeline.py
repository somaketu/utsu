import os
import json
from typing import Dict, Any
from groq import Groq
from utsu.storage.repository import DeltaDB
from utsu.core.config import ConfigManager
from utsu.core.logger import log

class TriageAgent:
    def __init__(self):
        self.cfg = ConfigManager()
        # Dynamically pull the model from the active YAML profile configuration
        self.model_name = getattr(self.cfg, "ai_model", None) or "llama-3.3-70b-versatile"
        
        self.api_key = os.getenv("GROQ_API_KEY")
        self.db = DeltaDB(self.cfg.db_path)
        
        if not self.api_key:
            log.error("[-] FATAL: GROQ_API_KEY environment variable is missing.")
            
        self.client = Groq(api_key=self.api_key) if self.api_key else None
        
        self.system_prompt = """You are an elite Application Security Engineer and Penetration Tester.
You will be provided with a target URL, a list of extracted endpoints, and leaked secrets found in JS files.
Your objective is to correlate this data and identify high-probability attack vectors.

You MUST output your response in strict JSON format matching exactly this schema:
{
    "target": "string",
    "high_risk_endpoints": ["list of strings"],
    "leaked_secrets_analysis": "string summarizing the risk of any provided secrets",
    "attack_vectors": [
        {
            "vulnerability_type": "string",
            "target_url": "string",
            "proof_of_concept_command": "string",
            "reasoning": "string"
        }
    ]
}
DO NOT output any markdown, explanations, or text outside of the JSON object."""

    def run(self, web_service_id: int, url: str, scope_rules: str = "") -> str:
        if not self.client:
            return ""

        log.info(f"Extracting intelligence for {url} via Repository layer...")
        
        # FIXED: Call domain-specific abstraction methods. Zero raw SQL exposure here.
        endpoints = self.db.get_endpoints_by_service(web_service_id)
        secrets = self.db.get_encrypted_secrets_by_service(web_service_id)
        
        if not endpoints and not secrets:
            log.warning(f"No viable intelligence assets found for {url}. Skipping inference.")
            return ""

        user_prompt = f"Target: {url}\nScope: {scope_rules}\n\n"
        
        if secrets:
            user_prompt += "LEAKED SECRETS FOUND (DECRYPTED VIA VAULT):\n" + json.dumps(secrets, indent=2) + "\n\n"
            
        user_prompt += "EXTRACTED ENDPOINTS:\n" + "\n".join(endpoints[:1000])

        log.info(f"Dispatching payload to Groq ({self.model_name})...")
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt}
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
            log.error(f"Groq API inference failed for {url}: {e}")
            return ""