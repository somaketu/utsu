import os
import json
from typing import Dict, Any
from groq import Groq
from utsu.storage.repository import DeltaDB
from utsu.core.config import ConfigManager
from utsu.core.logger import log

class TriageAgent:
    def __init__(self, model_name: str = "llama-3.3-70b-versatile"):
        self.model_name = model_name
        self.api_key = os.getenv("GROQ_API_KEY")
        self.cfg = ConfigManager()
        self.db = DeltaDB(self.cfg.db_path)
        
        if not self.api_key:
            log.error("[-] FATAL: GROQ_API_KEY environment variable is missing.")
            log.error("Run: export GROQ_API_KEY='your_key_here'")
            
        self.client = Groq(api_key=self.api_key) if self.api_key else None
        
        # We are using a 70B model now, so we can demand deep reasoning and attack vectors.
        self.system_prompt = """You are an elite Application Security Engineer and Penetration Tester.
You will be provided with a target URL, a list of extracted endpoints, and potentially leaked secrets found in JS files.
Your objective is to correlate this data and identify the highest-probability attack vectors.

You MUST output your response in strict JSON format matching exactly this schema:
{
    "target": "string",
    "high_risk_endpoints": ["list of strings"],
    "leaked_secrets_analysis": "string summarizing the risk of any provided secrets",
    "attack_vectors": [
        {
            "vulnerability_type": "string (e.g., IDOR, SQLi, Prototype Pollution)",
            "target_url": "string",
            "proof_of_concept_command": "string (A fully constructed curl command or script snippet to test the vector)",
            "reasoning": "string"
        }
    ]
}

DO NOT output any markdown, explanations, or text outside of the JSON object."""

    def _fetch_target_data(self, web_service_id: int) -> Dict[str, Any]:
        """Extracts all crawled intelligence for a specific target directly from the SQLite database."""
        data = {"endpoints": [], "secrets": []}
        try:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                
                # Fetch endpoints
                cursor.execute("SELECT path FROM endpoints WHERE web_service_id = ?", (web_service_id,))
                data["endpoints"] = [row[0] for row in cursor.fetchall()]
                
                # Fetch secrets safely, handling potential schema naming variations
                try:
                    cursor.execute("SELECT type, value, location FROM leaked_secrets WHERE web_service_id = ?", (web_service_id,))
                    data["secrets"] = [{"type": row[0], "value": row[1], "location": row[2]} for row in cursor.fetchall()]
                except Exception:
                    # Fallback if the database schema was built with the alternative naming convention
                    cursor.execute("SELECT secret_type, value, location FROM leaked_secrets WHERE web_service_id = ?", (web_service_id,))
                    data["secrets"] = [{"type": row[0], "value": row[1], "location": row[2]} for row in cursor.fetchall()]
                
        except Exception as e:
            log.error(f"Database extraction failed during triage: {e}")
            
        return data

    def run(self, web_service_id: int, url: str, scope_rules: str = "") -> str:
        if not self.client:
            return ""

        log.info(f"Extracting intelligence for {url} from local database...")
        intel = self._fetch_target_data(web_service_id)
        
        if not intel["endpoints"] and not intel["secrets"]:
            log.warning(f"No viable endpoints or secrets found for {url}. Skipping AI inference.")
            return ""

        # Construct the context payload
        user_prompt = f"Target: {url}\nScope: {scope_rules}\n\n"
        
        if intel["secrets"]:
            user_prompt += "LEAKED SECRETS FOUND:\n" + json.dumps(intel["secrets"], indent=2) + "\n\n"
            
        user_prompt += "EXTRACTED ENDPOINTS:\n" + "\n".join(intel["endpoints"][:1000]) # Groq handles large contexts easily

        log.info(f"Dispatching payload to Groq ({self.model_name})...")
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"}, # Forces guaranteed JSON output
                temperature=0.1
            )
            
            raw_response = response.choices[0].message.content
            
            # Guardrail: Prevent json.loads(None) if the API fails to return text
            if not raw_response:
                log.error(f"Groq API returned an empty or null response for {url}.")
                return ""
            
            # Prettify the JSON for the CLI output and Markdown report
            parsed = json.loads(raw_response)
            return json.dumps(parsed, indent=4)
            
        except Exception as e:
            log.error(f"Groq API inference failed for {url}: {e}")
            return ""