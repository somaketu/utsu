import json
import requests
from urllib.parse import urlparse
from utsu.core.logger import log

class TriageAgent:
    def __init__(self, model_name: str = "llama3"):
        self.model_name = model_name
        # Points strictly to the local Ollama daemon. Data never leaves the machine.
        self.api_url = "http://localhost:11434/api/generate"

    def run(self, web_service_id: int, url: str, scope_rules: str) -> str:
        """Evaluates target intelligence entirely locally via Ollama."""
        from utsu.storage.repository import DeltaDB
        from utsu.core.config import ConfigManager
        
        cfg = ConfigManager()
        db = DeltaDB(cfg.db_path)
        
        with db._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM endpoints WHERE web_service_id = ?', (web_service_id,))
            ep_columns = [desc[0] for desc in cursor.description]
            filtered = []
            for row in cursor.fetchall():
                row_dict = dict(zip(ep_columns, row))
                path = row_dict.get('path') or row_dict.get('endpoint') or row_dict.get('url', '')
                if path:
                    filtered.append(path)
            
            cursor.execute('SELECT * FROM leaked_secrets WHERE web_service_id = ?', (web_service_id,))
            sec_columns = [desc[0] for desc in cursor.description]
            secrets = [dict(zip(sec_columns, row)) for row in cursor.fetchall()]

        meaningful_routes = [
            r for r in filtered 
            if r.strip() and r.strip("/") != url.strip("/") and len(urlparse(r).path) > 1
        ]

        if not meaningful_routes and not secrets:
            return (
                f"=== AI Triage Report: {url} ===\n"
                f"[!] Status: Deprioritized\n"
                f"[-] Reason: No deep endpoints, parameters, or credentials detected by the extraction engine.\n"
                f"[+] Action: Maintain passive monitoring. No actionable web attack surface.\n"
            )

        system_prompt = f"""You are a deterministic, elite offensive security triage engine. 
Analyze the real technical indicators and output a highly technical structured JSON response.

[RULES]
1. Base your hypothesis ONLY on the data provided inside the <ROUTES> and <SECRETS> tags.
2. Do not invent endpoints, parameters, or vulnerabilities.
3. Output strictly in valid JSON format with the following exact keys:
   - "vulnerability_hypothesis": (string) The specific, technical vulnerability hypothesized.
   - "steps_to_validate": (list of strings) Step-by-step instructions to manually validate in Burp Suite.
   - "scope_compliance": (string) A brief check against the provided scope rules.

[PROGRAM POLICY]
{scope_rules or "Adhere to standard, responsible bug bounty constraints."}

[LIVE ASSET UNDER ANALYSIS]
Target URL: {url}

<ROUTES>
{chr(10).join(meaningful_routes)}
</ROUTES>

<SECRETS>
{json.dumps(secrets) if secrets else "None"}
</SECRETS>"""

        payload = {
            "model": self.model_name,
            "prompt": system_prompt,
            "stream": False,
            "format": "json"  # This will force Ollama to return clean JSON...(Might improve in future)
        }

        try:
            log.info(f"Sending intelligence to local {self.model_name} model for triage on {url}...")
            response = requests.post(self.api_url, json=payload, timeout=180)
            
            if response.status_code == 200:
                raw_result = response.json().get("response", "")
                try:
                    result = json.loads(raw_result)
                except json.JSONDecodeError:
                    log.error(f"Failed to parse JSON from local AI on {url}. Raw output: {raw_result}")
                    return f"[-] AI Triage parsing failed for {url}."

                report = (
                    f"=== AI Triage Report: {url} ===\n"
                    f"[!] Hypothesis: {result.get('vulnerability_hypothesis', 'None provided')}\n\n"
                    f"[*] Validation Steps:\n"
                )
                steps = result.get('steps_to_validate', [])
                if isinstance(steps, list):
                    for i, step in enumerate(steps, 1):
                        report += f"    {i}. {step}\n"
                else:
                    report += f"    1. {steps}\n"
                    
                report += f"\n[+] Scope Check: {result.get('scope_compliance', 'None provided')}\n"
                
                return report

            else:
                log.warning(f"Local AI returned unexpected status code: {response.status_code}")
                return f"[-] AI Triage Failed for {url}: Invalid response from local model."

        except requests.exceptions.ConnectionError:
            # Yo This will trap the error gracefully instead of crashing the pipeline....
            log.error("Failed to connect to local AI. Is Ollama running on localhost:11434?")
            return f"[-] AI Triage Failed for {url}: Connection refused. Ensure Ollama is active."
        except requests.exceptions.Timeout:
            log.warning("Local AI inference timed out. Consider using a smaller model.")
            return f"[-] AI Triage Failed for {url}: Inference timeout."
        except Exception as e:
            log.debug(f"Unexpected error during local AI triage on {url}: {str(e)}", exc_info=True)
            return f"[-] AI Triage Failed for {url}: Internal error."