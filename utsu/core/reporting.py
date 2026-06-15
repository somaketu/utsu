import os
import json
from datetime import datetime
from utsu.core.logger import log

class ReportManager:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.master_hunt_log = ""  # Explicitly declare the attribute for Pylance
        
        # Ensure the persistent directory exists before writing
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def save_scan_targets(self, domain: str, live_urls: list) -> str:
        """Saves a raw flat list of live URLs for external tooling."""
        target_file = os.path.join(self.output_dir, f"{domain}_live.txt")
        with open(target_file, "w", encoding="utf-8") as f:
            for url in live_urls:
                f.write(f"{url}\n")
        return target_file

    def save_triage_report(self, url: str, ai_json_output: str) -> str:
        """
        Parses the strict JSON from the 70B model and formats it into a 
        minimalist, highly readable Markdown artifact.
        """
        if not ai_json_output:
            return ""

        try:
            data = json.loads(ai_json_output)
        except json.JSONDecodeError:
            log.error("Failed to parse AI output for reporting. Invalid JSON structure.")
            return ""

        # Extract a clean base domain to group subdomains into a single master file
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        base_domain = ".".join(domain.split(".")[-2:]) if domain.count(".") > 0 else domain
        
        report_path = os.path.join(self.output_dir, f"{base_domain}_hunt.md")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Construct the minimalist Markdown artifact
        md_content = f"## Target: `{data.get('target', url)}`\n"
        md_content += f"> **Log Time:** {timestamp}\n>\n"
        
        secrets_analysis = data.get('leaked_secrets_analysis', '')
        if secrets_analysis and "no leaked secrets" not in secrets_analysis.lower():
             md_content += f"> **Secrets Analysis:** {secrets_analysis}\n"
        
        md_content += "\n### High-Risk Endpoints\n"
        endpoints = data.get('high_risk_endpoints', [])
        if endpoints:
            for ep in endpoints:
                md_content += f"- `{ep}`\n"
        else:
            md_content += "- None identified.\n"

        md_content += "\n### Attack Vectors\n"
        vectors = data.get('attack_vectors', [])
        if vectors:
            for vector in vectors:
                v_type = vector.get('vulnerability_type', 'Unknown Vector')
                t_url = vector.get('target_url', 'N/A')
                logic = vector.get('reasoning', 'N/A')
                poc = vector.get('proof_of_concept_command', 'N/A')
                
                # Safe block formatting to prevent syntax breakage
                md_content += f"#### {v_type}\n"
                md_content += f"- **Target:** `{t_url}`\n"
                md_content += f"- **Logic:** {logic}\n"
                md_content += "- **Proof of Concept:**\n"
                md_content += f"  ```bash\n  {poc}\n  ```\n\n"
        else:
            md_content += "- No immediate vectors identified.\n\n"
        
        md_content += "---\n\n"

        # Append to the master document
        with open(report_path, "a", encoding="utf-8") as f:
            f.write(md_content)

        self.master_hunt_log = report_path
        return report_path