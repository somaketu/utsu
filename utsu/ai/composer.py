import os
from typing import List
from utsu.core.logger import log

class PromptComposer:
    def __init__(self):
        # Establish base path relative to the runtime execution context
        self.base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts")

    def _read_prompt_file(self, category: str, profile_name: str) -> str:
        file_path = os.path.join(self.base_dir, category, f"{profile_name}.md")
        if not os.path.exists(file_path):
            log.warning(f"[-] Prompt profile missing at {file_path}. Falling back to default.")
            fallback_path = os.path.join(self.base_dir, category, "default.md")
            if not os.path.exists(fallback_path):
                return ""
            file_path = fallback_path
            
        with open(file_path, "r") as f:
            return f.read().strip()

    def build_system_prompt(self, category: str, profiles: List[str]) -> str:
        """Dynamically stitches together multiple mission-objective prompts."""
        if not profiles:
            profiles = ["default"]
            
        compiled_blocks = []
        for profile in profiles:
            content = self._read_prompt_file(category, profile)
            if content:
                compiled_blocks.append(content)
                
        if not compiled_blocks:
            raise FileNotFoundError(f"CRITICAL: No viable system prompts found for category '{category}'")
            
        # Separate individual objective modules with a clean markdown semantic boundary
        return "\n\n---\n\n".join(compiled_blocks)