import os
import requests
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from dataclasses import dataclass
from utsu.ai.sanitizer import OPSECSanitizer
from utsu.core.logger import log

@dataclass
class AIResponse:
    content: str
    provider: str
    model: str
    latency_seconds: float
    error: Optional[str] = None

class AIProvider(ABC):
    def __init__(self, config: Any):
        self.sanitizer = OPSECSanitizer(redact_secrets=getattr(config, "redact_secrets", True))
        self.max_retries = 3
        # Initialize base attributes for static analysis
        self.name = "base"
        self.model = "unknown"

    def generate(self, system_prompt: str, user_payload: Any) -> AIResponse:
        """Mandatory security boundary: sanitizes payload before hitting the network."""
        sanitized_payload = self.sanitizer.process_delta(user_payload)
        
        # Convert dictionary payload to string for the LLM
        if isinstance(sanitized_payload, (dict, list)):
            import json
            payload_str = json.dumps(sanitized_payload)
        else:
            payload_str = str(sanitized_payload)

        start_time = time.monotonic()
        
        for attempt in range(1, self.max_retries + 1):
            try:
                content = self._execute_inference(system_prompt, payload_str)
                latency = time.monotonic() - start_time
                return AIResponse(content=content, provider=self.name, model=self.model, latency_seconds=latency)
            except Exception as e:
                log.warning(f"[-] AI Provider {self.name} failed attempt {attempt}/{self.max_retries}: {e}")
                if attempt == self.max_retries:
                    latency = time.monotonic() - start_time
                    return AIResponse(content="", provider=self.name, model=self.model, latency_seconds=latency, error=str(e))
                time.sleep(2 ** attempt) # Exponential backoff
                
        # Theoretical fallback to satisfy strict typing paths
        return AIResponse(content="", provider=self.name, model=self.model, latency_seconds=0.0, error="Execution loop failed.")

    @abstractmethod
    def _execute_inference(self, system_prompt: str, sanitized_payload: str) -> str:
        pass

class GroqProvider(AIProvider):
    def __init__(self, config: Any):
        super().__init__(config)
        self.name = "groq"
        self.model = getattr(config, "ai_model", "llama3.2")
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.url = "https://api.groq.com/openai/v1/chat/completions"

    def _execute_inference(self, system_prompt: str, sanitized_payload: str) -> str:
        if not self.api_key:
            raise ValueError("Missing GROQ_API_KEY environment variable.")
            
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": sanitized_payload}
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"}
        }
        
        response = requests.post(self.url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

class OllamaProvider(AIProvider):
    def __init__(self, config: Any):
        super().__init__(config)
        self.name = "ollama"
        self.model = getattr(config, "ai_model", "llama3.2")
        base_url = getattr(config, "ollama_url", "http://127.0.0.1:11434")
        self.url = f"{base_url.rstrip('/')}/api/chat"

    def _execute_inference(self, system_prompt: str, sanitized_payload: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": sanitized_payload}
            ],
            "options": {"temperature": 0.2},
            "stream": False,
            "format": "json"
        }
        
        response = requests.post(self.url, json=payload, timeout=60)
        response.raise_for_status()
        return response.json()["message"]["content"]

class ProviderFactory:
    @staticmethod
    def get_provider(config: Any) -> AIProvider:
        provider_type = getattr(config, "ai_provider", "groq").lower()
        local_only = getattr(config, "local_only", False)
        
        if local_only and provider_type not in ["ollama", "odysseus"]:
            raise ValueError("CRITICAL OPSEC VIOLATION: Profile mandates 'local_only: true' but an external cloud provider was requested.")

        if provider_type in ["ollama", "odysseus"]:
            return OllamaProvider(config)
        elif provider_type == "groq":
            return GroqProvider(config)
        else:
            raise ValueError(f"Unknown or unsupported AI provider: {provider_type}")