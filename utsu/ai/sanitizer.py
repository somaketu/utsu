import re
import hashlib
from typing import Any

class OPSECSanitizer:
    def __init__(self, redact_secrets: bool = True):
        self.redact_secrets = redact_secrets
        
        self.secret_patterns = {
            "google_api": re.compile(r'(?i)AIza[0-9A-Za-z-_]{35}'),
            "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "amazon_mws": re.compile(r'(?i)amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-.*'),
            "github_token": re.compile(r'(?i)gh[pousr]_[A-Za-z0-9_]{36}'),
            "slack_token": re.compile(r'(?i)xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}'),
            "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
        }

    def sanitize_string(self, text: str) -> str:
        if not self.redact_secrets:
            return text
            
        sanitized = text
        for secret_type, pattern in self.secret_patterns.items():
            for match in pattern.findall(sanitized):
                hashed = hashlib.sha256(match.encode()).hexdigest()[:10]
                replacement = f"<REDACTED_{secret_type.upper()}_HASH:{hashed}>"
                sanitized = sanitized.replace(match, replacement)
                
        # Generic fallback for key-value assignments
        sanitized = re.sub(
            r'(?i)(api_key|secret|password|access_token|token)([\s:=]+["\'])([^"\']{16,})(["\'])',
            lambda m: f"{m.group(1)}{m.group(2)}<REDACTED_GENERIC_HASH:{hashlib.sha256(m.group(3).encode()).hexdigest()[:10]}>{m.group(4)}",
            sanitized
        )
        return sanitized

    def process_delta(self, data: Any) -> Any:
        if isinstance(data, dict):
            return {k: self.process_delta(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.process_delta(item) for item in data]
        elif isinstance(data, str):
            return self.sanitize_string(data)
        return data