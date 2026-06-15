import os
import hashlib
from cryptography.fernet import Fernet
from utsu.core.logger import log

class Vault:
    def __init__(self):
        # The master key must be stored entirely outside the application directory.
        self.key_file = os.path.expanduser("~/.utsu_vault.key")
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

    def _load_or_generate_key(self) -> bytes:
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            # Strict OPSEC: Only the owner can read/write this key.
            os.chmod(self.key_file, 0o600)
            log.info("[*] Generated new local encryption key for Vault.")
            return key

    def encrypt(self, raw_secret: str) -> dict:
        """Returns the encrypted ciphertext, a safe preview, and a deterministic hash."""
        if not raw_secret:
            return {"ciphertext": "", "preview": "", "hash": ""}
        
        hashed = hashlib.sha256(raw_secret.encode()).hexdigest()
        
        # Safe preview: AKIA...XXXX
        if len(raw_secret) > 8:
            preview = f"{raw_secret[:4]}...{raw_secret[-4:]}"
        else:
            preview = "***MASKED***"
            
        encrypted = self.cipher.encrypt(raw_secret.encode()).decode()
        
        return {
            "ciphertext": encrypted,
            "preview": preview,
            "hash": hashed
        }

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self.cipher.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            log.error(f"[-] Vault decryption failed: {e}")
            return ""