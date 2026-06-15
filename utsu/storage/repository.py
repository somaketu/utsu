import sqlite3
import logging
import os
import stat
from typing import Iterator, List, Tuple, Optional, Dict
from contextlib import contextmanager
from utsu.core.encryption import Vault

class DeltaDB:
    def __init__(self, db_path: str = "data/utsu.db"):
        self.db_path = db_path
        self._ensure_secure_db()
        self._init_db()

    def _ensure_secure_db(self):
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            os.chmod(db_dir, stat.S_IRWXU)
            
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'a'): pass
            
        os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        logging.debug(f"[*] Enforced strict 0600 permissions on database: {self.db_path}")

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    subdomain TEXT UNIQUE NOT NULL,
                    is_scanned BOOLEAN DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(domain_id) REFERENCES domains(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain_id INTEGER,
                    url TEXT UNIQUE NOT NULL,
                    status_code INTEGER,
                    content_length INTEGER,
                    title TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    web_service_id INTEGER,
                    path TEXT NOT NULL,
                    source TEXT NOT NULL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(web_service_id, path),
                    FOREIGN KEY(web_service_id) REFERENCES web_services(id)
                )
            ''')
            # ADDED: discovered_at to track when the secret was first introduced
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS leaked_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                web_service_id INTEGER,
                type TEXT NOT NULL,
                preview TEXT NOT NULL,
                encrypted_value TEXT NOT NULL,
                secret_hash TEXT NOT NULL UNIQUE,
                location TEXT NOT NULL,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(web_service_id) REFERENCES web_services(id)
            )
        """)

    def add_endpoint(self, web_service_id: int, path: str, source: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO endpoints (web_service_id, path, source)
                VALUES (?, ?, ?)
            ''', (web_service_id, path, source))

    def add_secret(self, web_service_id: int, secret_type: str, value: str, location: str) -> bool:
        if not value: return False
        vault = Vault()
        encrypted_data = vault.encrypt(value)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO leaked_secrets 
                    (web_service_id, type, preview, encrypted_value, secret_hash, location)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    web_service_id, secret_type, encrypted_data['preview'], 
                    encrypted_data['ciphertext'], encrypted_data['hash'], location
                ))
                return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            logging.error(f"[-] Database error while saving encrypted secret: {e}")
            return False

    def add_web_service(self, subdomain_id: int, url: str, status_code: int, content_length: int, title: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO web_services (subdomain_id, url, status_code, content_length, title)
                VALUES (?, ?, ?, ?, ?)
            ''', (subdomain_id, url, status_code, content_length, title))

    def get_web_service_id_by_url(self, url: str) -> Optional[int]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM web_services WHERE url = ?', (url,))
            result = cursor.fetchone()
            return result[0] if result else None

    def add_domain(self, domain: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO domains (domain) VALUES (?)', (domain,))
            cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
            return cursor.fetchone()[0]

    def mark_scanned(self, subdomain_id: int):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE subdomains SET is_scanned = 1 WHERE id = ?', (subdomain_id,))

    def get_endpoints_by_service(self, web_service_id: int) -> List[str]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT path FROM endpoints WHERE web_service_id = ?", (web_service_id,))
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            return []

    def get_encrypted_secrets_by_service(self, web_service_id: int) -> List[Dict[str, str]]:
        try:
            vault = Vault()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT type, encrypted_value, location FROM leaked_secrets WHERE web_service_id = ?", (web_service_id,))
                rows = cursor.fetchall()
            decrypted_secrets = []
            for row in rows:
                decrypted_val = vault.decrypt(row[1])
                if decrypted_val:
                    decrypted_secrets.append({"type": row[0], "value": decrypted_val, "location": row[2]})
            return decrypted_secrets
        except Exception as e:
            return []

    # ==========================================
    # PHASE 3: HISTORICAL DIFFING ABSTRACTIONS
    # ==========================================

    def get_new_subdomains(self, domain: str, since_utc: str) -> List[str]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT s.subdomain FROM subdomains s
                    JOIN domains d ON s.domain_id = d.id
                    WHERE d.domain = ? AND s.first_seen >= ?
                ''', (domain, since_utc))
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Failed to fetch new subdomains: {e}")
            return []

    def get_new_endpoints(self, domain: str, since_utc: str) -> List[Dict[str, str]]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT w.url, e.path, e.source FROM endpoints e
                    JOIN web_services w ON e.web_service_id = w.id
                    JOIN subdomains s ON w.subdomain_id = s.id
                    JOIN domains d ON s.domain_id = d.id
                    WHERE d.domain = ? AND e.discovered_at >= ?
                ''', (domain, since_utc))
                return [{"url": row[0], "path": row[1], "source": row[2]} for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Failed to fetch new endpoints: {e}")
            return []

    def get_new_secrets(self, domain: str, since_utc: str) -> List[Dict[str, str]]:
        try:
            vault = Vault()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT w.url, ls.type, ls.encrypted_value, ls.location FROM leaked_secrets ls
                    JOIN web_services w ON ls.web_service_id = w.id
                    JOIN subdomains s ON w.subdomain_id = s.id
                    JOIN domains d ON s.domain_id = d.id
                    WHERE d.domain = ? AND ls.discovered_at >= ?
                ''', (domain, since_utc))
                rows = cursor.fetchall()
            
            new_secrets = []
            for row in rows:
                decrypted_val = vault.decrypt(row[2])
                if decrypted_val:
                    new_secrets.append({
                        "url": row[0], "type": row[1],
                        "value": decrypted_val, "location": row[3]
                    })
            return new_secrets
        except Exception as e:
            logging.error(f"Failed to fetch new secrets: {e}")
            return []