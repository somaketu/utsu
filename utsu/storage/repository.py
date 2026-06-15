import sqlite3
from typing import Iterator
import logging
import os
import stat
from typing import List, Tuple, Optional
from contextlib import contextmanager

class DeltaDB:
    def __init__(self, db_path: str = "data/utsu.db"):
        self.db_path = db_path
        self._ensure_secure_db()
        self._init_db()

    def _ensure_secure_db(self):
        """Forces strict 0600 OS-level permissions on the SQLite database."""
        db_dir = os.path.dirname(self.db_path)
        
        # Ensure the directory exists and restrict access to owner only (0700)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            os.chmod(db_dir, stat.S_IRWXU)
            
        # Create file if it doesn't exist to apply permissions before writing data
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'a'): pass
            
        # Explicitly restrict database file to owner read/write (0600)
        os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        logging.debug(f"[*] Enforced strict 0600 permissions on database: {self.db_path}")

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """
        Yields a safe, transactional database connection that automatically 
        closes itself when the 'with' block exits, preventing locked DBs.
        """
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
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS leaked_secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    web_service_id INTEGER,
                    type TEXT NOT NULL,
                    secret_value TEXT NOT NULL,
                    location TEXT NOT NULL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(web_service_id, secret_value),
                    FOREIGN KEY(web_service_id) REFERENCES web_services(id)
                )
            ''')

    def add_endpoint(self, web_service_id: int, path: str, source: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO endpoints (web_service_id, path, source)
                VALUES (?, ?, ?)
            ''', (web_service_id, path, source))

    def add_secret(self, web_service_id: int, secret_type: str, value: str, location: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO leaked_secrets (web_service_id, type, secret_value, location)
                VALUES (?, ?, ?, ?)
            ''', (web_service_id, secret_type, value, location))

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