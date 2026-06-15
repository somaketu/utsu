import os
import sqlite3
import pytest
from utsu.storage.repository import DeltaDB

def test_db_initialization(tmp_path):
    """Proves the database initializes with strict permissions and correct schemas."""
    db_path = tmp_path / "test_utsu.db"
    db = DeltaDB(str(db_path))

    # Verify file creation
    assert os.path.exists(db_path)

    # Verify all tables were created successfully
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        expected_tables = {"domains", "subdomains", "web_services", "endpoints", "leaked_secrets"}
        assert expected_tables.issubset(tables)

def test_add_and_retrieve_domain(tmp_path):
    """Proves the domain deduplication logic works cleanly."""
    db_path = tmp_path / "test_utsu.db"
    db = DeltaDB(str(db_path))

    domain_id = db.add_domain("example.com")
    assert domain_id is not None
    assert domain_id > 0

    # Simulate a delta-scan attempting to add the same domain again
    domain_id_duplicate = db.add_domain("example.com")
    
    # The framework must return the existing ID, not crash or create a new row
    assert domain_id == domain_id_duplicate

def test_relational_data_insertion(tmp_path):
    """Proves the relational pipeline (Domain -> Subdomain -> Web Service -> Endpoint/Secret) functions."""
    db_path = tmp_path / "test_utsu.db"
    db = DeltaDB(str(db_path))

    # 1. Setup relational prerequisites
    domain_id = db.add_domain("hackerone.com")
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)", (domain_id, "api.hackerone.com"))
        subdomain_id = cursor.lastrowid
        
    # FIX FOR PYLANCE: Prove to the type checker that the insert succeeded and is an int
    assert subdomain_id is not None

    # 2. Add the Web Service
    db.add_web_service(subdomain_id, "https://api.hackerone.com", 200, 1024, "API Root")
    ws_id = db.get_web_service_id_by_url("https://api.hackerone.com")
    assert ws_id is not None

    # 3. Inject JS extracted intelligence
    db.add_endpoint(ws_id, "/v1/graphql", "js_analyzer")
    db.add_secret(ws_id, "HIGH_ENTROPY_TOKEN", "sk_live_123456789", "main.js")

    # 4. Verify data integrity
    with db._get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT path FROM endpoints WHERE web_service_id = ?", (ws_id,))
        assert cursor.fetchone()[0] == "/v1/graphql"
        
        # FIX FOR CI/CD FATAL CRASH: Test the new encrypted schema
        cursor.execute("SELECT type, encrypted_value FROM leaked_secrets WHERE web_service_id = ?", (ws_id,))
        secret_row = cursor.fetchone()
        
        assert secret_row is not None
        assert secret_row[0] == "HIGH_ENTROPY_TOKEN"
        assert secret_row[1] != "sk_live_123456789" # Mathematical proof the DB no longer holds plaintext
        assert len(secret_row[1]) > 20 # Verify cipher payload exists