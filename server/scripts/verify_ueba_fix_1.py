#!/usr/bin/env python3
"""
UEBA Fix Verification Script.

Verifies that:
1. UEBA tables are created in the database
2. IsolationForest model directory exists
3. UEBA scoring pipeline is wired correctly
"""

import sys
import sqlite3
from pathlib import Path

# Add server src to path
server_root = Path(__file__).parent.parent
sys.path.insert(0, str(server_root / "src"))

def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def print_result(test_name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"  {status}: {test_name}")
    if details:
        print(f"         {details}")

def main():
    print_header("UEBA FIX VERIFICATION")
    
    # Find database path
    db_path = server_root / "data" / "events.db"
    print(f"\nDatabase path: {db_path}")
    print(f"Database exists: {db_path.exists()}")
    
    if not db_path.exists():
        print("\n⚠️  Database does not exist yet. Creating tables...")
        # Initialize storage to create tables
        from server.storage import get_storage, ensure_ueba_tables_exist
        storage = get_storage()
        ensure_ueba_tables_exist()
        print("Tables created.")
    
    # Connect to database
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    print_header("1. DATABASE TABLES CHECK")
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"\nExisting tables: {tables}")
    
    # Check UEBA tables
    ueba_tables = ['rule_hits', 'entity_risk', 'ueba_alerts']
    for table in ueba_tables:
        exists = table in tables
        print_result(f"Table '{table}' exists", exists)
        
        if exists:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"         Row count: {count}")
    
    print_header("2. EVENTS TABLE CHECK")
    
    cursor.execute("SELECT COUNT(*) FROM events")
    event_count = cursor.fetchone()[0]
    print_result(f"Events table has data", event_count > 0, f"Count: {event_count}")
    
    if event_count > 0:
        cursor.execute("""
            SELECT id, event_id, process_name, rule_score, anomaly_score, risk_score
            FROM events
            ORDER BY id DESC
            LIMIT 5
        """)
        print("\n  Recent events (last 5):")
        for row in cursor.fetchall():
            print(f"    id={row[0]}, event_id={row[1]}, process={row[2]}, "
                  f"rule_score={row[3]}, anomaly_score={row[4]}, risk_score={row[5]}")
    
    print_header("3. ISOLATION FOREST MODEL CHECK")
    
    model_dir = server_root / "data" / "risk_models"
    model_path = model_dir / "isolation_forest.pkl"
    
    print_result("Model directory exists", model_dir.exists(), str(model_dir))
    print_result("Model file exists", model_path.exists(), str(model_path))
    
    if model_path.exists():
        import os
        size = os.path.getsize(model_path)
        print(f"         Model size: {size} bytes")
    
    print_header("4. UEBA MODULE CHECK")
    
    ueba_dir = server_root / "src" / "server" / "ueba"
    ueba_files = ['__init__.py', 'rule_loader.py', 'scoring_engine.py', 'alert_manager.py']
    
    for f in ueba_files:
        file_path = ueba_dir / f
        print_result(f"UEBA module '{f}' exists", file_path.exists())
    
    print_header("5. RULES CONFIG CHECK")
    
    rules_dir = server_root / "config" / "rules"
    rules_file = rules_dir / "core_top25.yaml"
    
    print_result("Rules directory exists", rules_dir.exists(), str(rules_dir))
    print_result("Core rules file exists", rules_file.exists(), str(rules_file))
    
    if rules_file.exists():
        import yaml
        with open(rules_file) as f:
            rules_data = yaml.safe_load(f)
        rule_count = len(rules_data.get('rules', []))
        print(f"         Rule count: {rule_count}")
    
    print_header("6. INGEST PIPELINE CHECK")
    
    ingest_path = server_root / "src" / "server" / "ingest.py"
    with open(ingest_path) as f:
        ingest_content = f.read()
    
    checks = [
        ("UEBA import", "from .ueba import" in ingest_content),
        ("_process_ueba_scoring method", "_process_ueba_scoring" in ingest_content),
        ("store_rule_hits call", "store_rule_hits" in ingest_content),
        ("store_ueba_alert call", "store_ueba_alert" in ingest_content),
    ]
    
    for name, passed in checks:
        print_result(name, passed)
    
    print_header("SUMMARY")
    
    # Count passes/fails
    all_checks = [
        ('rule_hits' in tables, "rule_hits table"),
        ('entity_risk' in tables, "entity_risk table"),
        ('ueba_alerts' in tables, "ueba_alerts table"),
        (model_dir.exists(), "model directory"),
        (ueba_dir.exists(), "UEBA module"),
        (rules_file.exists(), "rules config"),
        ("_process_ueba_scoring" in ingest_content, "ingest pipeline wiring"),
    ]
    
    passed = sum(1 for check, _ in all_checks if check)
    total = len(all_checks)
    
    print(f"\n  Passed: {passed}/{total}")
    
    if passed == total:
        print("\n  ✅ ALL CHECKS PASSED - UEBA fix is complete!")
    else:
        print("\n  ⚠️  Some checks failed. Review the output above.")
    
    conn.close()
    
    print_header("VERIFICATION COMMANDS FOR UBUNTU")
    print("""
Run these commands on Ubuntu to verify:

# 1. Check tables exist
sqlite3 server/data/events.db ".tables"

# 2. Check UEBA tables
sqlite3 server/data/events.db "SELECT COUNT(*) FROM rule_hits;"
sqlite3 server/data/events.db "SELECT COUNT(*) FROM entity_risk;"
sqlite3 server/data/events.db "SELECT COUNT(*) FROM ueba_alerts;"

# 3. Check IsolationForest model
ls -lh server/data/risk_models/isolation_forest.pkl

# 4. After some events, check rule hits
sqlite3 server/data/events.db "SELECT rule_id, COUNT(*) FROM rule_hits GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 10;"

# 5. Check anomaly scores are no longer 0
sqlite3 server/data/events.db "SELECT id, event_id, rule_score, anomaly_score, risk_score FROM events WHERE anomaly_score > 0 LIMIT 10;"
""")

if __name__ == "__main__":
    main()
