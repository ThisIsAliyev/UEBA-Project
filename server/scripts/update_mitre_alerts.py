"""Script to update existing alerts with MITRE data based on behavior."""
import sqlite3
import json

# MITRE mapping for behaviors
mapping = {
    'failed_login_burst': (['TA0006'], ['T1110.003']),
    'suspicious_path_execution': (['TA0002'], ['T1055']),
    'security_log_clearing': (['TA0005'], ['T1070.001']),
    'restricted_hours_login': (['TA0001'], ['T1078']),
    'firewall_disabled': (['TA0005'], ['T1562.004'])
}

conn = sqlite3.connect('data/ueba.db')
cursor = conn.cursor()

# Find alerts without MITRE data
cursor.execute("""
    SELECT id, behavior FROM alerts 
    WHERE mitre_tactics IS NULL 
       OR mitre_tactics = '[]' 
       OR mitre_tactics = ''
""")
alerts = cursor.fetchall()
print(f'Found {len(alerts)} alerts without MITRE data')

for alert_id, behavior in alerts:
    if behavior in mapping:
        tactics, techniques = mapping[behavior]
        cursor.execute(
            'UPDATE alerts SET mitre_tactics = ?, mitre_techniques = ? WHERE id = ?',
            (json.dumps(tactics), json.dumps(techniques), alert_id)
        )
        print(f'  Updated alert {alert_id} ({behavior}) with {techniques}')

conn.commit()
conn.close()
print('Done!')
