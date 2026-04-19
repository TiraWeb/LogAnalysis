"""Quick connectivity + ingest test — run this to diagnose the issue."""
import requests, json
from datetime import datetime

OZ_URL  = 'http://localhost:5080'
OZ_USER = 'admin@velaris.local'
OZ_PASS = 'Admin1234!'
OZ_ORG  = 'default'

session = requests.Session()
session.auth = (OZ_USER, OZ_PASS)
session.headers['Content-Type'] = 'application/json'

# 1. Health check
print('=== Health ===')
r = session.get(f'{OZ_URL}/healthz')
print(r.status_code, r.text[:200])

# 2. List orgs (tells us the real org name)
print('\n=== Organisations ===')
r = session.get(f'{OZ_URL}/api/organizations')
print(r.status_code, r.text[:500])

# 3. Try pushing one test record
print('\n=== Test ingest ===')
record = [{
    '_timestamp': int(datetime.utcnow().timestamp() * 1_000_000),
    'service': 'debug-test',
    'level': 'info',
    'message': 'hello from debug script',
}]
r = session.post(f'{OZ_URL}/api/{OZ_ORG}/velaris_logs/_json', json=record)
print(r.status_code, r.text[:500])

# 4. List streams
print('\n=== Streams ===')
r = session.get(f'{OZ_URL}/api/{OZ_ORG}/streams')
print(r.status_code, r.text[:500])
