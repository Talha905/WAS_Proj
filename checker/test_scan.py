import sys, uuid
sys.path.insert(0, '.')
from database import init_db, create_scan, get_scan, get_results
from engine.scanner import Scanner

init_db()

config = {
    'target_url': 'http://localhost:5001',
    'spec_type': 'manual',
    'spec': [
        {'path': '/api/auth/me', 'method': 'GET', 'requires_auth': True},
        {'path': '/api/admin/users', 'method': 'GET', 'requires_auth': True, 'tags': ['admin']},
    ],
    'roles': [{'name': 'user_a', 'type': 'bearer', 'value': 'bad_token'}],
    'known_ids': {}
}

scan_id = create_scan(config['target_url'], 'manual', config)
print('Scan created:', scan_id[:8])

s = Scanner(scan_id, config)
s.run()

scan = get_scan(scan_id)
results = get_results(scan_id)
print('Status:', scan['status'])
print('Results:', len(results))
for r in results:
    verdict = r['verdict']
    status = r['actual_status']
    module = r['module_name']
    endpoint = r['endpoint']
    method = r['method']
    print(f'  {method} {endpoint} [{module}] -> {verdict} (HTTP {status})')
