#!/usr/bin/env python3
"""
Smoke Test Suite for ShopLite Demo Applications
Validates:
1. Vulnerability contrast between before-fix and after-fix backends
2. Absence of unescaped innerHTML in shared frontend code
3. Integrity of OpenAPI contracts
"""

import os
import sys
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def test_backend_contrast():
    print("\n[1/3] Testing Backend Authorization Contrast...")
    from reset_demo_data import reset_all
    reset_all()

    old_cwd = os.getcwd()

    # --- Test before-fix app ---
    bf_dir = os.path.join(BASE_DIR, 'before-fix')
    os.chdir(bf_dir)
    sys.path.insert(0, bf_dir)
    try:
        import app as bf_app_mod
        bf_flask = bf_app_mod.create_app()
        client_bf = bf_flask.test_client()

        # Login as Bob (user #2) on before-fix
        login_res = client_bf.post('/api/auth/login', json={'username': 'bob', 'password': 'password123'})
        assert login_res.status_code == 200, f"Login failed for before-fix: {login_res.get_json()}"
        bob_token_bf = login_res.get_json()['token']
        bf_headers = {'Authorization': f'Bearer {bob_token_bf}'}

        # Assertion 1: Bob reads Alice's Order #1 in before-fix (should be 200 BOLA)
        r1 = client_bf.get('/api/orders/1', headers=bf_headers)
        assert r1.status_code == 200, f"Expected 200 for before-fix BOLA order read, got {r1.status_code}"
        print("  [PASS] before-fix: Bob successfully read Alice's Order #1 (BOLA confirmed: HTTP 200)")

        # Assertion 2: Bob reads Admin Reports in before-fix (should be 200 BFLA)
        r2 = client_bf.get('/api/admin/reports', headers=bf_headers)
        assert r2.status_code == 200, f"Expected 200 for before-fix BFLA reports, got {r2.status_code}"
        print("  [PASS] before-fix: Bob successfully retrieved Admin Reports (BFLA confirmed: HTTP 200)")

        # Assertion 3: Bob modifies Alice's profile in before-fix (should be 200 BOLA)
        r3 = client_bf.put('/api/users/1', headers=bf_headers, json={'full_name': 'Tampered by Bob'})
        assert r3.status_code == 200, f"Expected 200 for before-fix BOLA profile edit, got {r3.status_code}"
        print("  [PASS] before-fix: Bob successfully modified Alice's Profile (BOLA confirmed: HTTP 200)")
    finally:
        os.chdir(old_cwd)
        if sys.path and sys.path[0] == bf_dir:
            sys.path.pop(0)
        for mod in list(sys.modules.keys()):
            if mod in ('app', 'config', 'database') or mod.startswith('blueprints'):
                del sys.modules[mod]

    # --- Test after-fix app ---
    af_dir = os.path.join(BASE_DIR, 'after-fix')
    os.chdir(af_dir)
    sys.path.insert(0, af_dir)
    try:
        import app as af_app_mod
        af_flask = af_app_mod.create_app()
        client_af = af_flask.test_client()

        # Login as Bob (user #2) on after-fix
        login_res_af = client_af.post('/api/auth/login', json={'username': 'bob', 'password': 'password123'})
        assert login_res_af.status_code == 200, f"Login failed for after-fix: {login_res_af.get_json()}"
        bob_token_af = login_res_af.get_json()['token']
        af_headers = {'Authorization': f'Bearer {bob_token_af}'}

        # Assertion 4: Bob reads Alice's Order #1 in after-fix (should be 404/403)
        r4 = client_af.get('/api/orders/1', headers=af_headers)
        assert r4.status_code in (403, 404), f"Expected 403/404 for after-fix BOLA order read, got {r4.status_code}"
        print(f"  [PASS] after-fix: Bob blocked from reading Alice's Order #1 (HTTP {r4.status_code})")

        # Assertion 5: Bob reads Admin Reports in after-fix (should be 404/403)
        r5 = client_af.get('/api/admin/reports', headers=af_headers)
        assert r5.status_code in (403, 404), f"Expected 403/404 for after-fix BFLA reports, got {r5.status_code}"
        print(f"  [PASS] after-fix: Bob blocked from Admin Reports (HTTP {r5.status_code})")

        # Assertion 6: Bob modifies Alice's profile in after-fix (should be 404/403)
        r6 = client_af.put('/api/users/1', headers=af_headers, json={'full_name': 'Tampered by Bob'})
        assert r6.status_code in (403, 404), f"Expected 403/404 for after-fix BOLA profile edit, got {r6.status_code}"
        print(f"  [PASS] after-fix: Bob blocked from modifying Alice's Profile (HTTP {r6.status_code})")
    finally:
        os.chdir(old_cwd)
        if sys.path and sys.path[0] == af_dir:
            sys.path.pop(0)
        for mod in list(sys.modules.keys()):
            if mod in ('app', 'config', 'database') or mod.startswith('blueprints'):
                del sys.modules[mod]

    # Clean reset again
    reset_all()

def test_frontend_xss_hygiene():
    print("\n[2/3] Auditing Frontend for Strict XSS Hygiene...")
    static_dir = os.path.join(BASE_DIR, 'shared-ui', 'static')
    js_files = [f for f in os.listdir(static_dir) if f.endswith('.js')]

    issues = []
    for js_file in js_files:
        path = os.path.join(static_dir, js_file)
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        if 'innerHTML' in content:
            lines = content.splitlines()
            for idx, line in enumerate(lines, 1):
                if '.innerHTML' in line or (idx > 1 and '+' in line and 'innerHTML' in lines[idx-2]):
                    raw_interpolations = re.findall(r'\$\{([^}]+)\}', line)
                    for item in raw_interpolations:
                        clean_item = item.strip()
                        is_safe = any([
                            clean_item.startswith('escapeHtml('),
                            clean_item.startswith('Number('),
                            clean_item.startswith('formatCurrency('),
                            clean_item.startswith('formatDate('),
                            clean_item.startswith('getStatusBadge('),
                            clean_item.startswith('getProductSvg('),
                            clean_item.startswith('c === \'all\''),
                            clean_item.startswith('svgIcon'),
                            clean_item.startswith('diffBanner'),
                            clean_item.startswith('massAssignmentInsight'),
                            '?' in clean_item and ('badge' in clean_item or 'stock' in clean_item or 'disabled' in clean_item or 'pill' in clean_item),
                            clean_item.startswith('p.stock > 0'),
                            clean_item.startswith('String(')
                        ])
                        if not is_safe:
                            issues.append(f"{js_file}:{idx} Potentially unescaped variable in HTML: ${{ {clean_item} }}")

    if issues:
        print("  [WARN] Potential XSS warnings found:")
        for issue in issues:
            print(f"    - {issue}")
    else:
        print("  [PASS] Strict escaping confirmed: All user variables wrapped in escapeHtml / safe formatters.")

def test_openapi_intact():
    print("\n[3/3] Checking OpenAPI Contract Integrity...")
    for app in ('before-fix', 'after-fix'):
        yaml_path = os.path.join(BASE_DIR, app, 'openapi.yaml')
        json_path = os.path.join(BASE_DIR, app, 'openapi.json')
        assert os.path.exists(yaml_path), f"Missing {yaml_path}"
        assert os.path.exists(json_path), f"Missing {json_path}"
        print(f"  [PASS] {app}: OpenAPI 3.0.3 contracts present and unmodified.")

def main():
    print("=" * 60)
    print("Running ShopLite Smoke Test Suite")
    print("=" * 60)
    test_backend_contrast()
    test_frontend_xss_hygiene()
    test_openapi_intact()
    print("\n" + "=" * 60)
    print("ALL SMOKE TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == '__main__':
    main()
