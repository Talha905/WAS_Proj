#!/usr/bin/env python3
"""
Reset Demo Data Script
Re-initializes and seeds SQLite databases for before-fix and after-fix apps
to ensure predictable fixture IDs (Alice=1, Bob=2, Admin=3; Alice orders=1,2; Bob orders=3,4).
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def reset_app(app_name):
    app_dir = os.path.join(BASE_DIR, app_name)
    if not os.path.isdir(app_dir):
        print(f"[SKIP] Directory not found: {app_dir}")
        return False

    old_cwd = os.getcwd()
    os.chdir(app_dir)
    sys.path.insert(0, app_dir)
    try:
        from app import create_app
        from database import seed_db_command

        flask_app = create_app()
        with flask_app.app_context():
            seed_db_command.callback()

        print(f"[OK] Successfully reset and re-seeded {app_name} database.")
        return True
    except Exception as e:
        print(f"[ERROR] Exception while resetting {app_name}: {e}")
        return False
    finally:
        os.chdir(old_cwd)
        if sys.path and sys.path[0] == app_dir:
            sys.path.pop(0)
        # Clear cached modules from that app
        for mod in list(sys.modules.keys()):
            if mod in ('app', 'config', 'database') or mod.startswith('blueprints'):
                del sys.modules[mod]

def reset_all():
    print("=" * 60)
    print("ShopLite Demo Data Reset Utility")
    print("=" * 60)
    
    ok1 = reset_app('before-fix')
    ok2 = reset_app('after-fix')

    if ok1 and ok2:
        print("-" * 60)
        print("All demo databases are reset to baseline state.")
        print("  - Alice (ID #1): owns Orders 1, 2 | Products 1, 2")
        print("  - Bob   (ID #2): owns Orders 3, 4 | Products 3, 4")
        print("  - Admin (ID #3): system administrator")
        print("-" * 60)
        return True
    return False

if __name__ == '__main__':
    success = reset_all()
    sys.exit(0 if success else 1)
