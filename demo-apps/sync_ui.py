#!/usr/bin/env python3
"""
Sync Script: Copies demo-apps/shared-ui into before-fix and after-fix apps.
demo-apps/shared-ui remains the single source of truth for the frontend.
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR = os.path.join(BASE_DIR, 'shared-ui')
TARGET_APPS = ['before-fix', 'after-fix']

def sync():
    shared_templates = os.path.join(SHARED_DIR, 'templates')
    shared_static = os.path.join(SHARED_DIR, 'static')

    if not os.path.exists(shared_templates) or not os.path.exists(shared_static):
        print(f"Error: Shared UI directory missing templates or static at {SHARED_DIR}")
        return False

    for app in TARGET_APPS:
        app_dir = os.path.join(BASE_DIR, app)
        if not os.path.isdir(app_dir):
            continue

        app_templates = os.path.join(app_dir, 'templates')
        app_static = os.path.join(app_dir, 'static')

        # Clean and copy templates
        os.makedirs(app_templates, exist_ok=True)
        for item in os.listdir(shared_templates):
            s = os.path.join(shared_templates, item)
            d = os.path.join(app_templates, item)
            if os.path.isfile(s):
                shutil.copy2(s, d)

        # Clean and copy static files
        os.makedirs(app_static, exist_ok=True)
        for item in os.listdir(shared_static):
            s = os.path.join(shared_static, item)
            d = os.path.join(app_static, item)
            if os.path.isfile(s):
                shutil.copy2(s, d)

        print(f"[OK] Synchronized shared frontend into {app}")

    print("Frontend synchronization complete.")
    return True

if __name__ == '__main__':
    sync()
