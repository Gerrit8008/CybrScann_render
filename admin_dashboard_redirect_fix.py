#!/usr/bin/env python3
"""
Fix admin dashboard redirects to prevent admins from being sent to client dashboard
"""

import re

def fix_admin_redirects():
    # Read the file
    with open('cybrscan_fresh.py', 'r') as f:
        content = f.read()
    
    # Find the dashboard function to add admin check
    dashboard_pattern = r'(@app\.route\(\'/dashboard\'\)\n@login_required\ndef dashboard\(\):\n    """User dashboard""")'
    dashboard_replacement = r'\1\n    # Check if admin should go to admin dashboard\n    if current_user.role == "admin":\n        return redirect(url_for("admin_dashboard"))'
    
    content = re.sub(dashboard_pattern, dashboard_replacement, content)
    
    # Also fix create_scanner redirect for admins
    # Find pattern where scanner is created and redirects to dashboard
    scanner_redirect_pattern = r'(flash\(\'Scanner created successfully[^\']*\', \'success\'\)\s*\n\s*return redirect\(url_for\(\'dashboard\'\)\))'
    scanner_redirect_replacement = r'flash("Scanner created successfully!", "success")\n        # Redirect admin to admin dashboard\n        if current_user.role == "admin":\n            return redirect(url_for("admin_dashboard"))\n        return redirect(url_for("dashboard"))'
    
    content = re.sub(scanner_redirect_pattern, scanner_redirect_replacement, content)
    
    # Fix scanner update redirect
    update_redirect_pattern = r'(flash\(\'Scanner updated successfully[^\']*\', \'success\'\)\s*\n\s*return redirect\(url_for\(\'dashboard\'\)\))'
    update_redirect_replacement = r'flash("Scanner updated successfully!", "success")\n        # Redirect admin to admin dashboard\n        if current_user.role == "admin":\n            return redirect(url_for("admin_dashboard"))\n        return redirect(url_for("dashboard"))'
    
    content = re.sub(update_redirect_pattern, update_redirect_replacement, content)
    
    # Write back
    with open('cybrscan_fresh.py', 'w') as f:
        f.write(content)
    
    print("Fixed admin dashboard redirects")
    
    # Show what was changed
    print("\nChanges made:")
    print("1. Added admin check to main dashboard route")
    print("2. Fixed scanner creation redirect for admins")
    print("3. Fixed scanner update redirect for admins")

if __name__ == "__main__":
    fix_admin_redirects()