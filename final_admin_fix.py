#!/usr/bin/env python3
"""
Final fix to ensure complete separation of admin, client, and lead generation panels
"""

def apply_final_fix():
    # Read the main app file
    with open('cybrscan_fresh.py', 'r') as f:
        content = f.read()
    
    # Fix 1: Ensure dashboard function has strong admin check
    dashboard_fix = '''@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard - ONLY for clients"""
    # CRITICAL: Admins must NEVER see client/MSP dashboard
    if hasattr(current_user, 'role') and current_user.role == 'admin':
        # Admin detected - redirect to admin dashboard immediately
        return redirect(url_for('admin_dashboard'))
    
    # Only clients see this MSP/Lead Generation dashboard'''
    
    # Apply dashboard fix
    import re
    content = re.sub(
        r'@app\.route\(\'/dashboard\'\)\n@login_required\ndef dashboard\(\):\n.*?"User dashboard.*?"\n.*?# CRITICAL:.*?\n.*?if current_user\.role == \'admin\':\n.*?return redirect\(url_for\(\'admin_dashboard\'\)\)\n.*?\n.*?# This is the CLIENT/MSP portal dashboard - admins should NEVER see this',
        dashboard_fix,
        content,
        flags=re.DOTALL
    )
    
    # Write back
    with open('cybrscan_fresh.py', 'w') as f:
        f.write(content)
    
    print("Applied final admin separation fix")
    print("- Dashboard route now has stronger admin detection")
    print("- Admins will ALWAYS go to admin dashboard")
    print("- Clients will see MSP/Lead Generation dashboard")

if __name__ == "__main__":
    apply_final_fix()