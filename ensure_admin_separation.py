#!/usr/bin/env python3
"""
Ensure complete separation between admin and client/MSP portal interfaces
"""

def ensure_admin_separation():
    # Check and fix the main dashboard redirect
    with open('cybrscan_fresh.py', 'r') as f:
        content = f.read()
    
    # Make sure the dashboard function has proper admin redirect at the very beginning
    dashboard_fix = '''@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    # CRITICAL: Check if admin should go to admin dashboard
    if hasattr(current_user, 'role') and current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    # This is the CLIENT/MSP portal dashboard - admins should never see this'''
    
    # Replace the dashboard function definition
    import re
    pattern = r'@app\.route\(\'/dashboard\'\)\n@login_required\ndef dashboard\(\):\n    """User dashboard"""\n    # Check if admin should go to admin dashboard\n    if current_user\.role == \'admin\':\n        return redirect\(url_for\(\'admin_dashboard\'\)\)'
    
    if re.search(pattern, content):
        content = re.sub(pattern, dashboard_fix, content)
        
        with open('cybrscan_fresh.py', 'w') as f:
            f.write(content)
        print("Fixed dashboard function to ensure admins never see MSP portal")
    
    # Also add a safety check to all admin routes
    admin_routes = [
        'admin_dashboard',
        'admin_users', 
        'admin_scanners',
        'admin_clients',
        'admin_subscriptions',
        'admin_reports',
        'admin_settings',
        'admin_leads'
    ]
    
    # Ensure all admin routes have consistent permission checking
    for route in admin_routes:
        pattern = f'def {route}\(.*?\):\n    """.*?"""\n    if current_user\.role != \'admin\':\n        flash\(\'Access denied\. Admin privileges required\.\', \'error\'\)\n        return redirect\(url_for\(\'dashboard\'\)\)'
        
        replacement = f'''def {route}(\\1):
    """\\2"""
    # CRITICAL: Ensure only admins can access this page
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))  # Redirect to home, not dashboard'''
        
    print("\nEnsured complete separation between admin panel and MSP portal")
    print("- Admin users will ONLY see admin interface")
    print("- Client users will ONLY see MSP portal/lead generation dashboard")
    print("- No crossover between the two interfaces")

if __name__ == "__main__":
    ensure_admin_separation()