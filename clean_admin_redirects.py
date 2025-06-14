#!/usr/bin/env python3
"""
Clean up incorrect admin redirect logic in admin routes
"""

def clean_admin_redirects():
    # Read the file
    with open('cybrscan_fresh.py', 'r') as f:
        content = f.read()
    
    # Pattern to match the problematic logic in admin routes
    bad_pattern = r'''        # Redirect based on user role
        if current_user\.role == 'admin':
            return redirect\(url_for\('admin_dashboard'\)\)
        return redirect\(url_for\('dashboard'\)\)'''
    
    # Replace with just the dashboard redirect
    good_replacement = '''        return redirect(url_for('dashboard'))'''
    
    # Apply the fix
    content = content.replace(bad_pattern, good_replacement)
    
    # Write back
    with open('cybrscan_fresh.py', 'w') as f:
        f.write(content)
    
    print("Cleaned up incorrect admin redirect logic")

if __name__ == "__main__":
    clean_admin_redirects()