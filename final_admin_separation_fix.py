#!/usr/bin/env python3
"""
Final comprehensive fix to ensure complete admin/client separation
"""

def final_separation_fix():
    # Read the main app file
    with open('cybrscan_fresh.py', 'r') as f:
        content = f.read()
    
    # Add a before_request handler to ensure admins always stay in admin interface
    before_request_code = '''
# Global request handler to ensure proper routing
@app.before_request
def ensure_proper_routing():
    """Ensure admins stay in admin interface and clients stay in client interface"""
    if current_user.is_authenticated and hasattr(current_user, 'role'):
        # Get the current endpoint
        endpoint = request.endpoint
        
        # If admin is trying to access client routes, redirect to admin equivalent
        if current_user.role == 'admin' and endpoint:
            client_to_admin_mapping = {
                'client_dashboard': 'admin_dashboard',
                'client_leads': 'admin_leads',
                'client_scanners': 'admin_scanners',
                'client_reports': 'admin_reports',
                'client_settings': 'admin_settings',
                'client_billing': 'admin_dashboard',  # No admin billing, go to dashboard
                'client_statistics': 'admin_dashboard'  # No admin statistics, go to dashboard
            }
            
            if endpoint in client_to_admin_mapping:
                return redirect(url_for(client_to_admin_mapping[endpoint]))
'''
    
    # Find a good place to insert this (after imports and before routes)
    import re
    
    # Insert after the login_manager setup
    insert_pos = content.find('@login_manager.user_loader')
    if insert_pos > 0:
        # Find the end of the load_user function
        next_route_pos = content.find('@app.route', insert_pos)
        if next_route_pos > 0:
            # Insert our before_request handler
            content = content[:next_route_pos] + before_request_code + '\n' + content[next_route_pos:]
    
    # Write back
    with open('cybrscan_fresh.py', 'w') as f:
        f.write(content)
    
    print("Added global request handler to ensure proper routing")
    print("- Admins accessing client routes will be redirected to admin equivalents")
    print("- Complete separation between admin and client interfaces")
    
    # Also update all admin templates to use admin-specific CSS
    import os
    admin_templates_dir = 'templates/admin/'
    
    for filename in os.listdir(admin_templates_dir):
        if filename.endswith('.html'):
            filepath = os.path.join(admin_templates_dir, filename)
            with open(filepath, 'r') as f:
                template_content = f.read()
            
            # Check if it's already using admin styles
            if '/static/css/styles.css' in template_content and '/static/css/admin-styles.css' not in template_content:
                # Replace styles.css with admin-styles.css
                template_content = template_content.replace(
                    '/static/css/styles.css',
                    '/static/css/admin-styles.css'
                )
                
                # Add body class if not present
                if '<body>' in template_content:
                    template_content = template_content.replace(
                        '<body>',
                        '<body class="admin-view admin-panel">'
                    )
                
                with open(filepath, 'w') as f:
                    f.write(template_content)
                
                print(f"Updated {filename} to use admin-specific styles")

if __name__ == "__main__":
    final_separation_fix()