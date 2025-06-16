#!/usr/bin/env python3
"""
Fix admin templates to ensure they're completely separate from client/MSP portal
"""

import os

def fix_admin_navigation():
    """Ensure all admin templates have consistent navigation without MSP/client elements"""
    
    # Standard admin navigation HTML
    admin_nav = '''                <div class="px-3">
                    <a href="/admin/dashboard" class="sidebar-link{active_dashboard}">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                    <a href="/admin/clients" class="sidebar-link{active_clients}">
                        <i class="bi bi-people"></i> Client Management
                    </a>
                    <a href="/admin/scanners" class="sidebar-link{active_scanners}">
                        <i class="bi bi-shield-check"></i> Scanner Management
                    </a>
                    <a href="/admin/leads" class="sidebar-link{active_leads}">
                        <i class="bi bi-person-plus"></i> Lead Management
                    </a>
                    <a href="/customize" class="sidebar-link{active_customize}">
                        <i class="bi bi-plus-circle"></i> Create Scanner
                    </a>
                    <a href="/admin/subscriptions" class="sidebar-link{active_subscriptions}">
                        <i class="bi bi-credit-card"></i> Subscriptions
                    </a>
                    <a href="/admin/reports" class="sidebar-link{active_reports}">
                        <i class="bi bi-file-earmark-text"></i> Reports
                    </a>
                    <a href="/admin/settings" class="sidebar-link{active_settings}">
                        <i class="bi bi-gear"></i> Settings
                    </a>
        
                    <hr class="my-4">
        
                    <a href="/auth/logout" class="sidebar-link text-danger">
                        <i class="bi bi-box-arrow-right"></i> Logout
                    </a>
                </div>'''
    
    # Templates to fix and their active states
    templates = {
        'scanner-management_minimal.html': 'scanners',
        'settings-dashboard_minimal.html': 'settings',
    }
    
    admin_dir = 'templates/admin/'
    
    for template, active_page in templates.items():
        filepath = os.path.join(admin_dir, template)
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Create active states dict
            active_states = {
                'active_dashboard': '',
                'active_clients': '',
                'active_scanners': '',
                'active_leads': '',
                'active_customize': '',
                'active_subscriptions': '',
                'active_reports': '',
                'active_settings': ''
            }
            
            # Set the active page
            if active_page:
                active_states[f'active_{active_page}'] = ' active'
            
            # Format the navigation with active states
            formatted_nav = admin_nav.format(**active_states)
            
            # Replace the navigation section
            # Look for the sidebar div and replace its content
            import re
            
            # Pattern to find the navigation div
            pattern = r'(<div class="px-3">.*?</div>)(?=\s*</div>\s*<!-- Main Content -->|$)'
            
            # Replace with our standard navigation
            new_content = re.sub(pattern, formatted_nav, content, flags=re.DOTALL)
            
            # Also ensure we're using consistent sidebar styling
            new_content = re.sub(
                r'class="d-block text-light text-decoration-none p-2 mb-1[^"]*"',
                'class="sidebar-link"',
                new_content
            )
            
            # Fix the active state for current page
            if active_page == 'scanners':
                new_content = re.sub(
                    r'(<a href="/admin/scanners"[^>]+class="sidebar-link)(")',
                    r'\1 active\2',
                    new_content
                )
            
            # Write back
            with open(filepath, 'w') as f:
                f.write(new_content)
            
            print(f"Fixed {template}")
    
    print("\nAdmin templates have been fixed to ensure complete separation from client/MSP portal")

if __name__ == "__main__":
    fix_admin_navigation()