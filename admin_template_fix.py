"""
Admin Template Fix - Remove hardcoded demo/example data
Ensures templates show only real data from backend
"""

import os
import re

def fix_admin_templates(template_dir):
    """Remove hardcoded demo data from admin templates"""
    
    fixes_applied = []
    
    # List of files to fix
    template_files = [
        'admin-dashboard.html',
        'client-management.html',
        'scanner-management.html',
        'scanner-management_minimal.html',
        'subscriptions-dashboard.html',
        'reports-dashboard_minimal.html'
    ]
    
    for template_file in template_files:
        file_path = os.path.join(template_dir, template_file)
        if not os.path.exists(file_path):
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix 1: Remove hardcoded example rows that show when no data
        # Look for patterns like {% else %} followed by example data
        
        # Pattern for removing example table rows
        example_patterns = [
            # Remove Acme Corp examples
            (r'<tr>\s*<td>Acme Corp</td>.*?</tr>', '', re.DOTALL),
            (r'<tr>\s*<td>\s*<div class="d-flex align-items-center">\s*<div class="client-logo me-3">AC</div>\s*<div>\s*<div class="fw-bold">Acme Corporation</div>.*?</tr>', '', re.DOTALL),
            
            # Remove john.smith examples
            (r'<tr>\s*<td>John Smith</td>.*?</tr>', '', re.DOTALL),
            (r'<td>john\.smith@acmecorp\.com</td>', '<td>No data</td>', 0),
            
            # Remove demo domain examples
            (r'acme-corp\.yourscannerdomain\.com', '#', 0),
            (r'demo\.example\.com', '#', 0),
            
            # Fix "Example row" comments
            (r'<!-- Example row \(only shown if no.*?\) -->', '<!-- No data placeholder -->', re.DOTALL),
            
            # Remove hardcoded activity examples
            (r'<div><strong>Acme Corp</strong>.*?</div>', '<div>No recent activity</div>', 0),
        ]
        
        for pattern, replacement, flags in example_patterns:
            if flags:
                content = re.sub(pattern, replacement, content, flags=flags)
            else:
                content = re.sub(pattern, replacement, content)
        
        # Fix 2: Ensure "No data" messages instead of examples
        if '{% else %}' in content:
            # Add proper no-data messages after {% else %} blocks
            content = re.sub(
                r'({% else %})\s*(?!.*?<tr.*?No .*? yet.*?</tr>)',
                r'\1\n                                                <tr>\n                                                    <td colspan="10" class="text-center text-muted py-4">No data available yet</td>\n                                                </tr>\n',
                content
            )
        
        # Fix 3: Remove specific hardcoded data
        replacements = [
            ('May 1, 2025', '{{ item.created_at|default("N/A") }}'),
            ('250', '{{ item.count|default(0) }}'),
            ('$2,400/mo', '{{ item.revenue|default("$0") }}'),
            ('32.5%', '{{ item.rate|default("0%") }}'),
        ]
        
        for old, new in replacements:
            content = content.replace(old, new)
        
        # Only write if changes were made
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            fixes_applied.append(template_file)
            print(f"✅ Fixed {template_file}")
    
    return fixes_applied

def add_no_data_placeholders(template_dir):
    """Ensure templates have proper no-data placeholders"""
    
    dashboard_file = os.path.join(template_dir, 'admin-dashboard.html')
    if os.path.exists(dashboard_file):
        with open(dashboard_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Ensure proper conditionals for empty data
        if 'recent_activity' in content and 'No recent activity' not in content:
            # Add check for empty recent_activity
            content = re.sub(
                r'({% for activity in recent_activity %})',
                r'{% if recent_activity %}\n                                            \1',
                content
            )
            content = re.sub(
                r'({% endfor %}\s*)(</div>\s*</div>\s*<!-- Activity)',
                r'\1\n                                            {% else %}\n                                            <div class="py-3 text-center text-muted">No recent activity</div>\n                                            {% endif %}\2',
                content
            )
        
        with open(dashboard_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print("✅ Added no-data placeholders to admin-dashboard.html")

if __name__ == "__main__":
    template_dir = "/home/gerrit/CybrScan_render-main/templates/admin"
    fixes = fix_admin_templates(template_dir)
    add_no_data_placeholders(template_dir)
    print(f"\n✅ Fixed {len(fixes)} template files")