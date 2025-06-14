#!/usr/bin/env python3
"""
Quick fix to remove hardcoded demo data from scanner-management.html
"""

def fix_scanner_management_template():
    template_path = "/home/gerrit/CybrScan_render-main/templates/admin/scanner-management.html"
    
    try:
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Remove hardcoded demo company references
        demo_patterns = [
            'Global Innovations',
            'Stellar Services', 
            'Stellar Security',
            'TechFlow Solutions',
            'Quantum Data',
            'BlueTech Industries'
        ]
        
        for pattern in demo_patterns:
            if pattern in content:
                # Replace with generic placeholder
                content = content.replace(pattern, 'Unknown Company')
                print(f"✅ Removed '{pattern}' reference")
        
        # Write back
        with open(template_path, 'w') as f:
            f.write(content)
        
        print("✅ Fixed scanner-management.html - removed hardcoded demo data")
        return True
        
    except Exception as e:
        print(f"❌ Error fixing scanner-management.html: {e}")
        return False

if __name__ == "__main__":
    fix_scanner_management_template()