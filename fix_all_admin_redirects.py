#!/usr/bin/env python3
"""
Fix ALL admin redirects throughout the application
"""

import re

def fix_all_admin_redirects():
    # Read the file
    with open('cybrscan_fresh.py', 'r') as f:
        lines = f.readlines()
    
    # Track changes
    changes_made = []
    
    # Process each line
    for i, line in enumerate(lines):
        # Look for redirect(url_for('dashboard'))
        if "return redirect(url_for('dashboard'))" in line and i > 0:
            # Check if this is in a function that might be used by admins
            # Look back to find the function definition
            function_line = None
            for j in range(i-1, max(0, i-50), -1):
                if lines[j].strip().startswith('def '):
                    function_line = j
                    function_name = lines[j].strip()
                    break
            
            # Skip if already has admin check nearby
            admin_check_exists = False
            for j in range(max(0, i-10), min(len(lines), i+10)):
                if 'current_user.role == "admin"' in lines[j]:
                    admin_check_exists = True
                    break
            
            if not admin_check_exists and function_line is not None:
                # Get indentation
                indent = len(line) - len(line.lstrip())
                spaces = ' ' * indent
                
                # Replace the line with admin check
                new_lines = [
                    f"{spaces}# Redirect based on user role\n",
                    f"{spaces}if current_user.role == 'admin':\n",
                    f"{spaces}    return redirect(url_for('admin_dashboard'))\n",
                    f"{spaces}return redirect(url_for('dashboard'))\n"
                ]
                
                lines[i] = ''.join(new_lines)
                changes_made.append(f"Line {i+1}: Added admin redirect check in {function_name}")
    
    # Write back
    with open('cybrscan_fresh.py', 'w') as f:
        f.writelines(lines)
    
    print(f"Fixed {len(changes_made)} redirect locations")
    for change in changes_made:
        print(f"  - {change}")
    
    return len(changes_made)

if __name__ == "__main__":
    changes = fix_all_admin_redirects()
    if changes == 0:
        print("\nNo additional changes needed - all redirects already handle admin role correctly.")