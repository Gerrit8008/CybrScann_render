#!/usr/bin/env python3
"""
Quick fix to remove hardcoded demo data from client-management.html
"""

def fix_client_management_template():
    template_path = "/home/gerrit/CybrScan_render-main/templates/admin/client-management.html"
    
    try:
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Find tbody section and replace all hardcoded content
        start_marker = '<tbody>'
        end_marker = '</tbody>'
        
        start_idx = content.find(start_marker)
        end_idx = content.find(end_marker) + len(end_marker)
        
        if start_idx != -1 and end_idx != -1:
            # Create clean template logic
            clean_tbody = '''<tbody>
                                    {% if clients %}
                                        {% for client in clients %}
                                        <tr>
                                            <td>
                                                <div class="d-flex align-items-center">
                                                    <div class="client-logo me-3">{{ client.name[:2]|upper }}</div>
                                                    <div>
                                                        <div class="fw-bold">{{ client.name }}</div>
                                                        <div class="text-muted small">Since {{ client.created_at }}</div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td>{{ client.scanners }} scanners</td>
                                            <td>{{ client.email }}</td>
                                            <td>{{ client.email.split('@')[0] }}.yourscannerdomain.com</td>
                                            <td><span class="subscription-badge subscription-{{ client.subscription }}">{{ client.subscription|title }}</span></td>
                                            <td><span class="badge bg-success">Active</span></td>
                                            <td>{{ client.scans }}</td>
                                            <td>
                                                <div class="d-flex">
                                                    <button class="client-action" data-bs-toggle="tooltip" title="Edit">
                                                        <i class="bi bi-pencil"></i>
                                                    </button>
                                                    <button class="client-action" data-bs-toggle="tooltip" title="View">
                                                        <i class="bi bi-eye"></i>
                                                    </button>
                                                    <button class="client-action" data-bs-toggle="tooltip" title="More">
                                                        <i class="bi bi-three-dots-vertical"></i>
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                        {% endfor %}
                                    {% else %}
                                        <tr>
                                            <td colspan="8" class="text-center text-muted py-4">No clients yet - waiting for real users</td>
                                        </tr>
                                    {% endif %}
                                </tbody>'''
            
            # Replace the content
            new_content = content[:start_idx] + clean_tbody + content[end_idx:]
            
            # Write back
            with open(template_path, 'w') as f:
                f.write(new_content)
            
            print("✅ Fixed client-management.html - removed all hardcoded demo data")
            return True
            
    except Exception as e:
        print(f"❌ Error fixing client-management.html: {e}")
        return False

if __name__ == "__main__":
    fix_client_management_template()