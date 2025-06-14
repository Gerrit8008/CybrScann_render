"""
Admin Panel Real Data Patch
Ensures admin dashboard shows only real data, no demo data
"""

# Patch for cybrscan_fresh.py to show real data in admin panel
ADMIN_DASHBOARD_PATCH = '''
# CRITICAL FIX: Override admin routes to ensure real data only

# Store original routes
_original_admin_dashboard = admin_dashboard
_original_admin_clients = admin_clients
_original_admin_scanners = admin_scanners
_original_admin_reports = admin_reports

def admin_dashboard():
    """Admin dashboard - REAL DATA ONLY"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Force filter out ALL demo data
    real_users = []
    real_scanners = []
    real_scans = []
    real_leads = []
    
    # Get real users only (no demo)
    for user_id, user in users.items():
        if user_id == 'demo' or user.email == 'demo@example.com':
            continue  # Skip demo completely
        if user.role == 'client':
            real_users.append(user)
    
    # Get real scanners only
    for scanner in scanners_db.values():
        if scanner.get('user_id') == 'demo':
            continue  # Skip demo scanners
        # Verify owner is not demo
        owner_id = scanner.get('user_id')
        if owner_id in users and users[owner_id].email != 'demo@example.com':
            real_scanners.append(scanner)
    
    # Get real scans only
    for scan in scans_db.values():
        scanner_id = scan.get('scanner_id')
        if scanner_id in scanners_db:
            scanner = scanners_db[scanner_id]
            if scanner.get('user_id') != 'demo':
                real_scans.append(scan)
    
    # Get real leads only
    for lead in leads_db.values():
        if lead.get('user_id') == 'demo':
            continue
        real_leads.append(lead)
    
    # Calculate REAL statistics only
    total_clients = len(real_users)
    total_scanners = len(real_scanners)
    total_scans = len(real_scans)
    total_leads = len(real_leads)
    
    # Calculate REAL revenue (no demo data)
    monthly_revenue = 0
    for user in real_users:
        tier = user.subscription_level
        if tier in SUBSCRIPTION_TIERS and tier != 'basic':  # Don't count free tier
            monthly_revenue += SUBSCRIPTION_TIERS[tier]['price']
    
    total_revenue = monthly_revenue * 6  # 6 month estimate
    
    dashboard_stats = {
        'total_clients': total_clients,
        'total_scanners': total_scanners,
        'total_scans': total_scans,
        'total_leads': total_leads,
        'total_revenue': total_revenue,
        'monthly_revenue': monthly_revenue,
        'active_subscriptions': len([u for u in real_users if u.subscription_level != 'basic']),
        'conversion_rate': (total_leads / max(1, total_scans)) * 100 if total_scans > 0 else 0,
        'avg_scans_per_client': total_scans / max(1, total_clients) if total_clients > 0 else 0
    }
    
    # Get REAL recent activity only
    recent_activity = []
    
    # Add recent REAL client registrations
    for user in sorted(real_users, key=lambda x: getattr(x, 'created_at', '2024-01-01'), reverse=True)[:5]:
        if hasattr(user, 'created_at') and user.created_at:
            recent_activity.append({
                'type': 'New Client',
                'description': f'{user.email} registered',
                'time': user.created_at[:16].replace('T', ' ') if isinstance(user.created_at, str) else user.created_at.strftime('%Y-%m-%d %H:%M')
            })
    
    # Add recent REAL scans
    for scan in sorted(real_scans, key=lambda x: x.get('timestamp', ''), reverse=True)[:5]:
        if scan.get('timestamp'):
            recent_activity.append({
                'type': 'Scan Completed',
                'description': f'Security scan for {scan.get("domain", "unknown")}',
                'time': scan.get('timestamp', '')[:16].replace('T', ' ')
            })
    
    # Add recent REAL leads
    for lead in sorted(real_leads, key=lambda x: x.get('date_generated', ''), reverse=True)[:3]:
        if lead.get('date_generated'):
            recent_activity.append({
                'type': 'New Lead',
                'description': f'Lead: {lead.get("company", "Unknown")}',
                'time': lead.get('date_generated', '') + ' 12:00'
            })
    
    # Sort and limit
    recent_activity.sort(key=lambda x: x.get('time', ''), reverse=True)
    recent_activity = recent_activity[:5]
    
    # If no activity, show waiting message
    if not recent_activity:
        recent_activity = [{
            'type': 'System',
            'description': 'No activity yet - waiting for real users',
            'time': datetime.now().strftime('%Y-%m-%d %H:%M')
        }]
    
    # REAL subscription breakdown
    subscription_breakdown = {}
    for tier_name in SUBSCRIPTION_TIERS.keys():
        tier_users = [u for u in real_users if u.subscription_level == tier_name]
        tier_price = SUBSCRIPTION_TIERS[tier_name]['price']
        subscription_breakdown[tier_name] = {
            'count': len(tier_users),
            'revenue': len(tier_users) * tier_price
        }
    
    return render_template('admin/admin-dashboard.html',
                         user=current_user,
                         dashboard_stats=dashboard_stats,
                         recent_activity=recent_activity,
                         subscription_breakdown=subscription_breakdown,
                         subscription_levels=SUBSCRIPTION_TIERS)

# Replace the routes
app.view_functions['admin_dashboard'] = admin_dashboard
'''

def apply_admin_realdata_patch(app_file_path):
    """Apply the patch to ensure real data in admin panel"""
    try:
        # Read the current file
        with open(app_file_path, 'r') as f:
            content = f.read()
        
        # Check if patch already applied
        if 'CRITICAL FIX: Override admin routes' in content:
            print("✅ Admin real data patch already applied")
            return True
        
        # Find where to insert the patch (after all route definitions)
        insert_position = content.rfind('if __name__ ==')
        if insert_position == -1:
            insert_position = len(content) - 1
        
        # Insert the patch
        patched_content = content[:insert_position] + '\n\n' + ADMIN_DASHBOARD_PATCH + '\n\n' + content[insert_position:]
        
        # Write back
        with open(app_file_path, 'w') as f:
            f.write(patched_content)
        
        print("✅ Admin real data patch applied successfully")
        return True
        
    except Exception as e:
        print(f"❌ Failed to apply admin patch: {e}")
        return False