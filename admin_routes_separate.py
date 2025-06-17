"""
Completely separate admin routes to prevent mixing with client dashboard
"""

from flask import render_template, redirect, url_for, flash
from datetime import datetime

def create_admin_routes(app, users, scanners_db, leads_db, scans_db, SUBSCRIPTION_TIERS, current_user, login_required):
    
    @app.route('/admin/dashboard/platform')
    @login_required
    def admin_platform_dashboard():
        """COMPLETELY SEPARATE Admin dashboard - Platform overview only"""
        if current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get ALL real clients (exclude demo users) - PLATFORM WIDE
        all_platform_clients = []
        for user_id, user in users.items():
            # Skip ALL demo accounts
            if user_id == 'demo' or user.email == 'demo@example.com' or user.email.startswith('demo') or '@example.com' in user.email:
                continue
            if user.role == 'client':
                all_platform_clients.append(user)
        
        # Get ALL real scanners from ALL clients - PLATFORM WIDE
        all_platform_scanners = []
        for scanner in scanners_db.values():
            user_id = scanner.get('user_id')
            if user_id == 'demo':
                continue
            if user_id in users and (users[user_id].email == 'demo@example.com' or users[user_id].email.startswith('demo') or '@example.com' in users[user_id].email):
                continue
            all_platform_scanners.append(scanner)
        
        # Get ALL real scans from ALL clients - PLATFORM WIDE
        all_platform_scans = []
        for scan in scans_db.values():
            scanner = scanners_db.get(scan.get('scanner_id'))
            if scanner:
                user_id = scanner.get('user_id')
                if user_id == 'demo':
                    continue
                if user_id in users and (users[user_id].email == 'demo@example.com' or users[user_id].email.startswith('demo') or '@example.com' in users[user_id].email):
                    continue
                all_platform_scans.append(scan)
        
        # Get ALL real leads from ALL clients - PLATFORM WIDE
        all_platform_leads = []
        for lead in leads_db.values():
            user_id = lead.get('user_id')
            if user_id == 'demo':
                continue
            if user_id in users and (users[user_id].email == 'demo@example.com' or users[user_id].email.startswith('demo') or '@example.com' in users[user_id].email):
                continue
            all_platform_leads.append(lead)
        
        # PLATFORM SUMMARY STATISTICS - Never individual client data
        platform_stats = {
            'total_clients': len(all_platform_clients),
            'total_scanners': len(all_platform_scanners),
            'total_scans': len(all_platform_scans),
            'total_leads': len(all_platform_leads),
            'monthly_revenue': sum(SUBSCRIPTION_TIERS.get(client.subscription_level, {}).get('price', 0) for client in all_platform_clients),
            'total_vulnerabilities': sum(scan.get('vulnerabilities_found', 0) for scan in all_platform_scans),
            'avg_security_score': sum(scan.get('risk_score', 0) for scan in all_platform_scans) // max(1, len(all_platform_scans)) if all_platform_scans else 0,
        }
        
        # Platform activity - aggregated from all clients
        platform_activity = []
        
        # Recent client registrations
        for client in sorted(all_platform_clients, key=lambda x: getattr(x, 'created_at', '2024-01-01'), reverse=True)[:5]:
            platform_activity.append({
                'type': 'New Client Registration',
                'description': f'New client: {getattr(client, "company_name", client.email)}',
                'time': getattr(client, 'created_at', '2024-01-01')[:16] if hasattr(client, 'created_at') else 'Unknown time',
                'icon': 'bi-person-plus',
                'color': 'text-success'
            })
        
        # Recent scanner deployments
        for scanner in sorted(all_platform_scanners, key=lambda x: x.get('created_at', ''), reverse=True)[:5]:
            owner = users.get(scanner.get('user_id'))
            platform_activity.append({
                'type': 'Scanner Deployed',
                'description': f'Scanner deployed for {getattr(owner, "company_name", "client") if owner else "unknown client"}',
                'time': scanner.get('created_at', '2024-01-01')[:16] if scanner.get('created_at') else 'Unknown time',
                'icon': 'bi-shield-check',
                'color': 'text-primary'
            })
        
        # Recent leads generated
        for lead in sorted(all_platform_leads, key=lambda x: x.get('date_generated', ''), reverse=True)[:5]:
            platform_activity.append({
                'type': 'Lead Generated',
                'description': f'{lead.get("lead_score", "").capitalize()} lead: {lead.get("company", "Unknown Company")}',
                'time': lead.get('date_generated', 'Unknown date'),
                'icon': 'bi-bullseye',
                'color': 'text-warning'
            })
        
        # Sort and limit activity
        platform_activity.sort(key=lambda x: x.get('time', ''), reverse=True)
        platform_activity = platform_activity[:10]
        
        # If no activity, show system ready message
        if not platform_activity:
            platform_activity = [{
                'type': 'System Status',
                'description': 'Platform ready - waiting for client activity',
                'time': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'icon': 'bi-check-circle',
                'color': 'text-muted'
            }]
        
        # Recent clients for display
        recent_clients = []
        for client in sorted(all_platform_clients, key=lambda x: getattr(x, 'created_at', '2024-01-01'), reverse=True)[:5]:
            recent_clients.append({
                'company_name': getattr(client, 'company_name', client.username),
                'scanner_name': 'Security Scanner',
                'subscription': client.subscription_level,
                'status': 'Active'
            })
        
        # Deployed scanners for display
        deployed_scanners = []
        for scanner in all_platform_scanners[:10]:
            owner = users.get(scanner.get('user_id'))
            if owner:
                deployed_scanners.append({
                    'id': scanner.get('id'),
                    'business_name': getattr(owner, 'company_name', owner.username),
                    'business_domain': getattr(owner, 'business_domain', 'unknown.com'),
                    'scanner_name': scanner.get('name', 'Security Scanner'),
                    'subdomain': scanner.get('subdomain', scanner.get('id')),
                    'deploy_status': scanner.get('status', 'deployed'),
                    'deploy_date': scanner.get('created_at', '2024-01-01')[:10],
                    'created_at': scanner.get('created_at', '2024-01-01')
                })
        
        return render_template('admin/platform-dashboard.html', 
                             user=current_user,
                             dashboard_stats=platform_stats,
                             recent_activity=platform_activity,
                             recent_clients=recent_clients,
                             deployed_scanners=deployed_scanners,
                             subscription_levels=SUBSCRIPTION_TIERS)
    
    return app