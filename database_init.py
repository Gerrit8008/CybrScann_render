"""
Database initialization helper for CybrScan
Ensures database is properly configured and connected
"""

import os
from flask_sqlalchemy import SQLAlchemy
from flask import Flask

def init_database(app):
    """Initialize database connection"""
    
    # Configure database URL
    if not app.config.get('SQLALCHEMY_DATABASE_URI'):
        # Check for environment variable first
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url and database_url.startswith('postgres://'):
            # Fix for SQLAlchemy compatibility
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        
        if not database_url:
            # Use SQLite as fallback
            database_url = 'sqlite:///cybrscan.db'
        
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    
    # Set other database config
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    print(f"📊 Database configured: {app.config['SQLALCHEMY_DATABASE_URI'][:30]}...")
    
    return app

def check_database_models():
    """Check if database models are available"""
    try:
        from models import db, User, Scanner, Scan, Lead
        print("✅ Database models loaded successfully")
        return True
    except Exception as e:
        print(f"⚠️ Database models not available: {e}")
        return False

def migrate_inmemory_to_database(app, users, scanners_db, leads_db, scans_db):
    """Migrate in-memory data to database if needed"""
    try:
        from models import db, User, Scanner, Scan, Lead
        
        with app.app_context():
            # Create tables if they don't exist
            db.create_all()
            
            # Count existing data
            existing_users = User.query.count()
            existing_scanners = Scanner.query.count()
            
            if existing_users == 0 and len(users) > 0:
                print("📊 Migrating in-memory users to database...")
                
                # Migrate users (skip demo)
                for user_id, user in users.items():
                    if user_id != 'demo' and not User.query.filter_by(email=user.email).first():
                        db_user = User(
                            email=user.email,
                            username=user.username,
                            password_hash=user.password_hash,
                            company_name=getattr(user, 'company_name', ''),
                            role=user.role,
                            subscription_level=user.subscription_level,
                            is_active=True
                        )
                        db.session.add(db_user)
                
                db.session.commit()
                print(f"✅ Migrated {User.query.count()} users to database")
            
            if existing_scanners == 0 and len(scanners_db) > 0:
                print("📊 Migrating in-memory scanners to database...")
                
                # Migrate scanners (skip demo)
                for scanner_id, scanner in scanners_db.items():
                    if scanner.get('user_id') != 'demo':
                        owner = User.query.filter_by(email=users[scanner['user_id']].email).first() if scanner['user_id'] in users else None
                        if owner:
                            db_scanner = Scanner(
                                name=scanner.get('name', 'Unknown Scanner'),
                                description=scanner.get('description', ''),
                                api_key=scanner.get('api_key'),
                                user_id=owner.id,
                                primary_color=scanner.get('primary_color', '#007bff'),
                                secondary_color=scanner.get('secondary_color', '#6c757d'),
                                button_color=scanner.get('button_color', '#007bff'),
                                is_active=True
                            )
                            db.session.add(db_scanner)
                
                db.session.commit()
                print(f"✅ Migrated {Scanner.query.count()} scanners to database")
            
            return True
            
    except Exception as e:
        print(f"⚠️ Could not migrate data to database: {e}")
        return False