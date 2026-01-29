"""Database initialization and seeding utilities."""
from app.models import db, User, Flag
import secrets


def init_db(app):
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")


def seed_flags():
    """Seed the database with OWASP Top 10 flags."""
    flags_data = [
        # A01:2021 – Broken Access Control (Easy)
        {
            'name': 'Broken Access Control - Easy',
            'value': f'FLAG{{access_control_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Access the admin panel without proper authorization. Visit <a href="/admin">/admin</a> directly to find the flag.',
            'hint': 'Sometimes authentication checks are missing on certain routes. Try navigating to /admin'
        },
        # A01:2021 – Broken Access Control (Medium)
        {
            'name': 'Broken Access Control - Medium',
            'value': f'FLAG{{access_control_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Access another user\'s profile data by manipulating user IDs. Try <a href="/profile/2">/profile/2</a> to access the test user\'s profile.',
            'hint': 'Try changing the user_id parameter in the URL. The test user has ID 2.'
        },
        # A01:2021 – Broken Access Control (Hard)
        {
            'name': 'Broken Access Control - Hard',
            'value': f'FLAG{{access_control_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Exploit IDOR vulnerability to access sensitive files. Try <a href="/files/1">/files/1</a> and experiment with different file IDs.',
            'hint': 'File IDs might be predictable. Try accessing /files/1, /files/2, /files/3 to find the secret file.'
        },
        
        # A02:2021 – Cryptographic Failures (Easy)
        {
            'name': 'Cryptographic Failures - Easy',
            'value': f'FLAG{{crypto_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A02_Cryptographic_Failures',
            'description': 'Find sensitive data stored in plain text in the page source. Visit <a href="/secret-page">/secret-page</a> and view the HTML source.',
            'hint': 'Check HTML comments and JavaScript variables. Use View Page Source or Developer Tools.'
        },
        # A02:2021 – Cryptographic Failures (Medium)
        {
            'name': 'Cryptographic Failures - Medium',
            'value': f'FLAG{{crypto_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A02_Cryptographic_Failures',
            'description': 'Decrypt weakly encrypted data using basic cryptanalysis. Visit <a href="/encrypted-data">/encrypted-data</a> to find encrypted data.',
            'hint': 'ROT13 is not encryption! Use an online ROT13 decoder or Python.'
        },
        # A02:2021 – Cryptographic Failures (Hard)
        {
            'name': 'Cryptographic Failures - Hard',
            'value': f'FLAG{{crypto_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A02_Cryptographic_Failures',
            'description': 'Exploit weak password hashing to recover credentials. Visit <a href="/user-hashes">/user-hashes</a> to find exposed MD5 hashes.',
            'hint': 'MD5 is no longer secure for password hashing. Try using online hash crackers like CrackStation.'
        },
        
        # A03:2021 – Injection (Easy)
        {
            'name': 'SQL Injection - Easy',
            'value': f'FLAG{{sqli_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A03_Injection',
            'description': 'Bypass login using SQL injection. Visit <a href="/vuln-login">/vuln-login</a> and try the classic OR 1=1 technique.',
            'hint': 'Username: admin\' OR \'1\'=\'1 -- Leave password blank or any value'
        },
        # A03:2021 – Injection (Medium)
        {
            'name': 'SQL Injection - Medium',
            'value': f'FLAG{{sqli_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A03_Injection',
            'description': 'Extract data from the database using UNION-based SQL injection. Visit <a href="/search">/search</a> and use UNION SELECT.',
            'hint': 'Use UNION SELECT to combine results from different tables. Try: \' UNION SELECT id, name, value FROM flags--'
        },
        # A03:2021 – Injection (Hard)
        {
            'name': 'SQL Injection - Hard',
            'value': f'FLAG{{sqli_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A03_Injection',
            'description': 'Use blind SQL injection to extract sensitive information. Visit <a href="/check-user">/check-user</a> and exploit the boolean-based blind SQLi.',
            'hint': 'Time-based or boolean-based blind SQL injection techniques. Try: admin\' AND SUBSTR((SELECT value FROM flags WHERE id=9),1,1)=\'F\'--'
        },
        
        # A05:2021 – Security Misconfiguration (Easy)
        {
            'name': 'Security Misconfiguration - Easy',
            'value': f'FLAG{{misconfig_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A05_Security_Misconfiguration',
            'description': 'Find exposed configuration files. Try accessing <a href="/.env">/.env</a> to find exposed secrets.',
            'hint': 'Check for .git, .env, or backup files. Common paths: /.env, /.git/config, /config.php.bak'
        },
        
        # A07:2021 – Authentication Failures (Easy)
        {
            'name': 'Authentication Failures - Easy',
            'value': f'FLAG{{auth_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A07_Authentication_Failures',
            'description': 'Exploit weak password policy to gain access. Visit <a href="/weak-auth">/weak-auth</a> and try common passwords.',
            'hint': 'Try common passwords like "password123" or "admin" at /weak-auth'
        },
        
        # A08:2021 – Software and Data Integrity Failures (Medium)
        {
            'name': 'Data Integrity - Medium',
            'value': f'FLAG{{integrity_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A08_Software_Data_Integrity_Failures',
            'description': 'Manipulate serialized data to gain unauthorized access. Visit <a href="/session-check">/session-check</a> and manipulate URL parameters.',
            'hint': 'Check cookies and session data. Try adding ?admin=true to the URL.'
        },
        
        # A10:2021 – Server-Side Request Forgery (Hard)
        {
            'name': 'SSRF - Hard',
            'value': f'FLAG{{ssrf_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A10_SSRF',
            'description': 'Exploit SSRF to access internal resources. Visit <a href="/fetch-url">/fetch-url</a> and try fetching internal URLs.',
            'hint': 'Try accessing localhost or internal IP addresses through the URL parameter. Example: http://localhost:5000/admin'
        }
    ]
    
    for flag_data in flags_data:
        existing = Flag.query.filter_by(name=flag_data['name']).first()
        if not existing:
            flag = Flag(**flag_data)
            db.session.add(flag)
        else:
            # Update existing flags with new descriptions
            existing.description = flag_data['description']
            existing.hint = flag_data['hint']
    
    db.session.commit()
    print(f"Seeded {len(flags_data)} flags successfully!")


def seed_test_user():
    """Create a test user for IDOR challenges."""
    test_user = User.query.filter_by(username='testuser').first()
    if not test_user:
        test_user = User(
            username='testuser',
            email='test@example.com',
            is_admin=False
        )
        test_user.set_password('testpass123')
        db.session.add(test_user)
        db.session.commit()
        print("Test user created (username: testuser, password: testpass123)")
    else:
        print(f"Test user already exists")


def seed_admin_user():
    """Create an admin user if one doesn't exist."""
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@ratpetshop.local',
            is_admin=True
        )
        admin.set_password('admin123')  # Weak password for demo
        db.session.add(admin)
        db.session.commit()
        print("Admin user created (username: admin, password: admin123)")


def seed_database(app):
    """Seed the database with initial data."""
    with app.app_context():
        seed_admin_user()
        seed_test_user()
        seed_flags()
        print("Database seeded successfully!")
