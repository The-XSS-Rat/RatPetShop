"""Database initialization and seeding utilities."""
from app.models import db, User, Flag, FlagSecret
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
            'hint': None
        },
        # A01:2021 – Broken Access Control (Hard)
        {
            'name': 'Broken Access Control - Hard',
            'value': f'FLAG{{access_control_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Exploit IDOR vulnerability to access sensitive files. Try <a href="/files/1">/files/1</a> and experiment with different file IDs.',
            'hint': None
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
            'hint': None
        },
        # A02:2021 – Cryptographic Failures (Hard)
        {
            'name': 'Cryptographic Failures - Hard',
            'value': f'FLAG{{crypto_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A02_Cryptographic_Failures',
            'description': 'Exploit weak password hashing to recover credentials. Visit <a href="/user-hashes">/user-hashes</a> to find exposed MD5 hashes.',
            'hint': None
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
            'hint': None
        },
        # A03:2021 – Injection (Hard)
        {
            'name': 'SQL Injection - Hard',
            'value': f'FLAG{{sqli_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A03_Injection',
            'description': 'Use advanced blind SQL injection techniques to extract sensitive information. Visit <a href="/check-user">/check-user</a> and exploit the blind SQLi vulnerability. No direct output or hints provided.',
            'hint': None
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
            'hint': None
        },
        
        # A10:2021 – Server-Side Request Forgery (Hard)
        {
            'name': 'SSRF - Hard',
            'value': f'FLAG{{ssrf_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A10_SSRF',
            'description': 'Exploit SSRF to access internal resources. Visit <a href="/fetch-url">/fetch-url</a> and try fetching internal URLs.',
            'hint': None
        },
        
        # A04:2021 – Insecure Design (Medium)
        {
            'name': 'Insecure Design - Medium',
            'value': f'FLAG{{insecure_design_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A04_Insecure_Design',
            'description': 'Exploit a business logic flaw in the password reset functionality. Visit <a href="/reset-password">/reset-password</a> and find the vulnerability.',
            'hint': None
        },
        
        # A06:2021 – Vulnerable and Outdated Components (Easy)
        {
            'name': 'Outdated Components - Easy',
            'value': f'FLAG{{outdated_components_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A06_Vulnerable_Components',
            'description': 'Find information about vulnerable dependencies. Visit <a href="/dependencies">/dependencies</a> to see the application\'s dependencies and identify vulnerable versions.',
            'hint': 'Look for outdated package versions with known vulnerabilities'
        },
        
        # A09:2021 – Security Logging and Monitoring Failures (Medium)
        {
            'name': 'Logging Failures - Medium',
            'value': f'FLAG{{logging_failures_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A09_Logging_Monitoring_Failures',
            'description': 'Exploit insufficient logging to hide your tracks. Visit <a href="/sensitive-action">/sensitive-action</a> and perform actions that are not properly logged.',
            'hint': None
        },
        
        # Additional XSS challenge (A03:2021 - Injection variant)
        {
            'name': 'XSS - Medium',
            'value': f'FLAG{{xss_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A03_Injection',
            'description': 'Find and exploit a Cross-Site Scripting (XSS) vulnerability. Visit <a href="/comment">/comment</a> and inject JavaScript to steal the flag from the page.',
            'hint': 'Try injecting script tags in the comment field'
        },
        
        # Additional Path Traversal challenge (A01:2021 variant)
        {
            'name': 'Path Traversal - Hard',
            'value': f'FLAG{{path_traversal_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Exploit a path traversal vulnerability to read sensitive files. Visit <a href="/download">/download</a> and try to access files outside the intended directory.',
            'hint': None
        },
        
        # NEW CHALLENGES - 30 additional challenges
        
        # Command Injection challenges
        {
            'name': 'Command Injection - Easy',
            'value': f'FLAG{{cmd_injection_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A03_Injection',
            'description': 'Execute system commands through user input. Visit <a href="/ping">/ping</a> and try injecting commands.',
            'hint': 'Try using ; or && to chain commands. Example: 127.0.0.1; ls'
        },
        {
            'name': 'Command Injection - Medium',
            'value': f'FLAG{{cmd_injection_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A03_Injection',
            'description': 'Bypass basic command injection filters. Visit <a href="/nslookup">/nslookup</a> and find a way around the filters.',
            'hint': None
        },
        {
            'name': 'Command Injection - Hard',
            'value': f'FLAG{{cmd_injection_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A03_Injection',
            'description': 'Advanced command injection with strict filtering. Visit <a href="/whois">/whois</a> and exploit the vulnerability.',
            'hint': None
        },
        
        # XXE challenges
        {
            'name': 'XXE - Easy',
            'value': f'FLAG{{xxe_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A05_Security_Misconfiguration',
            'description': 'Exploit XML External Entity vulnerability. Visit <a href="/xml-parser">/xml-parser</a> and inject malicious XML.',
            'hint': 'Use DOCTYPE to define an external entity that reads a file or makes a request'
        },
        {
            'name': 'XXE - Medium',
            'value': f'FLAG{{xxe_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A05_Security_Misconfiguration',
            'description': 'Advanced XXE with limited output. Visit <a href="/xml-validator">/xml-validator</a> to find the flag.',
            'hint': None
        },
        
        # Template Injection challenges
        {
            'name': 'Template Injection - Easy',
            'value': f'FLAG{{ssti_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A03_Injection',
            'description': 'Exploit Server-Side Template Injection. Visit <a href="/greet">/greet</a> and inject template code.',
            'hint': 'Try {{7*7}} to test for template injection'
        },
        {
            'name': 'Template Injection - Medium',
            'value': f'FLAG{{ssti_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A03_Injection',
            'description': 'Advanced SSTI to extract sensitive data. Visit <a href="/render-template">/render-template</a> and exploit it.',
            'hint': None
        },
        
        # Open Redirect challenges
        {
            'name': 'Open Redirect - Easy',
            'value': f'FLAG{{redirect_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Find and exploit an open redirect vulnerability. Visit <a href="/redirect">/redirect</a> and manipulate the redirect parameter.',
            'hint': 'Look for URL parameters like ?next= or ?url='
        },
        {
            'name': 'Open Redirect - Medium',
            'value': f'FLAG{{redirect_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Bypass open redirect filters. Visit <a href="/safe-redirect">/safe-redirect</a> and find a bypass.',
            'hint': None
        },
        
        # CSRF challenges
        {
            'name': 'CSRF - Easy',
            'value': f'FLAG{{csrf_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Exploit missing CSRF protection. Visit <a href="/change-email">/change-email</a> to find the vulnerability.',
            'hint': 'This endpoint accepts POST requests without CSRF tokens'
        },
        {
            'name': 'CSRF - Medium',
            'value': f'FLAG{{csrf_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Bypass weak CSRF protection. Visit <a href="/transfer-funds">/transfer-funds</a> and exploit it.',
            'hint': None
        },
        
        # NoSQL Injection challenges
        {
            'name': 'NoSQL Injection - Easy',
            'value': f'FLAG{{nosql_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A03_Injection',
            'description': 'Exploit NoSQL injection vulnerability. Visit <a href="/mongo-search">/mongo-search</a> and inject NoSQL operators.',
            'hint': 'Try using MongoDB operators like $ne, $gt in JSON'
        },
        {
            'name': 'NoSQL Injection - Medium',
            'value': f'FLAG{{nosql_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A03_Injection',
            'description': 'Advanced NoSQL injection. Visit <a href="/mongo-login">/mongo-login</a> to bypass authentication.',
            'hint': None
        },
        
        # Business Logic challenges
        {
            'name': 'Business Logic - Easy',
            'value': f'FLAG{{logic_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A04_Insecure_Design',
            'description': 'Exploit a business logic flaw in the coupon system. Visit <a href="/apply-coupon">/apply-coupon</a>.',
            'hint': 'Try applying the same coupon multiple times'
        },
        {
            'name': 'Business Logic - Medium',
            'value': f'FLAG{{logic_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A04_Insecure_Design',
            'description': 'Find a race condition in the order system. Visit <a href="/place-order">/place-order</a>.',
            'hint': None
        },
        {
            'name': 'Business Logic - Hard',
            'value': f'FLAG{{logic_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A04_Insecure_Design',
            'description': 'Exploit complex business logic in the refund system. Visit <a href="/request-refund">/request-refund</a>.',
            'hint': None
        },
        
        # Information Disclosure challenges
        {
            'name': 'Info Disclosure - Easy',
            'value': f'FLAG{{info_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A02_Cryptographic_Failures',
            'description': 'Find sensitive information in HTTP headers. Visit <a href="/api/info">/api/info</a> and examine the response.',
            'hint': 'Check HTTP response headers for sensitive data'
        },
        {
            'name': 'Info Disclosure - Medium',
            'value': f'FLAG{{info_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A02_Cryptographic_Failures',
            'description': 'Extract data from debug endpoints. Visit <a href="/debug/vars">/debug/vars</a> to find the flag.',
            'hint': None
        },
        {
            'name': 'Info Disclosure - Hard',
            'value': f'FLAG{{info_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A02_Cryptographic_Failures',
            'description': 'Find hidden API endpoints through enumeration. Start at <a href="/api/v1">/api/v1</a>.',
            'hint': None
        },
        
        # JWT challenges
        {
            'name': 'JWT - Easy',
            'value': f'FLAG{{jwt_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A07_Authentication_Failures',
            'description': 'Exploit weak JWT signature. Visit <a href="/jwt-login">/jwt-login</a> and manipulate the token.',
            'hint': 'Try changing the algorithm to "none" or modifying the payload'
        },
        {
            'name': 'JWT - Medium',
            'value': f'FLAG{{jwt_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A07_Authentication_Failures',
            'description': 'Crack a weak JWT secret. Visit <a href="/jwt-protected">/jwt-protected</a> with a valid token.',
            'hint': None
        },
        {
            'name': 'JWT - Hard',
            'value': f'FLAG{{jwt_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A07_Authentication_Failures',
            'description': 'Exploit JWT key confusion attack. Visit <a href="/jwt-admin">/jwt-admin</a>.',
            'hint': None
        },
        
        # File Upload challenges
        {
            'name': 'File Upload - Easy',
            'value': f'FLAG{{upload_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Bypass file type restrictions. Visit <a href="/upload">/upload</a> and upload a restricted file.',
            'hint': 'Try changing the file extension or MIME type'
        },
        {
            'name': 'File Upload - Medium',
            'value': f'FLAG{{upload_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A01_Broken_Access_Control',
            'description': 'Upload a file to overwrite existing files. Visit <a href="/upload-image">/upload-image</a>.',
            'hint': None
        },
        
        # Rate Limiting challenges
        {
            'name': 'Rate Limiting - Easy',
            'value': f'FLAG{{rate_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A07_Authentication_Failures',
            'description': 'Exploit missing rate limiting to brute force. Visit <a href="/otp-verify">/otp-verify</a>.',
            'hint': 'There is no rate limiting on OTP attempts'
        },
        {
            'name': 'Rate Limiting - Medium',
            'value': f'FLAG{{rate_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A07_Authentication_Failures',
            'description': 'Bypass client-side rate limiting. Visit <a href="/api-calls">/api-calls</a>.',
            'hint': None
        },
        
        # Deserialization challenges
        {
            'name': 'Deserialization - Medium',
            'value': f'FLAG{{deser_medium_{secrets.token_hex(8)}}}',
            'points': 200,
            'difficulty': 'medium',
            'vulnerability_type': 'A08_Software_Data_Integrity_Failures',
            'description': 'Exploit insecure deserialization. Visit <a href="/load-profile">/load-profile</a>.',
            'hint': None
        },
        {
            'name': 'Deserialization - Hard',
            'value': f'FLAG{{deser_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A08_Software_Data_Integrity_Failures',
            'description': 'Chain deserialization with code execution. Visit <a href="/import-data">/import-data</a>.',
            'hint': None
        },
        
        # Additional XSS variants
        {
            'name': 'XSS - Easy',
            'value': f'FLAG{{xss_easy_{secrets.token_hex(8)}}}',
            'points': 100,
            'difficulty': 'easy',
            'vulnerability_type': 'A03_Injection',
            'description': 'Find a reflected XSS vulnerability. Visit <a href="/search-products">/search-products</a> and inject JavaScript.',
            'hint': 'Try <script>alert(1)</script> in the search parameter'
        },
        {
            'name': 'DOM XSS - Hard',
            'value': f'FLAG{{dom_xss_hard_{secrets.token_hex(8)}}}',
            'points': 300,
            'difficulty': 'hard',
            'vulnerability_type': 'A03_Injection',
            'description': 'Exploit DOM-based XSS. Visit <a href="/client-render">/client-render</a> and find the vulnerability.',
            'hint': None
        }
    ]
    
    for flag_data in flags_data:
        flag_value = flag_data.pop('value')  # Remove value from flag_data
        
        existing = Flag.query.filter_by(name=flag_data['name']).first()
        if not existing:
            flag = Flag(**flag_data)
            db.session.add(flag)
            db.session.flush()  # Get the flag ID
            
            # Create the secret entry
            secret = FlagSecret(flag_id=flag.id, value=flag_value)
            db.session.add(secret)
        else:
            # Update existing flags with new descriptions
            existing.description = flag_data['description']
            existing.hint = flag_data['hint']
            
            # Update or create secret
            if not existing.secret:
                secret = FlagSecret(flag_id=existing.id, value=flag_value)
                db.session.add(secret)
            else:
                existing.secret.value = flag_value
    
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
        print(f"Test user already exists (username: testuser)")


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
