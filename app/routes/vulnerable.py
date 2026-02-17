"""Vulnerable routes for challenges - INTENTIONALLY INSECURE!"""
from flask import Blueprint, render_template, request, session
from app.models import db, User, Flag
import sqlite3
import os
import hashlib
import urllib.request
import urllib.parse

vulnerable_bp = Blueprint('vulnerable', __name__)


def get_db_path():
    """Helper function to get the database path."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'instance', 'ratpetshop.db')


# Challenge 1: Broken Access Control - Easy (Admin Panel)
@vulnerable_bp.route('/admin')
def admin_panel():
    """VULNERABLE: Admin panel with no access control check."""
    # Intentionally vulnerable - no authentication check!
    
    # Get the flag for this challenge
    flag = Flag.query.filter_by(name='Broken Access Control - Easy').first()
    
    return render_template('vulnerable/admin.html', flag=flag)


# Challenge 2: Broken Access Control - Medium (IDOR - User Profile)
@vulnerable_bp.route('/profile/<int:user_id>')
def user_profile(user_id):
    """VULNERABLE: Access any user's profile without authorization check."""
    # Intentionally vulnerable - no authorization check!
    
    user = User.query.get_or_404(user_id)
    
    # Get the flag for this challenge (show to user 2)
    flag = None
    if user_id == 2:
        flag = Flag.query.filter_by(name='Broken Access Control - Medium').first()
    
    return render_template('vulnerable/profile.html', user=user, flag=flag)


# Challenge 3: Broken Access Control - Hard (IDOR - File Access)
@vulnerable_bp.route('/files/<int:file_id>')
def file_access(file_id):
    """VULNERABLE: Access any file without authorization check."""
    # Intentionally vulnerable - no authorization check!
    
    # Simulate files
    files = {
        1: {'name': 'public.txt', 'content': 'This is a public file.'},
        2: {'name': 'private.txt', 'content': 'This is a private file.'},
        3: {'name': 'secret.txt', 'content': 'This is a secret file with the flag!'},
    }
    
    file = files.get(file_id)
    if not file:
        return "File not found", 404
    
    # Get the flag for this challenge (show in file 3)
    flag = None
    if file_id == 3:
        flag = Flag.query.filter_by(name='Broken Access Control - Hard').first()
        file['content'] = f"{file['content']}\n\nFlag: {flag.secret.value if (flag and flag.secret) else 'ERROR'}"
    
    return render_template('vulnerable/file.html', file=file, file_id=file_id)


# Challenge 4: Cryptographic Failures - Easy (Plain text in source)
@vulnerable_bp.route('/secret-page')
def secret_page():
    """VULNERABLE: Contains flag in HTML comments/JS."""
    flag = Flag.query.filter_by(name='Cryptographic Failures - Easy').first()
    return render_template('vulnerable/secret_page.html', flag=flag)


# Challenge 5: Cryptographic Failures - Medium (ROT13)
@vulnerable_bp.route('/encrypted-data')
def encrypted_data():
    """VULNERABLE: Weakly encrypted data using ROT13."""
    flag = Flag.query.filter_by(name='Cryptographic Failures - Medium').first()
    
    # ROT13 "encryption"
    encrypted = "ERROR"
    if flag and flag.secret:
        encrypted = flag.secret.value.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        ))
    
    return render_template('vulnerable/encrypted.html', encrypted=encrypted)


# Challenge 6: Cryptographic Failures - Hard (Weak hashing)
@vulnerable_bp.route('/user-hashes')
def user_hashes():
    """VULNERABLE: Exposes MD5 password hashes."""
    # Create a test user with weak MD5 hash
    test_password = "admin123"
    md5_hash = hashlib.md5(test_password.encode()).hexdigest()
    
    flag = Flag.query.filter_by(name='Cryptographic Failures - Hard').first()
    
    users_with_hashes = [
        {'username': 'admin', 'hash': md5_hash, 'hint': 'Common password'},
        {'username': 'testuser', 'hash': 'e10adc3949ba59abbe56e057f20f883e', 'hint': 'Very common'},
    ]
    
    return render_template('vulnerable/hashes.html', users=users_with_hashes, flag=flag)


# Challenge 7: SQL Injection - Easy (Login Bypass)
@vulnerable_bp.route('/vuln-login', methods=['GET', 'POST'])
def vuln_login():
    """VULNERABLE: SQL Injection in login form."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # INTENTIONALLY VULNERABLE SQL QUERY
        # DO NOT USE THIS IN REAL APPLICATIONS!
        conn = sqlite3.connect(get_db_path())
        cursor = conn.cursor()
        
        # Vulnerable query - directly concatenating user input
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password}'"
        
        try:
            cursor.execute(query)
            result = cursor.fetchone()
            conn.close()
            
            # If any result is returned, consider it successful
            if result:
                flag = Flag.query.filter_by(name='SQL Injection - Easy').first()
                return render_template('vulnerable/vuln_login.html', 
                                     success=True, 
                                     flag=flag,
                                     message="Login successful!")
        except sqlite3.Error as e:
            conn.close()
            return render_template('vulnerable/vuln_login.html', 
                                 error=f"SQL Error: {str(e)}")
        
        return render_template('vulnerable/vuln_login.html', 
                             error="Invalid credentials!")
    
    return render_template('vulnerable/vuln_login.html')


# Challenge 8: SQL Injection - Medium (UNION-based)
@vulnerable_bp.route('/search')
def search():
    """VULNERABLE: UNION-based SQL injection in search."""
    query = request.args.get('q', '')
    
    if query:
        conn = sqlite3.connect(get_db_path())
        cursor = conn.cursor()
        
        # Vulnerable query
        sql = f"SELECT id, name, points FROM flags WHERE name LIKE '%{query}%'"
        
        try:
            cursor.execute(sql)
            results = cursor.fetchall()
            conn.close()
            
            flag = Flag.query.filter_by(name='SQL Injection - Medium').first()
            
            return render_template('vulnerable/search.html', 
                                 results=results, 
                                 query=query,
                                 flag=flag)
        except sqlite3.Error as e:
            conn.close()
            return render_template('vulnerable/search.html', 
                                 error=f"SQL Error: {str(e)}", 
                                 query=query)
    
    return render_template('vulnerable/search.html')


# Challenge 9: SQL Injection - Hard (Blind SQLi)
@vulnerable_bp.route('/check-user')
def check_user():
    """VULNERABLE: Blind SQL injection - advanced techniques required."""
    username = request.args.get('username', '')
    
    if username:
        conn = sqlite3.connect(get_db_path())
        cursor = conn.cursor()
        
        # Vulnerable query for blind SQLi
        sql = f"SELECT COUNT(*) FROM users WHERE username = '{username}'"
        
        try:
            cursor.execute(sql)
            result = cursor.fetchone()
            conn.close()
            
            # No flag display - must use OOB exfiltration
            if result and result[0] > 0:
                return render_template('vulnerable/check_user.html', 
                                     exists=True, 
                                     username=username)
            else:
                return render_template('vulnerable/check_user.html', 
                                     exists=False, 
                                     username=username)
        except sqlite3.Error as e:
            conn.close()
            return render_template('vulnerable/check_user.html', 
                                 error=f"SQL Error: {str(e)}")
    
    return render_template('vulnerable/check_user.html')


# Challenge 10: Security Misconfiguration - Easy (Exposed files)
@vulnerable_bp.route('/.env')
def exposed_env():
    """VULNERABLE: Exposed .env file."""
    flag = Flag.query.filter_by(name='Security Misconfiguration - Easy').first()
    
    env_content = f"""# Environment Configuration
# DO NOT EXPOSE THIS FILE!

SECRET_KEY=super-secret-key-12345
DATABASE_URL=sqlite:///ratpetshop.db
ADMIN_PASSWORD=admin123

# Flag for this challenge:
FLAG={flag.secret.value if (flag and flag.secret) else 'ERROR'}
"""
    
    return env_content, 200, {'Content-Type': 'text/plain'}


# Challenge 11: Authentication Failures - Easy (Weak password)
@vulnerable_bp.route('/weak-auth', methods=['GET', 'POST'])
def weak_auth():
    """VULNERABLE: Accepts weak passwords."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Weak password check - accepts common passwords
        weak_passwords = ['password', 'password123', 'admin', 'admin123', '123456']
        
        if password in weak_passwords:
            flag = Flag.query.filter_by(name='Authentication Failures - Easy').first()
            return render_template('vulnerable/weak_auth.html', 
                                 success=True, 
                                 flag=flag)
        
        return render_template('vulnerable/weak_auth.html', 
                             error="Invalid credentials!")
    
    return render_template('vulnerable/weak_auth.html')


# Challenge 12: Data Integrity - Medium (Session manipulation)
@vulnerable_bp.route('/session-check')
def session_check():
    """VULNERABLE: Can manipulate session data."""
    # Check if user has admin role in session (can be manipulated)
    is_admin = request.args.get('admin', 'false').lower() == 'true'
    
    flag = None
    if is_admin:
        flag = Flag.query.filter_by(name='Data Integrity - Medium').first()
    
    return render_template('vulnerable/session.html', is_admin=is_admin, flag=flag)


# Challenge 13: SSRF - Hard
@vulnerable_bp.route('/fetch-url')
def fetch_url():
    """VULNERABLE: SSRF vulnerability (but protected against file:// protocol)."""
    url = request.args.get('url', '')
    
    flag = None
    content = None
    error = None
    
    if url:
        try:
            # SECURITY FIX: Use proper URL parsing and whitelist only http/https protocols
            # This prevents reading sensitive files like /etc/shadow via file:// protocol
            # while still allowing the SSRF challenge to work with http/https protocols
            parsed_url = urllib.parse.urlparse(url)
            
            # Ensure a scheme is present (reject relative URLs and empty schemes)
            if not parsed_url.scheme:
                error = "Access denied: invalid URL format"
                return render_template('vulnerable/ssrf.html', url=url, content=content, error=error, flag=flag)
            
            # Only allow http and https schemes (case-insensitive)
            if parsed_url.scheme.lower() not in ['http', 'https']:
                error = "Access denied: only http:// and https:// protocols are allowed"
                return render_template('vulnerable/ssrf.html', url=url, content=content, error=error, flag=flag)
            
            # Ensure netloc (hostname) is present to prevent malformed URLs
            if not parsed_url.netloc:
                error = "Access denied: invalid URL format (missing hostname)"
                return render_template('vulnerable/ssrf.html', url=url, content=content, error=error, flag=flag)
            
            # Reconstruct URL from parsed components to prevent parsing inconsistencies
            validated_url = parsed_url.geturl()
            
            # NOTE: This endpoint is intentionally vulnerable to SSRF for educational purposes.
            # It allows access to localhost and private IPs (like 127.0.0.1, 2130706433, etc.)
            # to demonstrate SSRF attacks. In a real application, you would also need to:
            # - Block private IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            # - Block loopback addresses (127.0.0.0/8, ::1)
            # - Validate hostnames resolve to public IPs only
            # - Block cloud metadata endpoints (169.254.169.254)
            # However, these protections are omitted here to allow the CTF challenge to work.
            
            # Vulnerable - still allows SSRF to internal HTTP services for the CTF challenge!
            # WARNING: SSRF vulnerability - allows access to internal HTTP resources
            with urllib.request.urlopen(validated_url, timeout=5) as response:
                content = response.read().decode('utf-8')[:1000]  # Limit output
                
                # If accessing localhost/internal, show flag
                if 'localhost' in validated_url.lower() or '127.0.0.1' in validated_url:
                    flag = Flag.query.filter_by(name='SSRF - Hard').first()
        
        except Exception as e:
            error = str(e)
    
    return render_template('vulnerable/ssrf.html', url=url, content=content, error=error, flag=flag)


# Challenge 14: Insecure Design - Medium (Password Reset)
@vulnerable_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """VULNERABLE: Insecure password reset with predictable tokens."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        
        # Vulnerable - predictable reset token based on username
        if username:
            import hashlib
            # INSECURE: Token is just MD5 of username - predictable!
            reset_token = hashlib.md5(username.encode()).hexdigest()
            
            flag = None
            # If they figured out the token generation, show flag
            provided_token = request.form.get('token', '')
            if provided_token == reset_token:
                flag = Flag.query.filter_by(name='Insecure Design - Medium').first()
                return render_template('vulnerable/reset_password.html', 
                                     success=True, 
                                     flag=flag,
                                     token=reset_token)
            
            return render_template('vulnerable/reset_password.html', 
                                 token_generated=True,
                                 username=username,
                                 token=reset_token)
    
    return render_template('vulnerable/reset_password.html')


# Challenge 15: Vulnerable Components - Easy
@vulnerable_bp.route('/dependencies')
def dependencies():
    """VULNERABLE: Exposes information about outdated/vulnerable dependencies."""
    flag = Flag.query.filter_by(name='Outdated Components - Easy').first()
    
    # Simulate outdated dependencies with known vulnerabilities
    deps = [
        {'name': 'requests', 'version': '2.6.0', 'vulnerability': 'CVE-2018-18074'},
        {'name': 'flask', 'version': '0.12.0', 'vulnerability': 'CVE-2019-1010083'},
        {'name': 'werkzeug', 'version': '0.11.0', 'vulnerability': 'Multiple'},
    ]
    
    return render_template('vulnerable/dependencies.html', dependencies=deps, flag=flag)


# Challenge 16: Logging Failures - Medium
@vulnerable_bp.route('/sensitive-action', methods=['GET', 'POST'])
def sensitive_action():
    """VULNERABLE: Performs sensitive actions without proper logging."""
    flag = None
    
    if request.method == 'POST':
        action = request.form.get('action', '')
        
        # VULNERABLE: No logging of sensitive actions!
        # In a real app, this would be a security issue
        if action == 'delete_all_data':
            # Simulate a dangerous action with no logging
            flag = Flag.query.filter_by(name='Logging Failures - Medium').first()
            return render_template('vulnerable/logging.html', 
                                 action_performed=True,
                                 flag=flag)
    
    return render_template('vulnerable/logging.html')


# Challenge 17: XSS - Medium
@vulnerable_bp.route('/comment', methods=['GET', 'POST'])
def comment():
    """VULNERABLE: Stored XSS in comments."""
    from markupsafe import Markup
    
    flag = Flag.query.filter_by(name='XSS - Medium').first()
    
    # Store comments in session for demo (in real app would be DB)
    if 'comments' not in session:
        session['comments'] = []
    
    if request.method == 'POST':
        comment_text = request.form.get('comment', '')
        if comment_text:
            # VULNERABLE: No sanitization!
            session['comments'].append(comment_text)
            session.modified = True
    
    # Render comments without escaping - VULNERABLE!
    comments_html = []
    for comment in session.get('comments', []):
        comments_html.append(Markup(comment))
    
    return render_template('vulnerable/comment.html', 
                         comments=comments_html, 
                         flag=flag)


# Challenge 18: Path Traversal - Hard
@vulnerable_bp.route('/download')
def download():
    """VULNERABLE: Path traversal in file download."""
    filename = request.args.get('file', 'public.txt')
    
    flag = None
    error = None
    content = None
    
    try:
        # VULNERABLE: No path validation!
        # This allows path traversal like: ../../../etc/passwd
        file_path = os.path.join('data', filename)
        
        # For demo purposes, simulate file system
        if '../' in filename:
            # User is attempting path traversal
            flag = Flag.query.filter_by(name='Path Traversal - Hard').first()
            content = "This is a secret file accessed via path traversal!\n\nYou successfully exploited path traversal!"
        elif filename == 'public.txt':
            content = "This is a public file that anyone can access."
        elif filename == 'secret.txt':
            # Secret file should only be accessible via path traversal (e.g., ../data/secret.txt)
            content = "This file exists but you need to use path traversal to access it properly."
        else:
            error = "File not found"
    
    except Exception as e:
        error = str(e)
    
    return render_template('vulnerable/download.html', 
                         filename=filename, 
                         content=content, 
                         error=error, 
                         flag=flag)


# ============= NEW CHALLENGES (30 additional) =============

# Challenge 19-21: Command Injection
@vulnerable_bp.route('/ping', methods=['GET', 'POST'])
def ping():
    """VULNERABLE: Command injection in ping utility."""
    output = None
    error = None
    flag = None
    
    if request.method == 'POST':
        host = request.form.get('host', '')
        if host:
            try:
                import subprocess
                # VULNERABLE: Direct command execution with user input
                result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True, text=True, timeout=5)
                output = result.stdout + result.stderr
                
                # If command injection detected, show flag
                if ';' in host or '&&' in host or '|' in host:
                    flag = Flag.query.filter_by(name='Command Injection - Easy').first()
            except Exception as e:
                error = str(e)
    
    return render_template('vulnerable/ping.html', output=output, error=error, flag=flag)


@vulnerable_bp.route('/nslookup', methods=['GET', 'POST'])
def nslookup():
    """VULNERABLE: Command injection with basic filtering."""
    output = None
    error = None
    flag = None
    
    if request.method == 'POST':
        domain = request.form.get('domain', '')
        if domain:
            # Basic filter - can be bypassed
            if ';' in domain or '&&' in domain:
                error = "Invalid characters detected"
            else:
                try:
                    import subprocess
                    # Still vulnerable to other injection methods
                    result = subprocess.run(f'nslookup {domain}', shell=True, capture_output=True, text=True, timeout=5)
                    output = result.stdout + result.stderr
                    
                    if '|' in domain or '`' in domain or '$(' in domain:
                        flag = Flag.query.filter_by(name='Command Injection - Medium').first()
                except Exception as e:
                    error = str(e)
    
    return render_template('vulnerable/nslookup.html', output=output, error=error, flag=flag)


@vulnerable_bp.route('/whois', methods=['GET', 'POST'])
def whois():
    """VULNERABLE: Advanced command injection with strict filtering."""
    output = None
    error = None
    flag = None
    
    if request.method == 'POST':
        domain = request.form.get('domain', '')
        if domain:
            # Strict filter - harder to bypass
            blacklist = [';', '&&', '|', '`', '$', '>', '<', '\n', '\r']
            if any(char in domain for char in blacklist):
                error = "Invalid characters detected"
            else:
                try:
                    import subprocess
                    # Still vulnerable with creative payloads
                    result = subprocess.run(f'echo {domain}', shell=True, capture_output=True, text=True, timeout=5)
                    output = result.stdout + result.stderr
                    
                    # If they got creative enough, show flag
                    if len(output) > 100 or 'FLAG' in output:
                        flag = Flag.query.filter_by(name='Command Injection - Hard').first()
                except Exception as e:
                    error = str(e)
    
    return render_template('vulnerable/whois.html', output=output, error=error, flag=flag)


# Challenge 22-23: XXE
@vulnerable_bp.route('/xml-parser', methods=['GET', 'POST'])
def xml_parser():
    """VULNERABLE: XML External Entity injection."""
    result = None
    error = None
    flag = None
    
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        if xml_data:
            try:
                import xml.etree.ElementTree as ET
                # VULNERABLE: External entities enabled
                parser = ET.XMLParser()
                root = ET.fromstring(xml_data, parser=parser)
                result = f"Parsed XML: {root.tag}"
                
                # If XXE payload detected, show flag
                if 'ENTITY' in xml_data.upper():
                    flag = Flag.query.filter_by(name='XXE - Easy').first()
                    result += f"\n\nFlag: {flag.secret.value if (flag and flag.secret) else 'ERROR'}"
            except Exception as e:
                error = str(e)
    
    return render_template('vulnerable/xml_parser.html', result=result, error=error, flag=flag)


@vulnerable_bp.route('/xml-validator', methods=['GET', 'POST'])
def xml_validator():
    """VULNERABLE: XXE with limited output."""
    valid = None
    error = None
    flag = None
    result = None
    
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        if xml_data:
            try:
                import xml.etree.ElementTree as ET
                parser = ET.XMLParser()
                root = ET.fromstring(xml_data, parser=parser)
                valid = True
                result = "XML is valid"
                
                # Flag shown for advanced XXE
                if 'ENTITY' in xml_data.upper() and 'SYSTEM' in xml_data.upper():
                    flag = Flag.query.filter_by(name='XXE - Medium').first()
            except Exception as e:
                error = "Invalid XML"
                valid = False
                result = "XML validation failed"
    
    return render_template('vulnerable/xml_validator.html', valid=valid, error=error, flag=flag, result=result)


# Challenge 24-25: Template Injection
@vulnerable_bp.route('/greet', methods=['GET', 'POST'])
def greet():
    """VULNERABLE: Server-Side Template Injection."""
    from flask import render_template_string
    
    output = None
    error = None
    flag = None
    
    if request.method == 'POST':
        name = request.form.get('name', '')
        if name:
            try:
                # VULNERABLE: Template injection
                template = f"Hello {name}!"
                output = render_template_string(template)
                
                # If template injection detected
                if '{{' in name or '{%' in name:
                    flag = Flag.query.filter_by(name='Template Injection - Easy').first()
            except Exception as e:
                error = str(e)
    
    return render_template('vulnerable/greet.html', output=output, error=error, flag=flag)


@vulnerable_bp.route('/render-template', methods=['GET', 'POST'])
def render_template_vuln():
    """VULNERABLE: Advanced SSTI."""
    from flask import render_template_string
    
    output = None
    error = None
    flag = None
    
    if request.method == 'POST':
        template = request.form.get('template', '')
        if template:
            try:
                # VULNERABLE: Direct template rendering
                output = render_template_string(template)
                
                # If advanced SSTI used
                if 'config' in template or '__' in template:
                    flag = Flag.query.filter_by(name='Template Injection - Medium').first()
            except Exception as e:
                error = str(e)
    
    return render_template('vulnerable/render_template.html', output=output, error=error, flag=flag)


# Challenge 26-27: Open Redirect
@vulnerable_bp.route('/redirect')
def open_redirect():
    """VULNERABLE: Open redirect vulnerability."""
    url = request.args.get('url', '')
    
    if url:
        # VULNERABLE: No validation
        flag = Flag.query.filter_by(name='Open Redirect - Easy').first()
        return render_template('vulnerable/redirect.html', url=url, flag=flag)
    
    return render_template('vulnerable/redirect.html', url=None, flag=None)


@vulnerable_bp.route('/safe-redirect')
def safe_redirect():
    """VULNERABLE: Open redirect with weak filtering."""
    url = request.args.get('url', '')
    flag = None
    
    if url:
        # Weak filter - can be bypassed
        if not url.startswith('http://'):
            # Bypass: use https:// or // or other protocols
            flag = Flag.query.filter_by(name='Open Redirect - Medium').first()
        
        return render_template('vulnerable/safe_redirect.html', url=url, flag=flag)
    
    return render_template('vulnerable/safe_redirect.html', url=None, flag=None)


# Challenge 28-29: CSRF
@vulnerable_bp.route('/change-email', methods=['GET', 'POST'])
def change_email():
    """VULNERABLE: Missing CSRF protection."""
    success = None
    flag = None
    current_email = "user@example.com"
    
    if request.method == 'POST':
        new_email = request.form.get('email', '')
        if new_email:
            success = True
            flag = Flag.query.filter_by(name='CSRF - Easy').first()
    
    return render_template('vulnerable/change_email.html', success=success, flag=flag, current_email=current_email)


@vulnerable_bp.route('/transfer-funds', methods=['GET', 'POST'])
def transfer_funds():
    """VULNERABLE: Weak CSRF protection."""
    success = None
    flag = None
    balance = 1000
    
    if request.method == 'POST':
        # Weak CSRF check
        token = request.form.get('csrf_token', '')
        if token == 'weak_token':  # Predictable token
            amount = request.form.get('amount', '')
            to_user = request.form.get('to_user', '')
            success = True
            flag = Flag.query.filter_by(name='CSRF - Medium').first()
    
    return render_template('vulnerable/transfer_funds.html', success=success, flag=flag, token='weak_token', balance=balance)


# Challenge 30-31: NoSQL Injection (simulated)
@vulnerable_bp.route('/mongo-search', methods=['GET', 'POST'])
def mongo_search():
    """VULNERABLE: NoSQL injection simulation."""
    import json
    
    results = None
    error = None
    flag = None
    
    if request.method == 'POST':
        query = request.form.get('query', '')
        if query:
            try:
                # Simulate NoSQL injection
                query_obj = json.loads(query)
                if '$ne' in str(query_obj) or '$gt' in str(query_obj):
                    flag = Flag.query.filter_by(name='NoSQL Injection - Easy').first()
                    results = "Query executed successfully (injection detected)"
            except Exception as e:
                error = str(e)
    
    return render_template('vulnerable/mongo_search.html', results=results, error=error, flag=flag)


@vulnerable_bp.route('/mongo-login', methods=['GET', 'POST'])
def mongo_login():
    """VULNERABLE: NoSQL injection in authentication."""
    import json
    
    success = None
    error = None
    flag = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        try:
            # Simulate NoSQL authentication bypass
            if '{' in username or '{' in password:
                user_obj = json.loads(username) if '{' in username else username
                pass_obj = json.loads(password) if '{' in password else password
                
                if isinstance(user_obj, dict) or isinstance(pass_obj, dict):
                    success = True
                    flag = Flag.query.filter_by(name='NoSQL Injection - Medium').first()
        except Exception as e:
            error = str(e)
    
    return render_template('vulnerable/mongo_login.html', success=success, error=error, flag=flag)


# Challenge 32-34: Business Logic
@vulnerable_bp.route('/apply-coupon', methods=['GET', 'POST'])
def apply_coupon():
    """VULNERABLE: Coupon can be applied multiple times."""
    discount = 0
    flag = None
    
    if request.method == 'POST':
        coupon = request.form.get('coupon', '')
        times = int(request.form.get('times', 1))
        
        if coupon == 'SAVE10':
            # VULNERABLE: No check for multiple applications
            discount = 10 * times
            if times > 1:
                flag = Flag.query.filter_by(name='Business Logic - Easy').first()
    
    return render_template('vulnerable/apply_coupon.html', discount=discount, flag=flag)


@vulnerable_bp.route('/place-order', methods=['GET', 'POST'])
def place_order():
    """VULNERABLE: Race condition in inventory check."""
    success = None
    flag = None
    order = None
    
    if request.method == 'POST':
        item_id = request.form.get('item_id', '')
        quantity = int(request.form.get('quantity', 1))
        
        # Simulate race condition vulnerability
        if quantity > 10:  # Impossible order size
            success = True
            flag = Flag.query.filter_by(name='Business Logic - Medium').first()
            order = {'id': '12345', 'quantity': quantity, 'total': quantity * 19.99}
    
    return render_template('vulnerable/place_order.html', success=success, flag=flag, order=order)


@vulnerable_bp.route('/request-refund', methods=['GET', 'POST'])
def request_refund():
    """VULNERABLE: Multiple refunds for same order."""
    success = None
    flag = None
    refund = None
    
    if request.method == 'POST':
        order_id = request.form.get('order_id', '')
        refund_count = int(request.form.get('refund_count', 1))
        
        # VULNERABLE: Can request multiple refunds
        if refund_count > 1:
            success = True
            flag = Flag.query.filter_by(name='Business Logic - Hard').first()
            refund = {'amount': 29.99 * refund_count, 'count': refund_count}
    
    return render_template('vulnerable/request_refund.html', success=success, flag=flag, refund=refund)


# Challenge 35-37: Information Disclosure
@vulnerable_bp.route('/api/info')
def api_info():
    """VULNERABLE: Sensitive info in headers."""
    flag = Flag.query.filter_by(name='Info Disclosure - Easy').first()
    
    response = {
        'status': 'ok',
        'version': '1.0.0'
    }
    
    from flask import jsonify, make_response
    resp = make_response(jsonify(response))
    resp.headers['X-Debug-Token'] = 'debug-123456'
    resp.headers['X-Flag'] = flag.secret.value if (flag and flag.secret) else 'ERROR'
    return resp


@vulnerable_bp.route('/debug/vars')
def debug_vars():
    """VULNERABLE: Debug endpoint exposing variables."""
    flag = Flag.query.filter_by(name='Info Disclosure - Medium').first()
    
    config = {
        'app_mode': 'debug',
        'database': 'ratpetshop.db',
        'secret_key': 'dev-secret-key-change-in-production'
    }
    
    env_vars = {
        'PATH': '/usr/bin:/bin',
        'FLAG': flag.secret.value if (flag and flag.secret) else 'ERROR'
    }
    
    request_info = {
        'method': 'GET',
        'path': '/debug/vars',
        'user_agent': 'Mozilla/5.0'
    }
    
    debug_info = config  # For backwards compatibility
    
    return render_template('vulnerable/debug_vars.html', 
                         debug_info=debug_info,
                         config=config, 
                         env_vars=env_vars, 
                         request_info=request_info)


@vulnerable_bp.route('/api/v1')
def api_v1():
    """VULNERABLE: API enumeration starting point."""
    from flask import jsonify
    
    endpoints = [
        '/api/v1/users',
        '/api/v1/admin',
        '/api/v1/secret',
        '/api/v1/config'
    ]
    
    return jsonify({'endpoints': endpoints})


@vulnerable_bp.route('/api/v1/secret')
def api_secret():
    """VULNERABLE: Hidden endpoint with flag."""
    flag = Flag.query.filter_by(name='Info Disclosure - Hard').first()
    from flask import jsonify
    
    return jsonify({
        'flag': flag.secret.value if (flag and flag.secret) else 'ERROR',
        'message': 'You found the secret endpoint!'
    })


# Challenge 38-40: JWT
@vulnerable_bp.route('/jwt-login', methods=['GET', 'POST'])
def jwt_login():
    """VULNERABLE: Weak JWT implementation."""
    token = None
    flag = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        
        # Create weak JWT (base64 encoded, no signature)
        import base64
        import json
        
        payload = {'username': username, 'admin': False}
        token = base64.b64encode(json.dumps(payload).encode()).decode()
        
        # Check if token was manipulated
        if request.form.get('token'):
            try:
                decoded = json.loads(base64.b64decode(request.form.get('token')))
                if decoded.get('admin') == True:
                    flag = Flag.query.filter_by(name='JWT - Easy').first()
            except:
                pass
    
    return render_template('vulnerable/jwt_login.html', token=token, flag=flag)


@vulnerable_bp.route('/jwt-protected', methods=['GET', 'POST'])
def jwt_protected():
    """VULNERABLE: JWT with weak secret."""
    flag = None
    error = None
    data = None
    
    if request.method == 'POST':
        token = request.form.get('token', '')
        
        # Weak secret: "secret"
        try:
            import jwt as pyjwt
            decoded = pyjwt.decode(token, 'secret', algorithms=['HS256'])
            flag = Flag.query.filter_by(name='JWT - Medium').first()
            data = decoded
        except:
            error = "Invalid token"
    
    return render_template('vulnerable/jwt_protected.html', flag=flag, error=error, data=data)


@vulnerable_bp.route('/jwt-admin', methods=['GET', 'POST'])
def jwt_admin():
    """VULNERABLE: JWT key confusion."""
    flag = None
    error = None
    admin_data = None
    
    if request.method == 'POST':
        token = request.form.get('token', '')
        
        # Vulnerable to algorithm confusion attack
        try:
            import jwt as pyjwt
            # Accept multiple algorithms
            decoded = pyjwt.decode(token, options={"verify_signature": False})
            if decoded.get('admin') == True:
                flag = Flag.query.filter_by(name='JWT - Hard').first()
                admin_data = {'username': decoded.get('username', 'admin'), 'role': 'administrator'}
        except Exception as e:
            error = str(e)
    
    return render_template('vulnerable/jwt_admin.html', flag=flag, error=error, admin_data=admin_data)


# Challenge 41-42: File Upload
@vulnerable_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    """VULNERABLE: File upload with weak validation."""
    success = None
    flag = None
    filename = None
    filepath = None
    
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = file.filename
            # Weak extension check
            if not filename.endswith('.txt'):
                success = True
                flag = Flag.query.filter_by(name='File Upload - Easy').first()
                filepath = f'/uploads/{filename}'
    
    return render_template('vulnerable/upload.html', success=success, flag=flag, filename=filename, filepath=filepath)


@vulnerable_bp.route('/upload-image', methods=['GET', 'POST'])
def upload_image():
    """VULNERABLE: Path traversal in upload."""
    success = None
    flag = None
    filename = None
    filepath = None
    url = None
    
    if request.method == 'POST':
        file = request.files.get('file')
        filename = request.form.get('filename', '')
        
        if file and filename:
            # VULNERABLE: No path sanitization
            if '../' in filename:
                success = True
                flag = Flag.query.filter_by(name='File Upload - Medium').first()
                filepath = f'/uploads/{filename}'
                url = f'/view/{filename}'
    
    return render_template('vulnerable/upload_image.html', success=success, flag=flag, filename=filename, filepath=filepath, url=url)


# Challenge 43-44: Rate Limiting
@vulnerable_bp.route('/otp-verify', methods=['GET', 'POST'])
def otp_verify():
    """VULNERABLE: No rate limiting on OTP."""
    success = None
    flag = None
    attempts = 0
    
    if request.method == 'POST':
        otp = request.form.get('otp', '')
        attempts = int(request.form.get('attempts', 0)) + 1
        
        # Correct OTP is 1234
        if otp == '1234':
            success = True
            flag = Flag.query.filter_by(name='Rate Limiting - Easy').first()
    
    return render_template('vulnerable/otp_verify.html', success=success, flag=flag, attempts=attempts)


@vulnerable_bp.route('/api-calls', methods=['GET', 'POST'])
def api_calls():
    """VULNERABLE: Client-side rate limiting."""
    success = None
    flag = None
    result = None
    remaining = 10
    
    if request.method == 'POST':
        # Client-side check is in JS - easily bypassed
        calls = int(request.form.get('calls', 0))
        remaining = max(0, 10 - calls)
        if calls > 10:
            success = True
            flag = Flag.query.filter_by(name='Rate Limiting - Medium').first()
            result = f'Successfully made {calls} API calls!'
    
    return render_template('vulnerable/api_calls.html', success=success, flag=flag, result=result, remaining=remaining)


# Challenge 45-46: Deserialization
@vulnerable_bp.route('/load-profile', methods=['GET', 'POST'])
def load_profile():
    """VULNERABLE: Insecure deserialization."""
    import pickle
    import base64
    
    result = None
    error = None
    flag = None
    
    if request.method == 'POST':
        data = request.form.get('data', '')
        if data:
            try:
                # VULNERABLE: Unpickle user data
                decoded = base64.b64decode(data)
                obj = pickle.loads(decoded)
                result = str(obj)
                flag = Flag.query.filter_by(name='Deserialization - Medium').first()
            except Exception as e:
                error = str(e)
    
    return render_template('vulnerable/load_profile.html', result=result, error=error, flag=flag)


@vulnerable_bp.route('/import-data', methods=['GET', 'POST'])
def import_data():
    """VULNERABLE: Advanced deserialization."""
    import pickle
    import base64
    
    result = None
    error = None
    flag = None
    
    if request.method == 'POST':
        data = request.form.get('data', '')
        if data:
            try:
                # VULNERABLE: Unpickle without validation
                decoded = base64.b64decode(data)
                obj = pickle.loads(decoded)
                result = "Data imported successfully"
                flag = Flag.query.filter_by(name='Deserialization - Hard').first()
            except Exception as e:
                error = str(e)
    
    return render_template('vulnerable/import_data.html', result=result, error=error, flag=flag)


# Challenge 47: XSS - Easy (Reflected)
@vulnerable_bp.route('/search-products')
def search_products():
    """VULNERABLE: Reflected XSS."""
    from markupsafe import Markup
    
    query = request.args.get('q', '')
    flag = Flag.query.filter_by(name='XSS - Easy').first()
    
    # VULNERABLE: No escaping
    search_result = Markup(f"You searched for: {query}")
    
    # Simulate product results
    products = [
        {'name': 'Rat Food Premium', 'price': 19.99},
        {'name': 'Rat Cage Deluxe', 'price': 89.99},
        {'name': 'Rat Toy Set', 'price': 14.99}
    ]
    
    return render_template('vulnerable/search_products.html', 
                         search_result=search_result, 
                         query=query,
                         flag=flag,
                         products=products)


# Challenge 48: DOM XSS - Hard
@vulnerable_bp.route('/client-render')
def client_render():
    """VULNERABLE: DOM-based XSS."""
    flag = Flag.query.filter_by(name='DOM XSS - Hard').first()
    return render_template('vulnerable/client_render.html', flag=flag)
