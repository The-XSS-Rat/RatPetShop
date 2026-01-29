"""Vulnerable routes for challenges - INTENTIONALLY INSECURE!"""
from flask import Blueprint, render_template, request
from app.models import db, User, Flag
import sqlite3
import os
import hashlib
import urllib.request

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
        file['content'] = f"{file['content']}\n\nFlag: {flag.value if flag else 'ERROR'}"
    
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
    if flag and flag.value:
        encrypted = flag.value.translate(str.maketrans(
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
    """VULNERABLE: Blind SQL injection."""
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
            
            flag = Flag.query.filter_by(name='SQL Injection - Hard').first()
            
            if result and result[0] > 0:
                return render_template('vulnerable/check_user.html', 
                                     exists=True, 
                                     username=username,
                                     flag=flag)
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
FLAG={flag.value if flag else 'ERROR'}
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
    """VULNERABLE: SSRF vulnerability."""
    url = request.args.get('url', '')
    
    flag = None
    content = None
    error = None
    
    if url:
        try:
            # Vulnerable - no URL validation!
            # WARNING: SSRF vulnerability - allows access to internal resources
            with urllib.request.urlopen(url, timeout=5) as response:
                content = response.read().decode('utf-8')[:1000]  # Limit output
                
                # If accessing localhost/internal, show flag
                if 'localhost' in url.lower() or '127.0.0.1' in url:
                    flag = Flag.query.filter_by(name='SSRF - Hard').first()
        
        except Exception as e:
            error = str(e)
    
    return render_template('vulnerable/ssrf.html', url=url, content=content, error=error, flag=flag)
