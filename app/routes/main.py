"""Main application routes."""
from flask import Blueprint, render_template, session
from app.models import Flag, Submission, User, db
from sqlalchemy import func

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Home page."""
    # Get stats
    total_flags = Flag.query.count()
    total_users = User.query.count()
    
    # Get user's progress if logged in
    user_progress = 0
    if 'user_id' in session:
        user_submissions = Submission.query.filter_by(
            user_id=session['user_id'],
            is_correct=True
        ).count()
        user_progress = user_submissions
    
    # Get recent successful submissions for activity feed
    recent_submissions = db.session.query(
        User.username,
        Flag.name,
        Submission.submitted_at,
        Submission.points_awarded
    ).join(User).join(Flag).filter(
        Submission.is_correct == True
    ).order_by(
        Submission.submitted_at.desc()
    ).limit(10).all()
    
    return render_template('index.html',
                         total_flags=total_flags,
                         total_users=total_users,
                         user_progress=user_progress,
                         recent_submissions=recent_submissions)


@main_bp.route('/about')
def about():
    """About page with OWASP Top 10 information."""
    owasp_top_10 = [
        {
            'id': 'A01',
            'name': 'Broken Access Control',
            'description': 'Access control enforces policy such that users cannot act outside of their intended permissions.',
            'example': 'Accessing admin panel without authorization, viewing other users\' data.'
        },
        {
            'id': 'A02',
            'name': 'Cryptographic Failures',
            'description': 'Failures related to cryptography which often leads to sensitive data exposure.',
            'example': 'Unencrypted data transmission, weak encryption algorithms.'
        },
        {
            'id': 'A03',
            'name': 'Injection',
            'description': 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.',
            'example': 'SQL injection, command injection, LDAP injection.'
        },
        {
            'id': 'A04',
            'name': 'Insecure Design',
            'description': 'Missing or ineffective control design, focusing on risks related to design and architectural flaws.',
            'example': 'Missing security requirements, flawed business logic.'
        },
        {
            'id': 'A05',
            'name': 'Security Misconfiguration',
            'description': 'Security misconfiguration is the most commonly seen issue.',
            'example': 'Default credentials, exposed configuration files, verbose error messages.'
        },
        {
            'id': 'A06',
            'name': 'Vulnerable and Outdated Components',
            'description': 'Using components with known vulnerabilities.',
            'example': 'Outdated libraries, unpatched software.'
        },
        {
            'id': 'A07',
            'name': 'Identification and Authentication Failures',
            'description': 'Failures in confirming user identity, authentication, and session management.',
            'example': 'Weak passwords, session fixation, credential stuffing.'
        },
        {
            'id': 'A08',
            'name': 'Software and Data Integrity Failures',
            'description': 'Code and infrastructure that does not protect against integrity violations.',
            'example': 'Insecure deserialization, unsigned updates.'
        },
        {
            'id': 'A09',
            'name': 'Security Logging and Monitoring Failures',
            'description': 'Insufficient logging and monitoring, coupled with missing or ineffective integration.',
            'example': 'Missing audit logs, inadequate response to incidents.'
        },
        {
            'id': 'A10',
            'name': 'Server-Side Request Forgery (SSRF)',
            'description': 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.',
            'example': 'Accessing internal services, port scanning.'
        }
    ]
    
    return render_template('about.html', owasp_top_10=owasp_top_10)


@main_bp.route('/help')
def help_page():
    """Help page with guides."""
    return render_template('help.html')
