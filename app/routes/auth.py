"""Authentication routes."""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.models import db, User

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Validate input
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('auth/register.html')
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'error')
            return render_template('auth/register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        # Verify password
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('auth/login.html')


@auth_bp.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))


@auth_bp.route('/profile')
def profile():
    """User profile page."""
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'warning')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    
    # Get user's submissions
    from app.models import Submission, Flag
    submissions = db.session.query(
        Flag.name,
        Flag.difficulty,
        Flag.points,
        Submission.submitted_at,
        Submission.is_correct
    ).join(Flag).filter(
        Submission.user_id == user.id,
        Submission.is_correct == True
    ).order_by(
        Submission.submitted_at.desc()
    ).all()
    
    # Calculate total points
    total_points = sum(s.points for s in submissions)
    
    return render_template('auth/profile.html',
                         user=user,
                         submissions=submissions,
                         total_points=total_points)
