"""Challenge routes."""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from app.models import db, Flag, Submission
from datetime import datetime

challenges_bp = Blueprint('challenges', __name__)


@challenges_bp.route('/')
def index():
    """List all challenges."""
    if 'user_id' not in session:
        flash('Please log in to view challenges.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Get challenges grouped by difficulty
    easy_flags = Flag.query.filter_by(difficulty='easy').all()
    medium_flags = Flag.query.filter_by(difficulty='medium').all()
    hard_flags = Flag.query.filter_by(difficulty='hard').all()
    
    # Get user's solved flags
    solved_flag_ids = [s.flag_id for s in Submission.query.filter_by(
        user_id=session['user_id'],
        is_correct=True
    ).all()]
    
    return render_template('challenges/index.html',
                         easy_flags=easy_flags,
                         medium_flags=medium_flags,
                         hard_flags=hard_flags,
                         solved_flag_ids=solved_flag_ids)


@challenges_bp.route('/<int:flag_id>')
def challenge_detail(flag_id):
    """View challenge details."""
    if 'user_id' not in session:
        flash('Please log in to view challenges.', 'warning')
        return redirect(url_for('auth.login'))
    
    flag = Flag.query.get_or_404(flag_id)
    
    # Check if user has already solved this
    solved = Submission.query.filter_by(
        user_id=session['user_id'],
        flag_id=flag_id,
        is_correct=True
    ).first() is not None
    
    return render_template('challenges/detail.html',
                         flag=flag,
                         solved=solved)


@challenges_bp.route('/submit', methods=['POST'])
def submit_flag():
    """Submit a flag for validation."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first.'}), 401
    
    flag_id = request.form.get('flag_id')
    submitted_value = request.form.get('flag_value', '').strip()
    
    if not flag_id or not submitted_value:
        return jsonify({'success': False, 'message': 'Missing required fields.'}), 400
    
    # Get the flag
    flag = Flag.query.get(flag_id)
    if not flag:
        return jsonify({'success': False, 'message': 'Invalid flag ID.'}), 404
    
    # Check if already solved
    existing_submission = Submission.query.filter_by(
        user_id=session['user_id'],
        flag_id=flag_id,
        is_correct=True
    ).first()
    
    if existing_submission:
        return jsonify({
            'success': False,
            'message': 'You have already solved this challenge!'
        }), 400
    
    # Validate flag
    is_correct = submitted_value == flag.secret.value if flag.secret else False
    points_awarded = flag.points if is_correct else 0
    
    # Create submission
    submission = Submission(
        user_id=session['user_id'],
        flag_id=flag_id,
        is_correct=is_correct,
        points_awarded=points_awarded,
        submitted_at=datetime.utcnow()
    )
    db.session.add(submission)
    db.session.commit()
    
    if is_correct:
        return jsonify({
            'success': True,
            'message': f'Correct! You earned {points_awarded} points!',
            'points': points_awarded
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Incorrect flag. Try again!'
        })


@challenges_bp.route('/vulnerability/<vuln_type>')
def vulnerability_guide(vuln_type):
    """Show guide for specific vulnerability type."""
    if 'user_id' not in session:
        flash('Please log in to view guides.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Get flags for this vulnerability type
    flags = Flag.query.filter_by(vulnerability_type=vuln_type).all()
    
    return render_template('challenges/vulnerability_guide.html',
                         vuln_type=vuln_type,
                         flags=flags)
