"""Speedrun mode routes."""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from app.models import db, Flag, Submission, SpeedrunSession, User
from datetime import datetime
import secrets
import random

speedrun_bp = Blueprint('speedrun', __name__)


@speedrun_bp.route('/')
def index():
    """Speedrun mode home."""
    if 'user_id' not in session:
        flash('Please log in to access speedrun mode.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Get user's active speedrun session
    active_session = SpeedrunSession.query.filter_by(
        user_id=session['user_id'],
        is_active=True
    ).first()
    
    # Get user's completed speedrun sessions (exclude cancelled ones)
    completed_sessions = SpeedrunSession.query.filter(
        SpeedrunSession.user_id == session['user_id'],
        SpeedrunSession.is_active == False,
        SpeedrunSession.elapsed_time.isnot(None)
    ).order_by(SpeedrunSession.elapsed_time.asc()).all()
    
    return render_template('speedrun/index.html',
                         active_session=active_session,
                         completed_sessions=completed_sessions)


@speedrun_bp.route('/start', methods=['POST'])
def start_speedrun():
    """Start a new speedrun session."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first.'}), 401
    
    # Check if user already has an active session
    active_session = SpeedrunSession.query.filter_by(
        user_id=session['user_id'],
        is_active=True
    ).first()
    
    if active_session:
        # Cancel the existing active session
        active_session.is_active = False
        db.session.commit()
        
        # Clean up session data
        if f'speedrun_{active_session.tenant_id}_flags' in session:
            session.pop(f'speedrun_{active_session.tenant_id}_flags')
        if 'active_speedrun_tenant' in session:
            session.pop('active_speedrun_tenant')
    
    # Validate num_flags parameter
    num_flags = int(request.form.get('num_flags', 5))
    if num_flags < 1 or num_flags > 13:
        return jsonify({
            'success': False,
            'message': 'Number of flags must be between 1 and 13.'
        }), 400
    
    # Generate unique tenant ID for this speedrun
    tenant_id = f"speedrun_{secrets.token_hex(16)}"
    
    # Select random flags for this speedrun
    all_flags = Flag.query.all()
    if len(all_flags) < num_flags:
        return jsonify({
            'success': False,
            'message': 'Not enough flags available.'
        }), 400
    
    selected_flags = random.sample(all_flags, num_flags)
    
    # Create speedrun session
    speedrun_session = SpeedrunSession(
        user_id=session['user_id'],
        tenant_id=tenant_id,
        total_flags=len(selected_flags),
        flags_found=0,
        started_at=datetime.utcnow(),
        is_active=True
    )
    db.session.add(speedrun_session)
    db.session.commit()
    
    # Store selected flag IDs in session for this speedrun
    session[f'speedrun_{tenant_id}_flags'] = [f.id for f in selected_flags]
    session['active_speedrun_tenant'] = tenant_id
    
    return jsonify({
        'success': True,
        'message': 'Speedrun started!',
        'tenant_id': tenant_id,
        'redirect': url_for('speedrun.play', tenant_id=tenant_id)
    })


@speedrun_bp.route('/play/<tenant_id>')
def play(tenant_id):
    """Play speedrun session."""
    if 'user_id' not in session:
        flash('Please log in to access speedrun mode.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Get speedrun session
    speedrun_session = SpeedrunSession.query.filter_by(
        tenant_id=tenant_id,
        user_id=session['user_id']
    ).first_or_404()
    
    if not speedrun_session.is_active:
        flash('This speedrun session has ended.', 'info')
        return redirect(url_for('speedrun.index'))
    
    # Get flags for this speedrun
    flag_ids = session.get(f'speedrun_{tenant_id}_flags', [])
    flags = Flag.query.filter(Flag.id.in_(flag_ids)).all()
    
    # Get solved flags in this speedrun
    solved_flag_ids = [s.flag_id for s in Submission.query.filter_by(
        user_id=session['user_id'],
        tenant_id=tenant_id,
        is_correct=True
    ).all()]
    
    # Calculate elapsed time
    elapsed_seconds = int((datetime.utcnow() - speedrun_session.started_at).total_seconds())
    
    return render_template('speedrun/play.html',
                         speedrun_session=speedrun_session,
                         flags=flags,
                         solved_flag_ids=solved_flag_ids,
                         elapsed_seconds=elapsed_seconds,
                         tenant_id=tenant_id)


@speedrun_bp.route('/submit', methods=['POST'])
def submit_speedrun_flag():
    """Submit a flag in speedrun mode."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first.'}), 401
    
    flag_id = request.form.get('flag_id')
    submitted_value = request.form.get('flag_value', '').strip()
    tenant_id = request.form.get('tenant_id')
    
    if not all([flag_id, submitted_value, tenant_id]):
        return jsonify({'success': False, 'message': 'Missing required fields.'}), 400
    
    # Verify speedrun session
    speedrun_session = SpeedrunSession.query.filter_by(
        tenant_id=tenant_id,
        user_id=session['user_id'],
        is_active=True
    ).first()
    
    if not speedrun_session:
        return jsonify({'success': False, 'message': 'Invalid speedrun session.'}), 404
    
    # Get the flag
    flag = Flag.query.get(flag_id)
    if not flag:
        return jsonify({'success': False, 'message': 'Invalid flag ID.'}), 404
    
    # Check if already solved in this speedrun
    existing_submission = Submission.query.filter_by(
        user_id=session['user_id'],
        flag_id=flag_id,
        tenant_id=tenant_id,
        is_correct=True
    ).first()
    
    if existing_submission:
        return jsonify({
            'success': False,
            'message': 'You have already solved this flag in this speedrun!'
        }), 400
    
    # Validate flag
    is_correct = submitted_value == flag.value
    
    # Create submission
    submission = Submission(
        user_id=session['user_id'],
        flag_id=flag_id,
        is_correct=is_correct,
        points_awarded=0,  # No points in speedrun mode
        tenant_id=tenant_id,
        submitted_at=datetime.utcnow()
    )
    db.session.add(submission)
    
    if is_correct:
        # Update speedrun session
        speedrun_session.flags_found += 1
        
        # Check if all flags found
        if speedrun_session.flags_found >= speedrun_session.total_flags:
            speedrun_session.is_active = False
            speedrun_session.completed_at = datetime.utcnow()
            speedrun_session.elapsed_time = int(
                (speedrun_session.completed_at - speedrun_session.started_at).total_seconds()
            )
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Congratulations! You completed the speedrun!',
                'completed': True,
                'elapsed_time': speedrun_session.elapsed_time
            })
    
    db.session.commit()
    
    if is_correct:
        return jsonify({
            'success': True,
            'message': 'Correct!',
            'flags_found': speedrun_session.flags_found,
            'total_flags': speedrun_session.total_flags
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Incorrect flag. Try again!'
        })


@speedrun_bp.route('/cancel', methods=['POST'])
def cancel_speedrun():
    """Cancel an active speedrun session."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please log in first.'}), 401
    
    tenant_id = request.form.get('tenant_id')
    
    if not tenant_id:
        return jsonify({'success': False, 'message': 'Missing tenant ID.'}), 400
    
    # Get the active speedrun session
    speedrun_session = SpeedrunSession.query.filter_by(
        tenant_id=tenant_id,
        user_id=session['user_id'],
        is_active=True
    ).first()
    
    if not speedrun_session:
        return jsonify({'success': False, 'message': 'No active speedrun session found.'}), 404
    
    # Mark session as inactive (cancelled)
    speedrun_session.is_active = False
    db.session.commit()
    
    # Clean up session data
    if f'speedrun_{tenant_id}_flags' in session:
        session.pop(f'speedrun_{tenant_id}_flags')
    if 'active_speedrun_tenant' in session:
        session.pop('active_speedrun_tenant')
    
    return jsonify({
        'success': True,
        'message': 'Speedrun cancelled successfully.',
        'redirect': url_for('speedrun.index')
    })


@speedrun_bp.route('/leaderboard')
def leaderboard():
    """Show speedrun leaderboard."""
    # Get fastest completed speedruns
    leaderboard_data = db.session.query(
        User.username,
        SpeedrunSession.elapsed_time,
        SpeedrunSession.total_flags,
        SpeedrunSession.completed_at
    ).join(User).filter(
        SpeedrunSession.is_active == False,
        SpeedrunSession.elapsed_time.isnot(None)
    ).order_by(
        SpeedrunSession.elapsed_time.asc()
    ).limit(50).all()
    
    return render_template('speedrun/leaderboard.html',
                         leaderboard_data=leaderboard_data)
