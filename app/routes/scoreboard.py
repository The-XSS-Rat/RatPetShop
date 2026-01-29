"""Scoreboard routes."""
from flask import Blueprint, render_template, session
from app.models import db, User, Submission
from sqlalchemy import func

scoreboard_bp = Blueprint('scoreboard', __name__)


@scoreboard_bp.route('/')
def index():
    """Display the scoreboard."""
    # Get top users by total points
    scoreboard_data = db.session.query(
        User.id,
        User.username,
        func.sum(Submission.points_awarded).label('total_points'),
        func.count(Submission.id).label('flags_solved')
    ).join(
        Submission, User.id == Submission.user_id
    ).filter(
        Submission.is_correct == True
    ).group_by(
        User.id, User.username
    ).order_by(
        func.sum(Submission.points_awarded).desc()
    ).limit(100).all()
    
    # Get current user's rank if logged in
    user_rank = None
    user_points = None
    if 'user_id' in session:
        all_users = db.session.query(
            User.id,
            func.sum(Submission.points_awarded).label('total_points')
        ).join(
            Submission, User.id == Submission.user_id
        ).filter(
            Submission.is_correct == True
        ).group_by(
            User.id
        ).order_by(
            func.sum(Submission.points_awarded).desc()
        ).all()
        
        for idx, user_data in enumerate(all_users, start=1):
            if user_data.id == session['user_id']:
                user_rank = idx
                user_points = user_data.total_points
                break
    
    return render_template('scoreboard/index.html',
                         scoreboard_data=scoreboard_data,
                         user_rank=user_rank,
                         user_points=user_points)


@scoreboard_bp.route('/user/<int:user_id>')
def user_stats(user_id):
    """Display detailed stats for a specific user."""
    user = User.query.get_or_404(user_id)
    
    # Get user's submissions
    from app.models import Flag
    submissions = db.session.query(
        Flag.name,
        Flag.difficulty,
        Flag.vulnerability_type,
        Submission.points_awarded,
        Submission.submitted_at
    ).join(Flag).filter(
        Submission.user_id == user_id,
        Submission.is_correct == True
    ).order_by(
        Submission.submitted_at.desc()
    ).all()
    
    # Calculate stats
    total_points = sum(s.points_awarded for s in submissions)
    total_flags = len(submissions)
    
    # Count by difficulty
    easy_count = sum(1 for s in submissions if s.difficulty == 'easy')
    medium_count = sum(1 for s in submissions if s.difficulty == 'medium')
    hard_count = sum(1 for s in submissions if s.difficulty == 'hard')
    
    return render_template('scoreboard/user_stats.html',
                         user=user,
                         submissions=submissions,
                         total_points=total_points,
                         total_flags=total_flags,
                         easy_count=easy_count,
                         medium_count=medium_count,
                         hard_count=hard_count)
