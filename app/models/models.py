"""Database models for the RatPetShop OWASP Lab."""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    """User model for authentication and tracking."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    tenant_id = db.Column(db.String(50), nullable=True)  # For speedrun mode
    
    # Relationships
    submissions = db.relationship('Submission', backref='user', lazy=True, cascade='all, delete-orphan')
    speedrun_sessions = db.relationship('SpeedrunSession', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash."""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Flag(db.Model):
    """Flag model for challenges."""
    __tablename__ = 'flags'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    value = db.Column(db.String(255), nullable=False, unique=True)
    points = db.Column(db.Integer, default=100)
    difficulty = db.Column(db.String(20), nullable=False)  # easy, medium, hard
    vulnerability_type = db.Column(db.String(50), nullable=False)  # OWASP Top 10 type
    description = db.Column(db.Text, nullable=False)
    hint = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    submissions = db.relationship('Submission', backref='flag', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Flag {self.name} ({self.difficulty})>'


class Submission(db.Model):
    """Submission model to track user flag submissions."""
    __tablename__ = 'submissions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    flag_id = db.Column(db.Integer, db.ForeignKey('flags.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_correct = db.Column(db.Boolean, default=False)
    points_awarded = db.Column(db.Integer, default=0)
    tenant_id = db.Column(db.String(50), nullable=True)  # For speedrun mode
    
    def __repr__(self):
        return f'<Submission user={self.user_id} flag={self.flag_id}>'


class SpeedrunSession(db.Model):
    """Speedrun session model for tracking speedrun challenges."""
    __tablename__ = 'speedrun_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    tenant_id = db.Column(db.String(50), nullable=False, unique=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    total_flags = db.Column(db.Integer, default=0)
    flags_found = db.Column(db.Integer, default=0)
    elapsed_time = db.Column(db.Integer, nullable=True)  # in seconds
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<SpeedrunSession user={self.user_id} tenant={self.tenant_id}>'
