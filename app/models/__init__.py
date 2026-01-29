"""Initialize models package."""
from app.models.models import db, User, Flag, Submission, SpeedrunSession

__all__ = ['db', 'User', 'Flag', 'Submission', 'SpeedrunSession']
