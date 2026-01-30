"""Initialize models package."""
from app.models.models import db, User, Flag, FlagSecret, Submission, SpeedrunSession

__all__ = ['db', 'User', 'Flag', 'FlagSecret', 'Submission', 'SpeedrunSession']
