"""Routes package initialization."""
from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.challenges import challenges_bp
from app.routes.scoreboard import scoreboard_bp
from app.routes.speedrun import speedrun_bp
from app.routes.vulnerable import vulnerable_bp

__all__ = ['main_bp', 'auth_bp', 'challenges_bp', 'scoreboard_bp', 'speedrun_bp', 'vulnerable_bp']
