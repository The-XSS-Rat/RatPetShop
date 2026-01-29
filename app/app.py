"""Main Flask application."""
from flask import Flask
from app.models import db
from app.routes import main_bp, auth_bp, challenges_bp, scoreboard_bp, speedrun_bp
from app.utils.db_init import init_db, seed_database
import os


def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ratpetshop.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Override with custom config if provided
    if config:
        app.config.update(config)
    
    # Initialize extensions
    db.init_app(app)
    
    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(challenges_bp, url_prefix='/challenges')
    app.register_blueprint(scoreboard_bp, url_prefix='/scoreboard')
    app.register_blueprint(speedrun_bp, url_prefix='/speedrun')
    
    # Initialize database
    init_db(app)
    
    # Seed database if empty
    with app.app_context():
        from app.models import Flag
        if Flag.query.count() == 0:
            seed_database(app)
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='127.0.0.1', port=5000)
