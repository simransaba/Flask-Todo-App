from app import db  # Import your SQLAlchemy instance
from app import app  # Import your Flask app

with app.app_context():
    db.create_all()
