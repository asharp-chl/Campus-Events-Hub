
from werkzeug.security import generate_password_hash
from models import  *
from app import create_app, db


app = create_app()

with app.app_context():
    # Check if admin already exists
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        # Create admin user
        admin = User(
            username='admin',
            email='ine_event@admin.ma',
            password_hash=generate_password_hash('12345678'),
            role=UserRole.ADMIN

        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")