import os
import secrets
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
import requests

# ----------------------------------------------------
# 1. GLOBAL CONSTANTS & EXTENSION INITIALIZATION
# ----------------------------------------------------

SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(16))
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')

# 💡 Extensions initialized without app binding (needed for factory pattern)
db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO(cors_allowed_origins="*")
# app = None # Η εφαρμογή δεν ορίζεται πλέον global, αλλά επιστρέφεται από το create_app()

# Google OAuth 2.0 Configuration (Placeholders)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")


# ----------------------------------------------------
# 2. ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ (Χρησιμοποιούν το global 'db')
# ----------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False) # 'owner', 'admin', 'user'
    color = db.Column(db.String(7), default='#FFFFFF', nullable=False)
    avatar_url = db.Column(db.String(255), nullable=True)
    messages = db.relationship('Message', backref='user', lazy=True, cascade='all, delete-orphan') 

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

# ----------------------------------------------------
# 3. HELPER FUNCTIONS & DECORATORS (Πρέπει να οριστούν πριν από τη χρήση)
# ----------------------------------------------------

def get_default_color_by_role(role):
    """Επιστρέφει το προεπιλεγμένο χρώμα με βάση τον ρόλο."""
    if role == 'owner':
        return '#FF3399' # Έντονο Ροζ
    elif role == 'admin':
        return '#00CC00' # Πράσινο
    else:
        return '#FFFFFF' # Λευκό

# Οι decorators ορίζονται έξω, αλλά χρησιμοποιούν τα routes που ορίζονται μέσα στο create_app
def login_required(f):
    def decorated_function(*args, **kwargs):
        if request.current_user is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def check_admin_or_owner(f):
    @login_required
    def decorated_function(*args, **kwargs):
        user = request.current_user
        if user and user.role in ['admin', 'owner']:
            return f(*args, **kwargs)
        return abort(403)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ----------------------------------------------------
# 4. APPLICATION FACTORY FUNCTION (Η λύση στο σφάλμα)
# ----------------------------------------------------
def create_app(config_object=None):
    app = Flask(__name__)
    
    # App Configuration
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_SECURE'] = True # 🚨 Η διόρθωση για το HTTPS/Render
    
    # 💡 Binding extensions to the app
    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app) 

    # 4.1 Before Request Hook (Πρέπει να οριστεί εδώ)
    @app.before_request
    def load_user_from_session():
        """Φορτώνει τον χρήστη από το session σε κάθε request."""
        user = None
        if 'user_id' in session:
            user = db.session.execute(select(User).where(User.id == session['user_id'])).scalar_one_or_none()
        request.current_user = user

    # 4.2 ROUTES & APIs
    
    # Index, Login, Logout, Chat
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/login')
    def login():
        if request.current_user:
            return redirect(url_for('chat'))
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        return redirect(url_for('index'))

    @app.route('/login_submit', methods=['POST'])
    def login_submit():
        display_name = request.form.get('display_name')
        password = request.form.get('password')
        if not display_name or not password:
            return render_template('login.html', error='Invalid display name or password.')
        
        user = db.session.execute(select(User).where(User.display_name == display_name)).scalar_one_or_none()

        if user and user.password_hash and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error='Invalid display name or password.')

    @app.route('/chat')
    @login_required
    def chat():
        user = request.current_user
        has_password_hash = user.password_hash is not None
        return render_template('chat.html', user_id=user.id, display_name=user.display_name, role=user.role, color=user.color, avatar_url=user.avatar_url, has_password_hash=has_password_hash)

    # Admin Panel
    @app.route('/admin_panel')
    @check_admin_or_owner
    def admin_panel():
        return render_template('admin_panel.html')

    # Utility route for checking login status from Admin Panel JS
    @app.route('/check_login')
    @login_required
    def check_login():
        user = request.current_user
        return jsonify({'id': user.id, 'display_name': user.display_name, 'role': user.role}), 200


    # Admin API - User Creation
    @app.route('/admin_create_user', methods=['POST'])
    @check_admin_or_owner
    def admin_create_user():
        try:
            data = request.get_json() 
        except:
            return jsonify({'error': 'Invalid JSON format'}), 400
            
        display_name = data.get('display_name')
        password = data.get('password')
        role = data.get('role', 'user') 

        if not display_name or not password:
            return jsonify({'error': 'Display name and password are required'}), 400

        hashed_password = generate_password_hash(password)
        default_color = get_default_color_by_role(role)

        try:
            new_user = User(
                display_name=display_name,
                password_hash=hashed_password,
                role=role,
                color=default_color,
                avatar_url=None
            )
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({'message': f'User {display_name} created successfully with role {role}.'}), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'User with this display name already exists.'}), 409
        except Exception as e:
            db.session.rollback()
            print(f"Error creating user via admin panel: {e}")
            return jsonify({'error': 'An unexpected error occurred.'}), 500


    # Admin API - Get All Users
    @app.route('/api/v1/admin/users', methods=['GET'])
    @check_admin_or_owner
    def get_all_users():
        users = db.session.execute(select(User).order_by(User.id)).scalars().all()
        user_list = [
            {
                'id': u.id,
                'display_name': u.display_name,
                'role': u.role,
                'has_password': u.password_hash is not None, 
                'google_linked': u.google_id is not None,
                'color': u.color
            }
            for u in users
        ]
        return jsonify(user_list)


    # Admin API - Delete User
    @app.route('/api/v1/admin/user/<int:user_id>/delete', methods=['DELETE'])
    @check_admin_or_owner
    def admin_delete_user(user_id):
        target_user = db.session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        
        if not target_user:
            return jsonify({'error': 'Target user not found.'}), 404

        current_user = request.current_user

        if target_user.id == current_user.id:
            return jsonify({'error': 'You cannot delete your own account.'}), 403

        if target_user.role == 'admin' and current_user.role != 'owner':
            return jsonify({'error': 'Only the Owner can delete an Admin account.'}), 403

        try:
            db.session.delete(target_user)
            db.session.commit()
            return jsonify({'message': f'User {target_user.display_name} deleted successfully.'})
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting user: {e}")
            return jsonify({'error': 'An unexpected error occurred during deletion.'}), 500


    # 4.3 SocketIO Events (Πρέπει να οριστούν εδώ)

    @socketio.on('connect')
    def handle_connect():
        if request.current_user:
            print(f"User {request.current_user.display_name} connected via SocketIO.")
            join_room('global_chat')
            emit('user_status', {'display_name': request.current_user.display_name, 'status': 'online'}, room='global_chat')
        else:
             print("Anonymous user connected but not logged in.")


    @socketio.on('send_message')
    @login_required
    def handle_message(data):
        user = request.current_user
        content = data.get('content', '').strip()

        if not content:
            return 
        
        # Αποθήκευση μηνύματος
        new_message = Message(user_id=user.id, content=content)
        db.session.add(new_message)
        db.session.commit()
        
        # Εκπομπή στο chat
        message_data = {
            'id': new_message.id,
            'user_id': user.id,
            'display_name': user.display_name,
            'content': content,
            'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'role': user.role,
            'color': user.color
        }
        emit('new_message', message_data, room='global_chat')


    @socketio.on('disconnect')
    def handle_disconnect():
        if request.current_user:
            print(f"User {request.current_user.display_name} disconnected from SocketIO.")
            leave_room('global_chat')
            emit('user_status', {'display_name': request.current_user.display_name, 'status': 'offline'}, room='global_chat')
            
    
    return app


# ----------------------------------------------------
# 5. EXECUTION BLOCK
# ----------------------------------------------------
# Αυτό το block τρέχει μόνο όταν καλείται το αρχείο απευθείας (π.χ. db_init.py ή local testing)
if __name__ == '__main__':
    app_instance = create_app()
    with app_instance.app_context():
        # Μπορείτε να προσθέσετε εδώ κώδικα αρχικοποίησης
        pass 
    # Χρησιμοποιούμε το socketio που είναι ήδη συνδεδεμένο με την app_instance
    socketio.run(app_instance, debug=True)