import requests
import os
import json
import uuid
import time
import random
import secrets
import string

from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import jsonify, url_for, request 

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import select, desc, func 
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, OperationalError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates 


# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app, για να χρησιμοποιηθούν στο factory pattern
db = SQLAlchemy()
sess = Session()
oauth = OAuth()
socketio = SocketIO()

# --- Μοντέλα Βάσης Δεδομένων ---
# (Τα models παραμένουν ίδια)

class User(db.Model):
    """Μοντέλο Χρήστη."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(80), nullable=True) 
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(20), default='user')
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default=lambda: generate_random_color())
    is_google_user = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    @validates('role')
    def validate_role(self, key, role):
        if role not in ['user', 'moderator', 'admin', 'owner']:
            raise ValueError("Invalid role specified.")
        return role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    """Μοντέλο Μηνύματος στο Chat."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))
    room_name = db.Column(db.String(80), default='general')
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    is_deleted = db.Column(db.Boolean, default=False)
    
class Settings(db.Model):
    """Παγκόσμιες Ρυθμίσεις."""
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(50), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=True)

class Emoticon(db.Model):
    """Custom Emoticons για το chat."""
    id = db.Column(db.Integer, primary_key=True)
    shortcut = db.Column(db.String(20), unique=True, nullable=False) 
    image_url = db.Column(db.String(255), nullable=False) 

# --- Βοηθητικές Συναρτήσεις ---

def generate_random_color():
    """Δημιουργεί ένα τυχαίο hex χρώμα."""
    return f'#{secrets.token_hex(3)}'

def login_required(f):
    """Decorator για την απαίτηση σύνδεσης."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def initialize_settings(app, db):
    """Διασφαλίζει την ύπαρξη βασικών ρυθμίσεων."""
    with app.app_context():
        required_settings = {
            'chat_name': 'NeonChat',
            'welcome_message': 'Welcome to the NeonChat! Please be respectful.',
            'default_room': 'general'
        }
        for key, default_value in required_settings.items():
            stmt = select(Settings).where(Settings.setting_key == key)
            if not db.session.execute(stmt).scalar_one_or_none():
                db.session.add(Settings(setting_key=key, setting_value=default_value))
        db.session.commit()

def initialize_emoticons(app, db):
    """Διασφαλίζει την ύπαρξη βασικών emoticons."""
    with app.app_context():
        default_emoticons = {
            ':smile:': '/static/emoticons/smile.png',
            ':sad:': '/static/emoticons/sad.png',
            ':love:': '/static/emoticons/love.png',
        }
        for shortcut, url in default_emoticons.items():
            stmt = select(Emoticon).where(Emoticon.shortcut == shortcut)
            if not db.session.execute(stmt).scalar_one_or_none():
                db.session.add(Emoticon(shortcut=shortcut, image_url=url))
        db.session.commit()

def get_current_settings():
    """Παίρνει όλες τις ρυθμίσεις ως dict."""
    try:
        stmt = select(Settings)
        settings_list = db.session.execute(stmt).scalars().all()
        return {s.setting_key: s.setting_value for s in settings_list}
    except Exception as e:
        print(f"Error fetching settings: {e}")
        return {}
    
def get_user_by_session():
    """Βρίσκει τον user από τη session ή επιστρέφει None."""
    user_id = session.get('user_id')
    if user_id:
        try:
            stmt = select(User).where(User.id == user_id)
            return db.session.execute(stmt).scalar_one_or_none()
        except Exception as e:
            # Αυτό μπορεί να συμβεί αν η DB είναι offline, το αφήνουμε να επιστρέψει None
            print(f"Error fetching user by ID during session check: {e}")
            return None
    return None

def setup_app_on_startup(app, db):
    """Ελέγχει και δημιουργεί φακέλους, πινάκες και τον owner."""
    
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        print(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
        
    with app.app_context():
        try:
            # Δημιουργία πινάκων
            db.create_all() 
            print("Database tables ensured.")
            
            # Αρχικοποίηση ρυθμίσεων & emoticons
            initialize_settings(app, db)
            initialize_emoticons(app, db)
            print("Settings and Emoticons initialized.")
            
            # Έλεγχος και δημιουργία Owner User (παραμένει τοπικά για ευκολία)
            owner_username = os.environ.get('OWNER_USERNAME', 'admin')
            owner_email = os.environ.get('OWNER_EMAIL', 'admin@example.com')
            owner_password = os.environ.get('OWNER_PASSWORD', secrets.token_urlsafe(16))
            
            stmt = select(User).where(User.role == 'owner')
            owner_user = db.session.execute(stmt).scalar_one_or_none()
            
            if not owner_user:
                stmt = select(User).where(User.username == owner_username)
                existing_user = db.session.execute(stmt).scalar_one_or_none()
                
                if not existing_user:
                    default_owner = User(
                        username=owner_username,
                        display_name=owner_username,
                        email=owner_email,
                        role='owner',
                        avatar_url='/static/default_avatar.png',
                        color=generate_random_color() 
                    )
                    default_owner.set_password(owner_password)
                    db.session.add(default_owner)
                    db.session.commit()
                    print(f"✅ Created default Owner user: {owner_username}. Password is the one set in environment or a random one.")
                else:
                    print("Default Owner user check completed, an existing user has the chosen username.")
            else:
                print("Owner user check completed.")

        except OperationalError as e:
            print("-" * 50)
            print("🚨 CRITICAL DATABASE ERROR (OperationalError) 🚨")
            print(f"Could not connect to or operate the database: {e}")
            print("This usually means DATABASE_URL is wrong or the Postgres server is down.")
            print("-" * 50)
            # Αν αποτύχει εδώ, η εφαρμογή θα συνεχίσει αλλά οι DB routes θα αποτύχουν.
        except ProgrammingError as e:
             print(f"SQLAlchemy Programming Error during setup: {e}.")
        except Exception as e:
             print(f"An unexpected error occurred during DB setup: {e}")


# --- Flask Application Factory ---

def create_app():
    """Δημιουργεί και ρυθμίζει την Flask εφαρμογή."""
    app = Flask(__name__)

    # 🚨 ΚΡΙΣΙΜΗ ΠΡΟΣΘΗΚΗ: Χρησιμοποιούμε ProxyFix για να διασφαλίσουμε τη σωστή λειτουργία του SocketIO
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_port=1, x_prefix=1, x_proto=1)

    # Γενικές Ρυθμίσεις
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_change_me_in_prod')
    app.config['SESSION_TYPE'] = 'sqlalchemy' 
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

    # Ρυθμίσεις Uploads
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
    app.config['UPLOAD_FOLDER'] = 'static/uploads'

    # Ρυθμίσεις Βάσης Δεδομένων
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///chatbox.db')

    # Προσαρμόζουμε το URL του PostgreSQL
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Ρυθμίσεις OAuth Google
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    # --- ΑΡΧΙΚΟΠΟΙΗΣΗ ΤΩΝ EXTENSIONS ΜΕ ΤΟ app ---
    db.init_app(app)
    sess.init_app(app)
    socketio.init_app(app, manage_session=False, async_mode='threading', cors_allowed_origins="*")
    oauth.init_app(app)

 # 2.3. FIX ΓΙΑ Flask-Session & Flask-SQLAlchemy Conflict
    # Το Flask-Session, όταν χρησιμοποιεί το 'sqlalchemy' ως τύπο, προσπαθεί να δημιουργήσει
    # μια νέα επέκταση SQLAlchemy αν δεν του δοθεί ρητά η υπάρχουσα, οδηγώντας στο RuntimeError.
    if app.config.get('SESSION_TYPE') == 'sqlalchemy':
        # 🚨 ΚΡΙΣΙΜΗ ΔΙΟΡΘΩΣΗ: Δίνουμε την υπάρχουσα επέκταση `db` στο Session configuration.
       app.config['SESSION_SQLALCHEMY'] = db    # Προσθήκη Google OAuth Provider


    global google
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://oauth2.googleapis.com/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params={'scope': 'openid email profile'},
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'openid email profile'},
        jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    )
    
    # 🚨 Εκτελούμε το setup ΜΟΝΟ μια φορά όταν η εφαρμογή είναι έτοιμη
    with app.app_context():
        setup_app_on_startup(app, db)
        
    # --- Flask Routes ---

    @app.route('/')
    def index():
        """Η κύρια σελίδα του chat. Απαιτεί σύνδεση."""
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        
        try:
            current_user = get_user_by_session()
            if not current_user:
                session.pop('user_id', None)
                return redirect(url_for('login_page'))
                
            settings = get_current_settings()
            default_room = settings.get('default_room', 'general')
            
            # Λήψη των τελευταίων 50 μηνυμάτων
            stmt = select(Message).order_by(desc(Message.timestamp)).limit(50).options(db.joinedload(Message.user))
            messages = db.session.execute(stmt).scalars().all()
            messages.reverse() 
            
            return render_template('index.html', 
                                user=current_user, 
                                settings=settings, 
                                messages=messages,
                                default_room=default_room)
        except OperationalError as e:
            # Ειδικός χειρισμός αν η DB είναι offline
            print(f"🚨 OperationalError in index route: {e}")
            return "Database connection failed during chat load. Please check server logs.", 500
        except Exception as e:
            print(f"🚨 CRITICAL ERROR in index route: {e}")
            return "Internal Server Error during chat loading. Check database connection logs.", 500


    @app.route('/login')
    def login_page():
        """Σελίδα σύνδεσης/εγγραφής."""
        if 'user_id' in session:
            return redirect(url_for('index'))
        return render_template('login.html')

    # --- Login & Sign Up API Routes (Local) ---

    @app.route('/api/v1/sign_up', methods=['POST'])
    def sign_up():
        """Εγγραφή νέου χρήστη."""
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not password or len(username) < 3 or len(password) < 6:
            return jsonify({'error': 'Username must be at least 3 chars, password 6 chars.'}), 400

        try:
            stmt_username = select(User).where(User.username == username)
            if db.session.execute(stmt_username).scalar_one_or_none():
                return jsonify({'error': 'Username already taken.'}), 409
            
            if email:
                stmt_email = select(User).where(User.email == email)
                if db.session.execute(stmt_email).scalar_one_or_none():
                    return jsonify({'error': 'Email already registered.'}), 409

            new_user = User(username=username, display_name=username, email=email, color=generate_random_color())
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({'message': 'Registration successful! Please log in.'}), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Registration failed due to data conflict (e.g. duplicate username/email).'}), 409
        except Exception as e:
            db.session.rollback()
            print(f"Sign up error: {e}")
            return jsonify({'error': 'An unexpected error occurred during registration.'}), 500

    @app.route('/api/v1/login', methods=['POST'])
    def login():
        """Σύνδεση χρήστη."""
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Missing username or password.'}), 400

        try:
            stmt = select(User).where(User.username == username)
            user = db.session.execute(stmt).scalar_one_or_none()

            if user and user.password_hash and user.check_password(password):
                # Επιτυχής σύνδεση
                session['user_id'] = user.id
                session.permanent = True
                return jsonify({'message': 'Login successful!', 'redirect': url_for('index')}), 200
            elif user and user.is_google_user:
                return jsonify({'error': 'This username is registered via Google. Please use the Google sign-in button.'}), 401
            else:
                return jsonify({'error': 'Invalid username or password.'}), 401

        except Exception as e:
            print(f"Login error: {e}")
            return jsonify({'error': 'An unexpected error occurred during login.'}), 500

    @app.route('/logout')
    def logout():
        """Αποσύνδεση χρήστη."""
        session.pop('user_id', None)
        return redirect(url_for('login_page'))

    # --- Google OAuth Routes ---

    @app.route('/login/google')
    def login_google():
        """Ξεκινά τη διαδικασία σύνδεσης με Google."""
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)

    @app.route('/login/google/authorize')
    def authorize_google():
        """Callback μετά την επιτυχή σύνδεση με Google."""
        try:
            token = google.authorize_access_token()
            userinfo = google.get('userinfo').json()
            
            google_email = userinfo.get('email')
            google_username = google_email.split('@')[0] if google_email else userinfo.get('id')
            google_avatar = userinfo.get('picture')
            google_display_name = userinfo.get('name') or google_username
            
            if not google_email:
                return redirect(url_for('login_page', error='Google sign-in failed: No email provided.'))

            stmt = select(User).where(User.email == google_email)
            user = db.session.execute(stmt).scalar_one_or_none()

            if user:
                if not user.is_google_user:
                    return redirect(url_for('login_page', error='Email registered locally. Please log in with password.'))
                
                user.avatar_url = google_avatar
                user.display_name = google_display_name
                db.session.commit()
                
                session['user_id'] = user.id
                session.permanent = True
                return redirect(url_for('index'))
            else:
                new_user = User(
                    username=google_username,
                    display_name=google_display_name,
                    email=google_email,
                    is_google_user=True,
                    avatar_url=google_avatar,
                    color=generate_random_color(),
                )
                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id
                session.permanent = True
                return redirect(url_for('index'))

        except MismatchingStateError:
            return redirect(url_for('login_page', error='OAuth state mismatch. Please try again.'))
        except OAuthError as e:
            print(f"OAuth Error: {e}")
            return redirect(url_for('login_page', error=f'Google authorization failed: {e}'))
        except Exception as e:
            db.session.rollback()
            print(f"Google Authorize General Error: {e}")
            return redirect(url_for('login_page', error='An unexpected error occurred during Google login.'))
            
    # --- SocketIO Events (Events remain the same) ---

    @socketio.on('connect')
    def handle_connect():
        current_user = get_user_by_session()
        if current_user:
            settings = get_current_settings()
            default_room = settings.get('default_room', 'general')
            
            join_room(default_room)
            join_room(f"user_{current_user.id}")
            
            print(f"User {current_user.username} (ID: {current_user.id}) connected and joined {default_room}.")
            
            emit('user_joined', {'username': current_user.display_name, 'room': default_room}, room=default_room)
        else:
            print("Unauthenticated user connected.")
            
    @socketio.on('disconnect')
    def handle_disconnect():
        current_user = get_user_by_session()
        if current_user:
            settings = get_current_settings()
            default_room = settings.get('default_room', 'general')
            
            emit('user_left', {'username': current_user.display_name, 'room': default_room}, room=default_room)
            
            leave_room(default_room)
            leave_room(f"user_{current_user.id}")
            print(f"User {current_user.username} (ID: {current_user.id}) disconnected.")

    @socketio.on('send_message')
    @login_required
    def handle_send_message(data):
        content = data.get('content', '').strip()
        room_name = data.get('room', 'general')
        
        if not content:
            return

        current_user = get_user_by_session()
        
        if current_user:
            try:
                new_message = Message(
                    user_id=current_user.id,
                    room_name=room_name,
                    content=content,
                    timestamp=datetime.now(timezone.utc)
                )
                db.session.add(new_message)
                db.session.commit()
                
                message_data = {
                    'id': new_message.id,
                    'user_id': current_user.id,
                    'username': current_user.display_name,
                    'avatar_url': current_user.avatar_url,
                    'color': current_user.color,
                    'content': content,
                    'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'room': room_name
                }
                
                emit('new_message', message_data, room=room_name)
                
            except Exception as e:
                db.session.rollback()
                print(f"Error saving message: {e}")
                emit('error_message', {'error': 'Failed to send message.'}, room=f"user_{current_user.id}")
                
    return app


# --- Τερματικό Σημείο: Εκτέλεση του Server ---

# Αυτό το block είναι μόνο για τοπική εκτέλεση (π.χ. python server.py)
if __name__ == '__main__':
    app = create_app()
    print("Starting Flask-SocketIO server locally...")
    # 🚨 ΟΡΙΖΟΥΜΕ ΤΟ PORT ΝΑ ΠΡΟΕΡΧΕΤΑΙ ΑΠΟ ΤΟ ΠΕΡΙΒΑΛΛΟΝ, με fallback στο 10000
    port = int(os.environ.get('PORT', 10000)) 
    socketio.run(app, debug=True, port=port)
    
# 🚨 ΔΙΟΡΘΩΣΗ: Δεν καλούμε το create_app() εδώ. 
# Θα ορίσουμε το Procfile να καλεί τη συνάρτηση.
# application = create_app() # <--- ΣΧΟΛΙΑΣΕ Ή ΔΙΕΓΡΑΨΕ ΑΥΤΗ ΤΗ ΓΡΑΜΜΗ