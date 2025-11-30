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

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH --
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

# --- Global Real-time State (Safe for -w 1 eventlet worker) ---
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'

# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app, για να χρησιμοποιηθούν στο factory pattern
db = SQLAlchemy()
sess = Session()
oauth = OAuth()
socketio = SocketIO()

# --- Μοντέλα Βάσης Δεδομένων (SQLAlchemy) ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    
    # Τοπική σύνδεση
    username = db.Column(db.String(80), unique=True, nullable=True) # Μπορεί να είναι null αν είναι μόνο OAuth
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    
    # OAuth σύνδεση
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(256), nullable=True)

    # Πληροφορίες Χρήστη
    display_name = db.Column(db.String(80), nullable=False)
    avatar_url = db.Column(db.String(256), default='/static/default_avatar.png')
    
    # 🚨 Κρίσιμο: Προσθήκη πεδίων Role, Color, Online status 🚨
    # role: 'user', 'admin', 'owner'
    role = db.Column(db.String(20), default='user', nullable=False) 
    # color: hex code για το chat
    color = db.Column(db.String(7), default='#ffffff', nullable=False) 
    # is_online: Boolean για γρήγορο έλεγχο
    is_online = db.Column(db.Boolean, default=False, nullable=False)

    # Χρονικές σφραγίδες
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, default=datetime.now)
    last_activity = db.Column(db.DateTime, default=datetime.now)
    
    # Σχέσεις
    messages = db.relationship('Message', backref='author', lazy='dynamic')
    
    @validates('email')
    def validate_email(self, key, email):
        if email:
            return email.lower()
        raise ValueError("Email cannot be empty")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # 🚨 Helper για να βγάζει μόνο τα βασικά στοιχεία του χρήστη
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name,
            'role': self.role,
            'color': self.color,
            'avatar_url': self.avatar_url,
            'is_online': self.is_online,
            'last_activity': self.last_activity.isoformat()
        }

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    room = db.Column(db.String(50), default=GLOBAL_ROOM, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    is_system = db.Column(db.Boolean, default=False)
    
    # 🚨 Helper για να βγάζει το μήνυμα μαζί με τον χρήστη
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'content': self.content,
            'room': self.room,
            'timestamp': self.timestamp.isoformat(),
            'author': self.author.to_dict(), # 🚨 Κρίσιμο: Επιστρέφει όλο το dict του χρήστη
            'is_system': self.is_system
        }

class AppSetting(db.Model):
    __tablename__ = 'app_settings'
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(50), unique=True, nullable=False)
    setting_value = db.Column(db.String(255), nullable=False)

class Emoticon(db.Model):
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False) # π.χ. :smile:
    url = db.Column(db.String(255), nullable=False) # π.χ. /static/emoticons/smile.gif

# --- Decorator και Utility Functions ---

def login_required(f):
    """Decorator που απαιτεί ο χρήστης να είναι συνδεδεμένος (υπάρχει session['user_id'])"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Αν δεν είναι συνδεδεμένος, τον στέλνουμε στη σελίδα login
            return redirect(url_for('login', next=request.url))
        
        # Εντοπίζουμε τον χρήστη και τον περνάμε ως current_user
        current_user = db.session.get(User, session['user_id'])
        if not current_user:
            # Αν ο χρήστης διαγράφηκε, καθαρίζουμε το session
            session.pop('user_id', None)
            return redirect(url_for('login', next=request.url))
            
        kwargs['current_user'] = current_user
        return f(*args, **kwargs)
    return decorated_function

# 🚨 Νέα: Utility για να βρίσκει τον χρήστη από το session
def get_current_user():
    """Επιστρέφει τον τρέχοντα χρήστη ή None"""
    user_id = session.get('user_id')
    if user_id:
        return db.session.get(User, user_id)
    return None

# 🚨 Νέα: Utility για να βρίσκει τα settings (από memory cache ή DB)
SETTINGS_CACHE = {}
def get_setting(key, default=None):
    """Παίρνει μια ρύθμιση από τη βάση ή την cache"""
    if key in SETTINGS_CACHE:
        return SETTINGS_CACHE[key]
    
    # Πρέπει να τρέξει εντός app context
    from flask import current_app
    with current_app.app_context():
        setting = db.session.execute(select(AppSetting).where(AppSetting.setting_key == key)).scalar_one_or_none()
        if setting:
            SETTINGS_CACHE[key] = setting.setting_value
            return setting.setting_value
        return default

# 🚨 Νέα: Helper για να παράγει τυχαίο χρώμα (Διατηρείται ως fallback, αλλά δεν χρησιμοποιείται πλέον για νέους χρήστες)
def generate_random_color():
    """Δημιουργεί ένα τυχαίο hex χρώμα (π.χ. #a34b2f)"""
    return '#'+''.join(random.choices('0123456789abcdef', k=6))

# 🚨 Ο ΠΛΗΡΗΣ ΟΡΙΣΜΟΣ ΤΗΣ get_or_create_user 🚨
# ----------------------------------------------------------------------------------
def get_or_create_user(email, display_name, provider, oauth_id=None, avatar_url=None):
    """
    Βρίσκει ή δημιουργεί έναν χρήστη με βάση το email και τον OAuth provider/ID.
    """
    
    # Καθαρισμός/Τυποποίηση δεδομένων
    email = email.lower().strip()
    display_name = display_name.strip()
    provider = provider.strip().lower()

    # 1. Αναζήτηση με βάση OAuth ID και Provider (πρωταρχικός έλεγχος)
    if oauth_id and provider:
        user = db.session.execute(
            select(User).where(
                (User.oauth_provider == provider) & (User.oauth_id == oauth_id)
            )
        ).scalar_one_or_none()
        
        if user:
            # Βρέθηκε χρήστης μέσω OAuth. Ενημέρωση last_login.
            user.last_login = datetime.now()
            db.session.commit()
            return user

    # 2. Αναζήτηση με βάση το Email
    user = db.session.execute(
        select(User).where(User.email == email)
    ).scalar_one_or_none()
    
    if user:
        # Βρέθηκε χρήστης μέσω Email.
        
        # Αν ο χρήστης ήταν local και συνδέεται τώρα μέσω OAuth, τον μετατρέπουμε σε OAuth user.
        if not user.oauth_provider and oauth_id and provider:
            user.oauth_provider = provider
            user.oauth_id = oauth_id
            user.display_name = display_name 
            user.avatar_url = avatar_url if avatar_url else user.avatar_url
            
            if not user.username:
                user.username = f"{provider}_{secrets.token_hex(4)}"
            
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                pass
        
        # Ενημέρωση last_login
        user.last_login = datetime.now()
        db.session.commit()
        return user
        
    # 3. Δημιουργία Νέου Χρήστη (πρώτη φορά σύνδεση)
    
    # Δημιουργία μοναδικού username
    base_username = display_name.replace(' ', '_').lower()
    username = base_username
    count = 1
    while db.session.execute(select(User).where(User.username == username)).scalar_one_or_none():
        username = f"{base_username}_{count}"
        count += 1
        if count > 100: 
            username = f"{provider}_{secrets.token_hex(4)}" 
            break
            
    # 🚨 ΕΔΩ: Ορίζουμε το default χρώμα για νέους χρήστες (role='user') σε ΛΕΥΚΟ (#FFFFFF)
    new_user = User(
        email=email,
        display_name=display_name,
        oauth_provider=provider,
        oauth_id=oauth_id,
        avatar_url=avatar_url if avatar_url else '/static/default_avatar.png',
        username=username,
        role='user', 
        color='#FFFFFF' # Default white color for all new 'user' role accounts
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return new_user
    except IntegrityError:
        db.session.rollback()
        return None
# ----------------------------------------------------------------------------------


def save_and_emit_message(user_id, content, room_name=GLOBAL_ROOM, is_system=False):
    """Αποθηκεύει και εκπέμπει ένα μήνυμα στο chat"""
    try:
        new_message = Message(
            user_id=user_id,
            content=content,
            room=room_name,
            is_system=is_system
        )
        db.session.add(new_message)
        db.session.commit()
        
        # 🚨 Εκπομπή του μηνύματος σε όλους τους χρήστες του δωματίου
        socketio.emit('new_message', 
                      new_message.to_dict(), 
                      room=room_name)
        return True
    except Exception as e:
        print(f"Error saving/emitting message: {e}")
        db.session.rollback()
        return False

# 🚨 Νέα: Utility για να παίρνει τις ρυθμίσεις και τα emoticons
def get_initial_data(app_context):
    """Παίρνει ρυθμίσεις και emoticons για το chat.html"""
    with app_context:
        # 1. Settings
        settings = db.session.execute(select(AppSetting)).scalars().all()
        settings_dict = {s.setting_key: s.setting_value for s in settings}
        
        # 2. Emoticons
        emoticons = db.session.execute(select(Emoticon)).scalars().all()
        emoticons_dict = {e.code: e.url for e in emoticons}
        
        return settings_dict, emoticons_dict

# --- Factory Pattern για την εφαρμογή (Κρίσιμο για Render/Gunicorn) ---

def create_app():
    # 🚨 1. Αρχικοποίηση Flask App
    app = Flask(__name__, static_url_path='/static')
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_prefix=1, x_port=1, x_proto=1)

    # --- Ρυθμίσεις (Config) ---
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db') 
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Ρυθμίσεις Flask-Session
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions' # Νέος πίνακας
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_COOKIE_SECURE'] = True # Κρίσιμο για HTTPS σε παραγωγή
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24 * 7) # 1 εβδομάδα

    # Ρυθμίσεις OAuth
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    # --- 2. Αρχικοποίηση Extensions με το App ---
    
    # 🚨 DB/Session: Πρέπει να γίνει το db.init_app ΠΡΙΝ το sess.init_app
    db.init_app(app)
    sess.init_app(app) # Χρησιμοποιεί το db που μόλις αρχικοποιήθηκε
    
    # OAuth
    oauth.init_app(app)
    # Δημιουργία remote application για το Google
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        oauth.register(
            name='google',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            access_token_url='https://oauth2.googleapis.com/token',
            access_token_params=None,
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            authorize_params=None,
            api_base_url='https://www.googleapis.com/oauth2/v1/',
            client_kwargs={'scope': 'openid email profile'},
        )
    
    # SocketIO
    socketio.init_app(app, 
                      message_queue=os.environ.get('REDIS_URL'), # Χρήση Redis για παραγωγή
                      cors_allowed_origins="*", # Επιτρέπει συνδέσεις από παντού (για Dev)
                      logger=False, 
                      engineio_logger=False,
                      manage_session=False # Χρησιμοποιούμε το Flask-Session
                     )
    
    # --- 3. Δημιουργία Πινάκων και Βασικών Δεδομένων (Μόνο αν δεν υπάρχουν) ---
    with app.app_context():
        try:
            # Αυτό θα δημιουργήσει τους πίνακες αν δεν υπάρχουν
            db.create_all() 
            
            # 🚨 Δημιουργία Owner αν δεν υπάρχει
            owner_user = db.session.execute(select(User).where(User.role == 'owner')).scalar_one_or_none()
            if not owner_user:
                print("🚨 Creating initial OWNER user. Email: owner@example.com, Password: password123")
                new_owner = User(
                    username='owner',
                    email='owner@example.com',
                    display_name='Admin Owner',
                    role='owner',
                    # 🚨 Τροποποίηση: Χρυσό χρώμα για τον Owner
                    color='#FFD700', 
                    avatar_url='/static/default_avatar.png'
                )
                new_owner.set_password('password123')
                db.session.add(new_owner)
                db.session.commit()
                print("Owner created successfully.")
            
            # 🚨 Βασικές Ρυθμίσεις (Settings)
            default_settings = {
                'chat_enabled': 'True',
                'feature_bold': 'True',
                'feature_italic': 'True',
                'feature_underline': 'True',
                'max_msg_length': '500'
            }
            for key, default_value in default_settings.items():
                existing = db.session.execute(select(AppSetting).where(AppSetting.setting_key == key)).scalar_one_or_none()
                if not existing:
                    db.session.add(AppSetting(setting_key=key, setting_value=default_value))

            # 🚨 Βασικά Emoticons
            default_emoticons = {
                ':smile:': '/static/emoticons/smile.gif',
                ':laugh:': '/static/emoticons/laugh.gif',
                ':cry:': '/static/emoticons/cry.gif',
            }
            for code, url in default_emoticons.items():
                existing = db.session.execute(select(Emoticon).where(Emoticon.code == code)).scalar_one_or_none()
                if not existing:
                    db.session.add(Emoticon(code=code, url=url))

            db.session.commit()
            
        except (IntegrityError, ProgrammingError, OperationalError) as e:
            # Σφάλματα που μπορεί να συμβούν κατά το build/startup του Render
            db.session.rollback()
            print(f"DB Initialization Warning (Rollback): {e}")

    # --- 4. Flask Routes ---

    # 🚨 Route: Βασική σελίδα ελέγχου (απαιτεί session)
    @app.route('/', methods=['GET'])
    @login_required
    def index(current_user):
        # 🚨 Αν ο χρήστης είναι συνδεδεμένος, τον στέλνουμε στο chat
        if current_user:
            return redirect(url_for('chat'))
        
        # Αυτό το κομμάτι είναι backup/debug
        visits = session.get('visits', 0)
        visits += 1
        session['visits'] = visits
        return render_template('index.html', visits=visits)
    
    # 🚨 Route: Chat Room
    @app.route('/chat', methods=['GET'])
    @login_required
    def chat(current_user):
        # Παίρνουμε τα τελευταία 100 μηνύματα
        messages = db.session.execute(
            select(Message)
            .order_by(desc(Message.timestamp))
            .limit(100)
        ).scalars().all()
        
        # Αντιστρέφουμε τη σειρά για σωστή εμφάνιση (παλαιότερο-νέο)
        messages.reverse()
        
        # Παίρνουμε settings και emoticons
        settings, emoticons = get_initial_data(app.app_context())

        # Παίρνουμε τους online χρήστες 
        online_users = db.session.execute(
            select(User).where(User.is_online == True)
        ).scalars().all()

        return render_template('chat.html', 
                               user=current_user, 
                               messages=messages,
                               online_users=online_users,
                               global_settings=settings,
                               global_emoticons=emoticons)
    
    # 🚨 Route: Admin Panel
    @app.route('/admin', methods=['GET'])
    @login_required
    def admin_panel(current_user):
        if current_user.role not in ['admin', 'owner']:
            return redirect(url_for('chat'))
        return render_template('admin_panel.html')

    # 🚨 Route: Σελίδα Login/Sign Up
    @app.route('/login', methods=['GET'])
    def login():
        if 'user_id' in session:
            return redirect(url_for('chat'))
        # Περνάμε το Google auth URL
        google_auth_url = url_for('oauth_login', name='google')
        return render_template('login.html', google_auth_url=google_auth_url)

    # 🚨 API Route: Έλεγχος σύνδεσης (για JS client)
    @app.route('/check_login')
    def check_login():
        user = get_current_user()
        if user:
            return jsonify({'is_logged_in': True, 'id': user.id, 'role': user.role}), 200
        return jsonify({'is_logged_in': False}), 401

    # 🚨 API Route: Τοπικό Sign Up
    @app.route('/api/v1/sign_up', methods=['POST'])
    def api_sign_up():
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not (username and email and password):
            return jsonify({'error': 'Missing data.'}), 400
        
        email = email.lower().strip()
        username = username.strip()

        # Έλεγχος μοναδικότητας
        if db.session.execute(select(User).where(User.email == email)).scalar_one_or_none():
            return jsonify({'error': 'Email already registered.'}), 409
        if db.session.execute(select(User).where(User.username == username)).scalar_one_or_none():
            return jsonify({'error': 'Username already taken.'}), 409

        try:
            new_user = User(
                username=username,
                email=email,
                display_name=username,
                role='user',
                # 🚨 Τροποποίηση: Λευκό χρώμα για τους απλούς χρήστες
                color='#FFFFFF' 
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'Registration successful. Please log in.'}), 201
        except Exception as e:
            db.session.rollback()
            print(f"Sign up error: {e}")
            return jsonify({'error': 'Server error during registration.'}), 500

    # 🚨 API Route: Τοπικό Login
    @app.route('/api/v1/login', methods=['POST'])
    def api_login():
        data = request.json
        login_id = data.get('login_id') # Μπορεί να είναι email ή username
        password = data.get('password')

        if not (login_id and password):
            return jsonify({'error': 'Missing data.'}), 400

        login_id = login_id.lower().strip()

        # Αναζήτηση με email ή username
        user = db.session.execute(
            select(User).where(
                (func.lower(User.email) == login_id) | (func.lower(User.username) == login_id)
            )
        ).scalar_one_or_none()

        if user and user.password_hash and user.check_password(password):
            session['user_id'] = user.id
            user.last_login = datetime.now()
            db.session.commit()
            return jsonify({'message': 'Login successful!', 'redirect_url': url_for('chat')}), 200
        else:
            return jsonify({'error': 'Invalid credentials.'}), 401
            
    # 🚨 Route: Logout
    @app.route('/logout')
    def logout():
        user = get_current_user()
        if user:
            # Ενημέρωση ότι ο χρήστης έφυγε
            save_and_emit_message(user.id, f"{user.display_name} has left the chat.", is_system=True)

            # Ενημέρωση DB και Online state
            user.is_online = False
            user.last_activity = datetime.now()
            db.session.commit()

            # Εκπομπή event αποσύνδεσης (για ενημέρωση των άλλων χρηστών)
            socketio.emit('user_disconnected', {'user_id': user.id}) 
            
        session.pop('user_id', None)
        return redirect(url_for('login'))

    # 🚨 OAuth Login
    @app.route('/oauth/login/<name>')
    def oauth_login(name):
        client = oauth.create_client(name)
        if not client:
            return jsonify({'error': f'OAuth client {name} not configured.'}), 404
        
        # 🚨 Χρησιμοποιούμε το url_for('oauth_callback', name=name) για το redirect_uri
        redirect_uri = url_for('oauth_callback', name=name, _external=True)
        return client.authorize_redirect(redirect_uri)

    # 🚨 OAuth Callback
    @app.route('/oauth/callback/<name>')
    def oauth_callback(name):
        client = oauth.create_client(name)
        if not client:
            return jsonify({'error': f'OAuth client {name} not found.'}), 404
            
        try:
            # 1. Ανταλλαγή κωδικού με access token
            token = client.authorize_access_token()
            
            # 2. Φόρτωση πληροφοριών χρήστη
            # Ανάλογα με τον provider, μπορεί να χρειαστεί διαφορετικό endpoint.
            if name == 'google':
                user_info = client.get('userinfo').json()
            else:
                return jsonify({'error': f'Unsupported OAuth provider: {name}'}), 501
            
            # 3. Χρήση του get_or_create_user για σύνδεση/εγγραφή
            user = get_or_create_user(
                email=user_info.get('email'),
                display_name=user_info.get('name'),
                provider=name,
                oauth_id=user_info.get('sub'), # Google unique ID
                avatar_url=user_info.get('picture')
            )

            if user:
                session['user_id'] = user.id
                return redirect(url_for('chat'))
            else:
                return jsonify({'error': 'Failed to create or retrieve user profile.'}), 500

        except MismatchingStateError:
            return jsonify({'error': 'OAuth state mismatch. Please try again.'}), 400
        except OAuthError as e:
            return jsonify({'error': f'OAuth failed: {e}'}), 500
        except Exception as e:
            print(f"General OAuth Error: {e}")
            return jsonify({'error': 'An unexpected error occurred during OAuth.'}), 500
    
    # 🚨 API Routes για το Admin Panel 
    # (θα πρέπει να υλοποιηθούν: /api/v1/settings, /api/v1/emoticons, /api/v1/users)
    
    @app.route('/api/v1/settings', methods=['GET', 'POST'])
    @login_required
    def api_settings(current_user):
        if current_user.role not in ['admin', 'owner']:
            return jsonify({'error': 'Permission denied'}), 403
        
        if request.method == 'GET':
            # Επιστροφή όλων των ρυθμίσεων
            settings = db.session.execute(select(AppSetting)).scalars().all()
            return jsonify({s.setting_key: s.setting_value for s in settings}), 200
            
        elif request.method == 'POST':
            # Ενημέρωση ρυθμίσεων
            data = request.json
            for key, value in data.items():
                setting = db.session.execute(select(AppSetting).where(AppSetting.setting_key == key)).scalar_one_or_none()
                if setting:
                    setting.setting_value = str(value)
                else:
                    db.session.add(AppSetting(setting_key=key, setting_value=str(value)))
            db.session.commit()
            
            # 🚨 Εκκαθάριση cache ρυθμίσεων
            SETTINGS_CACHE.clear()
            
            # Εκπομπή event σε όλους για ενημέρωση ρυθμίσεων
            socketio.emit('settings_updated', data) 
            
            return jsonify({'message': 'Settings updated successfully'}), 200

    @app.route('/api/v1/users', methods=['GET', 'POST'])
    @login_required
    def api_users(current_user):
        if current_user.role not in ['admin', 'owner']:
            return jsonify({'error': 'Permission denied'}), 403
        
        if request.method == 'GET':
            users = db.session.execute(select(User).order_by(User.id)).scalars().all()
            return jsonify([u.to_dict() for u in users]), 200

        elif request.method == 'POST':
            # Ενημέρωση ρόλου ή άλλων στοιχείων χρήστη
            data = request.json
            user_id = data.get('user_id')
            new_role = data.get('role')
            
            if not user_id or not new_role:
                return jsonify({'error': 'Missing user_id or role'}), 400
                
            user_to_update = db.session.get(User, user_id)

            # Απαγόρευση αλλαγής του δικού μας ρόλου
            if user_to_update.id == current_user.id:
                 return jsonify({'error': 'Cannot change your own role.'}), 403

            # Απαγόρευση υποβάθμισης Owner
            if user_to_update.role == 'owner' and current_user.role != 'owner':
                return jsonify({'error': 'Only the owner can manage the owner role.'}), 403
            
            if user_to_update and new_role in ['user', 'admin', 'owner']:
                user_to_update.role = new_role
                db.session.commit()
                # Εκπομπή event για ενημέρωση του ρόλου
                socketio.emit('user_role_updated', {'user_id': user_id, 'role': new_role})
                return jsonify({'message': f'Role for user {user_id} updated to {new_role}'}), 200
            
            return jsonify({'error': 'User not found or invalid role.'}), 404
            
    # --- 5. SocketIO Events ---

    # 🚨 Event: Όταν συνδέεται ένας client
    @socketio.on('connect')
    def handle_connect():
        user = get_current_user()
        if user:
            # 1. Προσθήκη στο ONLINE_SIDS
            ONLINE_SIDS[request.sid] = user.id
            
            # 2. Είσοδος στο δωμάτιο
            join_room(GLOBAL_ROOM)

            # 3. Ενημέρωση DB status (αν δεν είναι ήδη online)
            # Αυτός ο έλεγχος μειώνει τα commits στη DB
            if not user.is_online:
                user.is_online = True
                user.last_activity = datetime.now()
                db.session.commit()
                
                # 4. Εκπομπή event σύνδεσης
                socketio.emit('user_connected', {'user': user.to_dict()}, room=GLOBAL_ROOM)
                
                # 5. Εκπομπή system message στο chat
                save_and_emit_message(user.id, f"{user.display_name} has joined the chat.", is_system=True)
            
            # 6. Επιστροφή των online users στον ίδιο τον client (μόνο σε αυτόν)
            online_users = db.session.execute(
                select(User).where(User.is_online == True)
            ).scalars().all()
            emit('initial_online_users', {'users': [u.to_dict() for u in online_users]})

        else:
            # Αν δεν υπάρχει session, αποσυνδέουμε τον socket client
            emit('auth_error', {'error': 'Authentication required. Redirecting to login.'})
            socketio.sleep(1)
            request.namespace.disconnect()


    # 🚨 Event: Όταν αποσυνδέεται ένας client
    @socketio.on('disconnect')
    def handle_disconnect():
        user_id = ONLINE_SIDS.pop(request.sid, None)
        
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                # Ελέγχουμε αν έχει μείνει άλλος ενεργός socket για τον ίδιο χρήστη
                if user_id not in ONLINE_SIDS.values():
                    # Δεν υπάρχει άλλος socket, οπότε ο χρήστης είναι πλέον offline
                    user.is_online = False
                    user.last_activity = datetime.now()
                    db.session.commit()
                    
                    # Εκπομπή event αποσύνδεσης (για ενημέρωση των άλλων χρηστών)
                    socketio.emit('user_disconnected', {'user_id': user_id}, room=GLOBAL_ROOM)
                    
                    # Εκπομπή system message στο chat
                    save_and_emit_message(user.id, f"{user.display_name} has left the chat.", is_system=True)
                
            leave_room(GLOBAL_ROOM)

    # 🚨 Event: Όταν ένας χρήστης στέλνει μήνυμα
    @socketio.on('send_message')
    def handle_send_message(data):
        user = get_current_user()
        if not user:
            emit('auth_error', {'error': 'Authentication required.'})
            return

        current_user = user # Χρήση του user από το session
        content = data.get('content', '').strip()
        room_name = data.get('room', GLOBAL_ROOM)
        
        # 1. Βασικός έλεγχος περιεχομένου
        if not content or len(content) > 500:
            error_msg = 'Message cannot be empty or too long (Max 500 chars).'
            emit('error_message', {'error': error_msg})
            return

        # 2. Αποθήκευση και εκπομπή
        success = save_and_emit_message(current_user.id, content, room_name)
        
        # 3. Ενημέρωση last_activity
        current_user.last_activity = datetime.now()
        db.session.commit()
        
        if not success:
            emit('error_message', {'error': 'Failed to send message due to server error.'})
            
        # 4. Εκπομπή event για ενημέρωση active state (για να μην φαίνεται ως idle)
        socketio.emit('user_activity', {'user_id': current_user.id}, room=GLOBAL_ROOM)
            
    return app


# --- Τερματικό Σημείο: Εκτέλεση του Server (για local dev) ---

# Αυτό το block είναι μόνο για τοπική εκτέλεση (π.χ. python server.py)
if __name__ == '__main__':
    app = create_app()
    print("Starting Flask-SocketIO server locally...")
    # 🚨 ΟΡΙΖΟΥΜΕ ΤΟ PORT ΝΑ ΠΡΟΕΡΧΕΤΑΙ ΑΠΟ ΤΟ ΠΕΡΙΒΑΛΛΟΝ, με fallback στο 10000
    port = int(os.environ.get('PORT', 10000)) 
    
    # 🚨 Κρίσιμο: Πρέπει να χρησιμοποιούμε eventlet/gunicorn για παραγωγή. 
    # Εδώ απλά τρέχουμε τοπικά με eventlet.
    # Πρέπει να εγκατασταθεί: pip install eventlet
    import eventlet
    eventlet.wsgi.server(eventlet.listen(('', port)), app, log=None)