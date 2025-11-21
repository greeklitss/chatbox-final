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
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user') # 'user', 'admin', 'owner', 'banned'
    display_name = db.Column(db.String(80), nullable=False)
    avatar_url = db.Column(db.String(256), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default='#ffffff')
    is_active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Σχέση με τα μηνύματα
    messages = db.relationship('Message', backref='author', lazy='dynamic')
    
    @validates('email')
    def validate_email(self, key, address):
        """Ελέγχει αν το email είναι έγκυρο και το μετατρέπει σε πεζά."""
        if '@' not in address:
            raise ValueError("Email is not valid.")
        return address.lower()

    def set_password(self, password):
        """Καταχωρεί το hash του κωδικού."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Ελέγχει αν ο κωδικός ταιριάζει με το hash."""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Message(db.Model):
    """Μοντέλο Μηνύματος."""
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    room = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.content[:20]} from {self.user_id} in {self.room}>'

class Setting(db.Model):
    """Μοντέλο για τις ρυθμίσεις του chat (π.χ. ενεργοποίηση/απενεργοποίηση features)."""
    __tablename__ = 'settings'
    key = db.Column(db.String(50), primary_key=True) # π.χ. 'feature_bold', 'max_users'
    value = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Setting {self.key}: {self.value}>'

class Emoticon(db.Model):
    """Μοντέλο για τους emoticons (π.χ. :smile: -> /static/emoticons/smile.gif)."""
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    shortcut = db.Column(db.String(50), unique=True, nullable=False) # π.χ. :smile:
    url = db.Column(db.String(255), nullable=False) # π.χ. /static/emoticons/smile.gif

    def __repr__(self):
        return f'<Emoticon {self.shortcut}: {self.url}>'

# --- Βοηθητικές Συναρτήσεις ---

def initialize_settings():
    """Αρχικοποιεί τις default ρυθμίσεις αν δεν υπάρχουν."""
    default_settings = {
        'feature_bold': 'True',
        'feature_italic': 'True',
        'feature_underline': 'True',
        'feature_img': 'True',
        'max_message_length': '300',
        'default_room': 'general'
    }
    for key, default_value in default_settings.items():
        if not db.session.execute(select(Setting).filter_by(key=key)).scalar_one_or_none():
            db.session.add(Setting(key=key, value=default_value))
    db.session.commit()

def initialize_emoticons():
    """Αρχικοποιεί τα default emoticons αν δεν υπάρχουν."""
    default_emoticons = {
        ':D': '/static/emoticons/happy.gif',
        ':)': '/static/emoticons/smile.gif',
        ':(': '/static/emoticons/sad.gif',
        ':P': '/static/emoticons/tongue.gif',
        ';)': '/static/emoticons/wink.gif',
        'B)': '/static/emoticons/cool.gif'
    }
    for shortcut, url in default_emoticons.items():
        if not db.session.execute(select(Emoticon).filter_by(shortcut=shortcut)).scalar_one_or_none():
            db.session.add(Emoticon(shortcut=shortcut, url=url))
    db.session.commit()

# --- Authorization Decorator ---

def login_required(f):
    """Decorator για τον έλεγχο σύνδεσης."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Αν είναι AJAX/API request, επιστρέφουμε JSON error
            if request.path.startswith('/api/') or request.path.startswith('/check_login'):
                return jsonify({'error': 'Unauthorized', 'message': 'Login required'}), 401
            # Αλλιώς, redirect στο login page
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role_names):
    """Decorator για τον έλεγχο ρόλου."""
    if not isinstance(role_names, list):
        role_names = [role_names]
        
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                return redirect(url_for('login'))
            
            user = db.session.get(User, user_id)
            if not user or user.role not in role_names:
                 # Αν είναι AJAX/API request, επιστρέφουμε JSON error
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Forbidden', 'message': 'Insufficient permissions'}), 403
                # Αλλιώς, redirect στο chat
                return redirect(url_for('chat'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Factory Function για την Δημιουργία της Εφαρμογής ---

def create_app(test_config=None):
    """Factory function για τη δημιουργία και ρύθμιση της Flask εφαρμογής."""
    
    # 2. Αρχικοποίηση Flask App
    app = Flask(__name__, static_folder='static', template_folder='templates')
    
    # Χρήση ProxyFix για σωστή ανάγνωση των headers από το reverse proxy (π.χ. Render)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_prefix=1)

    # 3. Ρυθμίσεις
    # Η χρήση της μεταβλητής περιβάλλοντος DATABASE_URL είναι η προτιμώμενη
    database_url = os.environ.get('DATABASE_URL')
    if database_url and database_url.startswith('postgres://'):
        # SQLAlchemy 2.0+ χρειάζεται postgresql://
        database_url = database_url.replace('postgres://', 'postgresql://', 1)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(16)),
        SQLALCHEMY_DATABASE_URI=database_url or 'sqlite:///local_chat.db',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_TYPE='sqlalchemy',
        SESSION_PERMANENT=True,
        SESSION_USE_SIGNER=True,
        SESSION_KEY_PREFIX='chat_session_',
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        # 🚨 FIX: Ορίζουμε ρητά το όνομα του πίνακα για να αποφύγουμε την επαναδημιουργία
        SESSION_SQLALCHEMY_TABLE='flask_sessions',
        OAUTH_CLIENT_ID=os.environ.get('OAUTH_CLIENT_ID'),
        OAUTH_CLIENT_SECRET=os.environ.get('OAUTH_CLIENT_SECRET'),
        UPLOAD_FOLDER='static/avatars',
        MAX_CONTENT_LENGTH=2 * 1024 * 1024 # 2MB limit for uploads
    )
    
    # Δημιουργία φακέλου uploads αν δεν υπάρχει
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # 4. Αρχικοποίηση Extensions
    db.init_app(app)
    # Θέτουμε το db instance για το Flask-Session
    app.config['SESSION_SQLALCHEMY'] = db
    sess.init_app(app)
    
    oauth.init_app(app)
    # Ρυθμίσεις Google OAuth2
    oauth.register(
        name='google',
        client_id=app.config.get('OAUTH_CLIENT_ID'),
        client_secret=app.config.get('OAUTH_CLIENT_SECRET'),
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params={'scope': 'email profile'},
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'email profile'},
        jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
    )
    
    # 5. Αρχικοποίηση SocketIO
    socketio.init_app(app, 
                      message_queue=os.environ.get('REDIS_URL'), # Χρησιμοποιούμε Redis για scaling αν υπάρχει
                      cors_allowed_origins="*", # Επιτρέπουμε όλους τους origins για απλότητα
                      async_mode='eventlet')
    
    # --- Context Processor για Global Variables (χρησιμοποιείται στο chat.html) ---
    
    @app.context_processor
    def inject_global_data():
        """Προσθέτει ρυθμίσεις και emoticons σε όλα τα templates."""
        settings = {}
        emoticons = {}
        try:
            # Η εκτέλεση της DB query πρέπει να γίνει μέσα σε app context
            for s in db.session.execute(select(Setting)).scalars():
                settings[s.key] = s.value
            
            for e in db.session.execute(select(Emoticon)).scalars():
                emoticons[e.shortcut] = e.url
        except Exception as e:
            # Αυτό μπορεί να συμβεί αν η DB δεν έχει αρχικοποιηθεί ακόμα
            print(f"Warning: Could not load settings/emoticons. DB may not be initialized. Error: {e}")

        # Ανάκτηση ενεργού χρήστη για το navigation bar
        user = None
        if 'user_id' in session:
            try:
                user = db.session.get(User, session['user_id'])
            except Exception as e:
                print(f"Error fetching user in context processor: {e}")
                
        return dict(settings=settings, emoticons=emoticons, user=user)

    # --- Routes (Διαδρομές) ---

    @app.route('/')
    @login_required
    def chat():
        return render_template('chat.html')

    @app.route('/login', methods=['GET'])
    def login():
        # Αν ο χρήστης είναι ήδη συνδεδεμένος, τον στέλνουμε στο chat
        if 'user_id' in session:
            return redirect(url_for('chat'))
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        session.clear()
        return redirect(url_for('login'))
    
    @app.route('/admin')
    @role_required(['admin', 'owner'])
    def admin_panel():
        return render_template('admin_panel.html')
    
    # --- API Routes για Authentication ---
    
    @app.route('/api/v1/sign_up', methods=['POST'])
    def api_sign_up():
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not all([username, email, password]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # 1. Έλεγχος αν υπάρχει ήδη χρήστης
        if db.session.execute(select(User).filter(User.username == username)).scalar_one_or_none():
            return jsonify({'error': 'Username already taken'}), 409
        if db.session.execute(select(User).filter(User.email == email)).scalar_one_or_none():
            return jsonify({'error': 'Email already registered'}), 409
        
        try:
            # 2. Ορισμός ρόλου: Ο πρώτος χρήστης που εγγράφεται γίνεται 'owner'
            is_owner = not db.session.execute(select(User)).first()
            role = 'owner' if is_owner else 'user'

            # 3. Δημιουργία Χρήστη
            new_user = User(
                username=username,
                email=email,
                display_name=username,
                role=role,
                color='#' + ''.join(random.choices('0123456789abcdef', k=6)) # Τυχαίο χρώμα
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            # 4. Αυτόματη σύνδεση μετά την εγγραφή
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            
            return jsonify({'message': 'User created successfully', 'user_id': new_user.id, 'role': role}), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'A user with that username or email already exists'}), 409
        except Exception as e:
            db.session.rollback()
            print(f"Error during sign up: {e}")
            return jsonify({'error': 'Registration failed due to server error'}), 500

    @app.route('/api/v1/login', methods=['POST'])
    def api_login():
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not all([username, password]):
            return jsonify({'error': 'Missing username or password'}), 400

        user = db.session.execute(select(User).filter(User.username == username)).scalar_one_or_none()
        
        if user and user.check_password(password):
            if not user.is_active:
                return jsonify({'error': 'Account is suspended'}), 403
                
            # Ενημέρωση session
            session['user_id'] = user.id
            session['username'] = user.username
            
            # Ενημέρωση last_seen
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            return jsonify({'message': 'Login successful', 'user_id': user.id, 'role': user.role}), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
        
    @app.route('/api/v1/update_profile', methods=['POST'])
    @login_required
    def api_update_profile():
        user_id = session['user_id']
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.json
        display_name = data.get('display_name')
        color = data.get('color')
        
        try:
            if display_name:
                user.display_name = display_name
            if color:
                user.color = color
            
            db.session.commit()
            
            # Ειδοποίηση SocketIO για ενημέρωση σε όλους
            socketio.emit('user_update', {
                'id': user.id,
                'display_name': user.display_name,
                'color': user.color
            }, room='general')

            return jsonify({'message': 'Profile updated successfully', 'display_name': user.display_name, 'color': user.color}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error updating profile: {e}")
            return jsonify({'error': 'Failed to update profile'}), 500

    # --- Google OAuth Routes ---
    
    @app.route('/login/google')
    def google_login():
        redirect_uri = url_for('google_authorize', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    @app.route('/login/google/authorize')
    def google_authorize():
        try:
            token = oauth.google.authorize_access_token()
            user_info = oauth.google.get('userinfo').json()
            
            google_id = user_info['id']
            email = user_info['email']
            display_name = user_info.get('name', email.split('@')[0])
            avatar_url = user_info.get('picture', '/static/default_avatar.png')
            username_prefix = 'google_'
            username = f"{username_prefix}{google_id}"

            # 1. Αναζήτηση χρήστη με Google ID
            user = db.session.execute(select(User).filter(User.username == username)).scalar_one_or_none()

            if user is None:
                # 2. Νέος χρήστης - Εγγραφή
                # Ορισμός ρόλου: Ο πρώτος χρήστης που εγγράφεται γίνεται 'owner'
                is_owner = not db.session.execute(select(User)).first()
                role = 'owner' if is_owner else 'user'
                
                # Δημιουργία τυχαίου, μη χρησιμοποιήσιμου κωδικού (πρέπει να υπάρχει λόγω του model)
                temp_password = secrets.token_urlsafe(32) 

                user = User(
                    id=str(uuid.uuid4()),
                    username=username,
                    email=email,
                    display_name=display_name,
                    avatar_url=avatar_url,
                    role=role,
                    color='#' + ''.join(random.choices('0123456789abcdef', k=6))
                )
                user.set_password(temp_password) # Θέτουμε τον temp κωδικό
                
                db.session.add(user)
                db.session.commit()
                
            # 3. Σύνδεση
            if not user.is_active:
                return "<h1>Access Denied: Your account is suspended.</h1>", 403
                
            session['user_id'] = user.id
            session['username'] = user.username
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            return redirect(url_for('chat'))

        except (MismatchingStateError, OAuthError) as e:
            print(f"OAuth Error: {e}")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"An unexpected error occurred during Google auth: {e}")
            db.session.rollback()
            return "<h1>Server Error during authentication</h1>", 500

    # --- API Routes για Admin Panel ---
    
    @app.route('/check_login')
    @login_required
    def check_login():
        """Ελέγχει αν ο χρήστης είναι συνδεδεμένος και επιστρέφει τα βασικά του στοιχεία."""
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)
        if user:
            return jsonify({'id': user.id, 'role': user.role, 'username': user.username}), 200
        return jsonify({'error': 'Unauthorized'}), 401
    
    @app.route('/api/v1/admin/settings', methods=['GET', 'POST'])
    @role_required(['admin', 'owner'])
    def api_admin_settings():
        if request.method == 'GET':
            settings_list = db.session.execute(select(Setting)).scalars().all()
            settings = {s.key: s.value for s in settings_list}
            return jsonify(settings), 200
        
        elif request.method == 'POST':
            data = request.json
            try:
                for key, value in data.items():
                    setting = db.session.execute(select(Setting).filter_by(key=key)).scalar_one_or_none()
                    if setting:
                        setting.value = str(value)
                    else:
                        db.session.add(Setting(key=key, value=str(value)))
                db.session.commit()
                
                # Ειδοποίηση όλων των συνδεδεμένων χρηστών για ενημέρωση ρυθμίσεων
                settings = {s.key: s.value for s in db.session.execute(select(Setting)).scalars()}
                socketio.emit('settings_update', settings, room='general')
                
                return jsonify({'message': 'Settings updated successfully'}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to update settings: {e}'}), 500

    @app.route('/api/v1/admin/emoticons', methods=['GET', 'POST', 'DELETE'])
    @role_required(['admin', 'owner'])
    def api_admin_emoticons():
        if request.method == 'GET':
            emoticons_list = db.session.execute(select(Emoticon)).scalars().all()
            emoticons = [{'id': e.id, 'shortcut': e.shortcut, 'url': e.url} for e in emoticons_list]
            return jsonify(emoticons), 200
        
        elif request.method == 'POST':
            data = request.json
            shortcut = data.get('shortcut')
            url = data.get('url')
            
            if not shortcut or not url:
                return jsonify({'error': 'Missing shortcut or URL'}), 400
            
            try:
                new_emoticon = Emoticon(shortcut=shortcut, url=url)
                db.session.add(new_emoticon)
                db.session.commit()
                
                # Ειδοποίηση όλων των συνδεδεμένων χρηστών για ενημέρωση emoticons
                emoticons = {e.shortcut: e.url for e in db.session.execute(select(Emoticon)).scalars()}
                socketio.emit('emoticons_update', emoticons, room='general')
                
                return jsonify({'message': 'Emoticon added successfully', 'id': new_emoticon.id}), 201
            except IntegrityError:
                db.session.rollback()
                return jsonify({'error': 'Shortcut already exists'}), 409
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to add emoticon: {e}'}), 500

        elif request.method == 'DELETE':
            emoticon_id = request.json.get('id')
            emoticon = db.session.get(Emoticon, emoticon_id)
            if not emoticon:
                return jsonify({'error': 'Emoticon not found'}), 404
            
            try:
                db.session.delete(emoticon)
                db.session.commit()
                
                # Ειδοποίηση όλων των συνδεδεμένων χρηστών για ενημέρωση emoticons
                emoticons = {e.shortcut: e.url for e in db.session.execute(select(Emoticon)).scalars()}
                socketio.emit('emoticons_update', emoticons, room='general')
                
                return jsonify({'message': 'Emoticon deleted successfully'}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to delete emoticon: {e}'}), 500

    @app.route('/api/v1/admin/users', methods=['GET'])
    @role_required(['admin', 'owner'])
    def api_admin_get_users():
        # Εξαιρούμε τον ρόλο 'owner' από τη λίστα για να μην μπορεί ο admin να τον αλλάξει
        users_list = db.session.execute(select(User).order_by(User.created_at.desc())).scalars().all()
        users_data = []
        for user in users_list:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'display_name': user.display_name,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active,
                'last_seen': user.last_seen.strftime('%Y-%m-%d %H:%M:%S') if user.last_seen else 'Never',
                'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        return jsonify(users_data), 200

    @app.route('/api/v1/admin/users/<user_id>', methods=['PUT'])
    @role_required(['admin', 'owner'])
    def api_admin_update_user(user_id):
        current_user_id = session['user_id']
        current_user = db.session.get(User, current_user_id)
        
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Έλεγχος: Ο Admin δεν μπορεί να αλλάξει τον Owner ή τον εαυτό του σε κάτι άλλο
        if user.role == 'owner' and current_user.role == 'admin':
            return jsonify({'error': 'Admin cannot modify the Owner account'}), 403
        
        if user.id == current_user_id and user.role in ['admin', 'owner']:
             # Επιτρέπουμε μόνο την αλλαγή του is_active για τον εαυτό του
             data = request.json
             if 'is_active' in data:
                 # Επιτρέπουμε μόνο self-deactivation/activation
                 if current_user.role == 'owner' and data.get('is_active') == False:
                     return jsonify({'error': 'The Owner cannot deactivate their own account.'}), 403

                 user.is_active = data['is_active']
                 
                 # Αν ο χρήστης απενεργοποιεί τον εαυτό του, τον αποσυνδέουμε
                 if not data['is_active']:
                     # Σημείωση: Δεν μπορούμε να καλέσουμε logout() άμεσα. Το αφήνουμε για τον επόμενο request.
                     pass 
             else:
                 return jsonify({'error': 'Self-modification is limited to account status.'}), 403
        
        else:
            data = request.json
            
            # Έλεγχος: Ο Admin δεν μπορεί να κάνει Owner άλλον χρήστη
            new_role = data.get('role')
            if current_user.role == 'admin' and new_role == 'owner':
                return jsonify({'error': 'Admin cannot promote users to Owner'}), 403
                
            # Έλεγχος: Αποτροπή αλλαγής ρόλου του Owner
            if user.role == 'owner' and 'role' in data and data['role'] != 'owner':
                 return jsonify({'error': 'Cannot demote the Owner account'}), 403
            
            try:
                if 'role' in data:
                    # Αλλαγή ρόλου
                    allowed_roles = ['user', 'admin', 'banned', 'owner']
                    if data['role'] in allowed_roles:
                        user.role = data['role']
                    else:
                        return jsonify({'error': 'Invalid role specified'}), 400
                    
                if 'is_active' in data:
                    user.is_active = data['is_active']
                    
                db.session.commit()
                
                # Ειδοποίηση SocketIO για ενημέρωση σε όλους
                socketio.emit('user_update', {
                    'id': user.id,
                    'role': user.role,
                    'is_active': user.is_active
                }, room='general')
                
                # Αν ο χρήστης έγινε banned ή ανενεργός, τον ενημερώνουμε και τον αποσυνδέουμε
                if user.role == 'banned' or not user.is_active:
                     # Στέλνουμε ένα μήνυμα αποσύνδεσης στον χρήστη
                     socketio.emit('force_logout', {'reason': f'Your account was set to role: {user.role} or deactivated.'}, room=f"user_{user.id}")

                return jsonify({'message': f'User {user.username} updated successfully'}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to update user: {e}'}), 500

    @app.route('/api/v1/admin/history', methods=['GET'])
    @role_required(['admin', 'owner'])
    def api_admin_history():
        # Παράμετροι σελίδων
        page = request.args.get('page', 1, type=int)
        per_page = 20 # 20 μηνύματα ανά σελίδα
        
        # Query για τα μηνύματα με pagination, τα πιο πρόσφατα πρώτα
        messages_query = db.session.execute(
            select(Message)
            .order_by(Message.timestamp.desc())
        ).scalars().all() # Fetch all for now for simplicity, but proper pagination is better

        # Πολλαπλά fetch για να πάρουμε τα στοιχεία των χρηστών
        # Βρίσκουμε όλα τα user_ids
        user_ids = list(set(m.user_id for m in messages_query))
        
        # Φέρνουμε όλους τους χρήστες με ένα query
        users_map = {
            user.id: {'username': user.username, 'display_name': user.display_name, 'avatar_url': user.avatar_url, 'color': user.color}
            for user in db.session.execute(select(User).where(User.id.in_(user_ids))).scalars()
        }
        
        messages_data = []
        for msg in messages_query:
            user_data = users_map.get(msg.user_id, {})
            messages_data.append({
                'id': msg.id,
                'user_id': msg.user_id,
                'username': user_data.get('username', 'Deleted User'),
                'display_name': user_data.get('display_name', 'Deleted User'),
                'avatar_url': user_data.get('avatar_url', '/static/default_avatar.png'),
                'color': user_data.get('color', '#ffffff'),
                'content': msg.content,
                'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'room': msg.room
            })
            
        # Εφαρμογή pagination μετά το fetch (για την απλοποίηση)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_messages = messages_data[start:end]
        total_messages = len(messages_data)
        
        return jsonify({
            'messages': paginated_messages,
            'total_messages': total_messages,
            'pages': (total_messages + per_page - 1) // per_page,
            'current_page': page
        }), 200

    @app.route('/api/v1/admin/delete_message/<int:message_id>', methods=['DELETE'])
    @role_required(['admin', 'owner'])
    def api_admin_delete_message(message_id):
        msg = db.session.get(Message, message_id)
        if not msg:
            return jsonify({'error': 'Message not found'}), 404
        
        try:
            db.session.delete(msg)
            db.session.commit()
            
            # Ειδοποίηση SocketIO για διαγραφή μηνύματος
            socketio.emit('message_deleted', {'id': message_id}, room=msg.room)
            
            return jsonify({'message': f'Message {message_id} deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete message: {e}'}), 500

    # --- SocketIO Events ---

    # Map για τους online χρήστες: {user_id: {username, room, role}}
    online_users = {}

    def get_online_users_in_room(room_name):
        """Επιστρέφει μια λίστα με τους online χρήστες σε ένα συγκεκριμένο δωμάτιο."""
        return [
            {'id': user_id, 
             'display_name': data['display_name'], 
             'role': data['role'], 
             'color': data['color']}
            for user_id, data in online_users.items() if data['room'] == room_name
        ]

    @socketio.on('connect')
    @login_required
    def handle_connect():
        """Χειρίζεται τη σύνδεση ενός χρήστη."""
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)
        
        if not user or not user.is_active:
            # Στέλνουμε σήμα στον client να αποσυνδεθεί αν δεν είναι έγκυρος ή active
            emit('force_disconnect', {'reason': 'Invalid or inactive session.'})
            return 
        
        # 1. Βρίσκουμε το προτιμώμενο δωμάτιο
        room_name = db.session.execute(select(Setting).filter_by(key='default_room')).scalar_one_or_none()
        room_name = room_name.value if room_name else 'general'
        
        # 2. Είσοδος στο δωμάτιο και στο προσωπικό δωμάτιο
        join_room(room_name)
        join_room(f"user_{user.id}") # Προσωπικό δωμάτιο για notifications/force_logout

        # 3. Ενημέρωση online_users
        is_new_connect = user_id not in online_users
        
        online_users[user_id] = {
            'username': user.username,
            'display_name': user.display_name,
            'role': user.role,
            'color': user.color,
            'room': room_name,
            'sid': request.sid # Αποθηκεύουμε το session ID του SocketIO
        }
        
        # 4. Ενημέρωση last_seen (γίνεται και στο login, αλλά το κάνουμε και εδώ)
        user.last_seen = datetime.utcnow()
        db.session.commit()
        
        # 5. Αποστολή ιστορικού
        messages = db.session.execute(
            select(Message)
            .filter_by(room=room_name)
            .order_by(Message.timestamp.desc())
            .limit(50)
        ).scalars().all()
        
        # Ανάκτηση όλων των user_ids από το ιστορικό για batch fetching
        history_user_ids = list(set(m.user_id for m in messages))
        history_users = db.session.execute(
            select(User)
            .where(User.id.in_(history_user_ids))
        ).scalars().all()
        history_users_map = {u.id: u for u in history_users}
        
        history_data = []
        for msg in reversed(messages):
            msg_user = history_users_map.get(msg.user_id) or user # fallback to current user if not found
            history_data.append({
                'id': msg.id,
                'user_id': msg_user.id,
                'username': msg_user.username,
                'avatar_url': msg_user.avatar_url,
                'color': msg_user.color,
                'content': msg.content,
                'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'room': msg.room
            })
            
        emit('history', {'messages': history_data}, room=f"user_{user.id}")
        
        # 6. Ενημέρωση online λίστας
        online_list = get_online_users_in_room(room_name)
        emit('online_users', online_list, room=room_name)
        
        # 7. System message για νέο χρήστη (μόνο αν είναι νέα σύνδεση)
        if is_new_connect:
             system_message = {
                'id': -1,
                'username': 'System',
                'content': f'{user.display_name} has joined the room: {room_name}.',
                'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
             }
             emit('new_message', system_message, room=room_name)

    @socketio.on('disconnect')
    @login_required
    def handle_disconnect():
        """Χειρίζεται την αποσύνδεση ενός χρήστη."""
        user_id = session.get('user_id')
        if user_id in online_users:
            # 1. Βρίσκουμε το δωμάτιο πριν τη διαγραφή
            room_name = online_users[user_id]['room']
            display_name = online_users[user_id]['display_name']
            
            # 2. Διαγραφή από online_users
            del online_users[user_id]
            
            # 3. System message
            system_message = {
                'id': -1,
                'username': 'System',
                'content': f'{display_name} has left the room: {room_name}.',
                'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
             }
            emit('new_message', system_message, room=room_name)
            
            # 4. Ενημέρωση online λίστας
            online_list = get_online_users_in_room(room_name)
            emit('online_users', online_list, room=room_name)

    @socketio.on('send_message')
    @login_required
    def handle_send_message(data):
        """Χειρίζεται την αποστολή νέου μηνύματος."""
        user_id = session.get('user_id')
        current_user = db.session.get(User, user_id)
        room_name = online_users.get(user_id, {}).get('room', 'general')
        content = data.get('content', '').strip()
        
        # Έλεγχοι
        if not content:
            emit('error_message', {'error': 'Message content cannot be empty.'}, room=f"user_{current_user.id}")
            return
        
        max_length_setting = db.session.execute(select(Setting).filter_by(key='max_message_length')).scalar_one_or_none()
        max_length = int(max_length_setting.value) if max_length_setting and max_length_setting.value.isdigit() else 300
        
        if len(content) > max_length:
            emit('error_message', {'error': f'Message exceeds maximum length of {max_length} characters.'}, room=f"user_{current_user.id}")
            return
        
        if current_user and current_user.is_active:
            try:
                new_message = Message(
                    user_id=current_user.id,
                    room=room_name,
                    content=content,
                    timestamp=datetime.utcnow()
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
    # Χρησιμοποιούμε eventlet για asynchronous I/O
    socketio.run(app, host='0.0.0.0', port=port, debug=True)