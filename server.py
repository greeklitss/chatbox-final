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
from flask import jsonify, url_for, request, current_app 
# 🚨 ΣΗΜΕΙΩΣΗ: Προσθήκη current_app εδώ για χρήση σε helper functions

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import select, desc, func
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates

# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app (Global Scope)
db = SQLAlchemy()
sess = Session()
oauth = OAuth()
socketio = SocketIO()

# ----------------------------------------------------
# --- MODELS (Πρέπει να είναι στο Global Scope για import από db_init.py) ---
# ----------------------------------------------------

def generate_random_color():
    """Generates a random hex color."""
    return f"#{secrets.token_hex(3)}"

def generate_random_password(length=12):
    """Generates a secure, random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(500), nullable=False)
    role = db.Column(db.String(20), default='guest')
    avatar_url = db.Column(db.String(200), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default=generate_random_color)
    is_google_user = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='author', lazy=True)

    @validates('role')
    def validate_role(self, key, role):
        if role not in ['guest', 'user', 'admin', 'owner']:
            raise ValueError("Invalid role assigned.")
        return role

    def __init__(self, username, email, display_name=None, role='guest', avatar_url=None, color=None, is_google_user=False):
        self.username = username
        self.email = email
        self.role = role
        self.display_name = display_name or username
        self.avatar_url = avatar_url or '/static/default_avatar.png'
        self.color = color or generate_random_color()
        self.is_google_user = is_google_user

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    room = db.Column(db.String(50), default='main')
    system_message = db.Column(db.Boolean, default=False)

class Setting(db.Model): # ΣΩΣΤΟ ΟΝΟΜΑ: Setting (ενικός)
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    is_boolean = db.Column(db.Boolean, default=True)

class Emoticon(db.Model):
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    url = db.Column(db.String(200), nullable=False)

# 💥 ΝΕΟ ΜΟΝΤΕΛΟ: Χειροκίνητος ορισμός του μοντέλου Session για το Flask-Session
class Session(db.Model):
    # CRITICAL FIX: Setting extend_existing=True allows the model to be loaded 
    # multiple times without the InvalidRequestError.
    __tablename__ = 'flask_sessions'
    __table_args__ = {'extend_existing': True} 

    id = db.Column(db.String(256), primary_key=True)
    data = db.Column(db.LargeBinary)
    expiry = db.Column(db.DateTime, nullable=False)

    def __init__(self, sid, data, expiry):
        self.id = sid
        self.data = data
        self.expiry = expiry

    def __repr__(self):
        return f"<Session {self.id}>"


# ----------------------------------------------------
# --- HELPER FUNCTIONS & DECORATORS (Global Scope) ---
# ----------------------------------------------------

def get_current_user():
    """Returns the current User object or None."""
    user_id = session.get('user_id')
    # Χρησιμοποιούμε current_app.app_context() για να έχουμε πρόσβαση στη βάση
    if user_id and current_app:
        with current_app.app_context():
            return db.session.scalar(select(User).filter_by(id=user_id))
    return None

def allowed_file(filename):
    """Checks if a file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def initialize_settings():
    default_settings = {
        'feature_bold': ('True', 'Enable **bold** formatting', True),
        'feature_italic': ('True', 'Enable *italic* formatting', True),
        'feature_underline': ('True', 'Enable __underline__ formatting', True),
        'feature_strike': ('True', 'Enable ~~strike~~ formatting', True),
        'feature_color': ('True', 'Enable [color=...] formatting', True),
        'feature_link': ('True', 'Enable [url=...] links', True),
        'feature_image': ('True', 'Enable [img]...[/img] tags', True),
        'feature_emoticons': ('True', 'Enable emoticon replacement', True),
        'chat_history_limit': ('100', 'Max number of messages to load on connect', False),
        'max_message_length': ('500', 'Max characters per message', False),
        'guest_mode_enabled': ('True', 'Allow unauthenticated guests to chat', True),
        'signup_enabled': ('True', 'Allow new users to register locally', True)
    }
    
    for key, (default_value, description, is_boolean) in default_settings.items():
        if not db.session.scalar(select(Setting).filter_by(key=key)):
            new_setting = Setting(key=key, value=default_value, description=description, is_boolean=is_boolean)
            db.session.add(new_setting)
    
    try:
        db.session.commit()
    except Exception as e:
        print(f"Error initializing settings: {e}")
        db.session.rollback()

def initialize_emoticons():
    default_emoticons = {
        ':D': '/static/emoticons/happy.gif',
        ':)': '/static/emoticons/smile.gif',
        ';)': '/static/emoticons/wink.gif',
        ':(': '/static/emoticons/sad.gif',
        ':love:': '/static/emoticons/love.gif',
        ':lol:': '/static/emoticons/lol.gif',
        ':p': '/static/emoticons/tongue.gif',
        ':cool:': '/static/emoticons/cool.gif',
        ':o': '/static/emoticons/surprise.gif',
        ':angry:': '/static/emoticons/angry.gif',
    }

    for code, url in default_emoticons.items():
        if not db.session.scalar(select(Emoticon).filter_by(code=code)):
            new_emoticon = Emoticon(code=code, url=url)
            db.session.add(new_emoticon)

    try:
        db.session.commit()
    except Exception as e:
        print(f"Error initializing emoticons: {e}")
        db.session.rollback()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith('/api'):
                 return jsonify({'error': 'Login required'}), 401
            # Χρησιμοποιεί το url_for του Flask που είναι διαθέσιμο όταν καλείται η ρουτίνα
            return redirect(url_for('login', next=request.url)) 
        return f(*args, **kwargs)
    return decorated_function

def setup_app_on_startup():
    """Ελέγχει και δημιουργεί φακέλους, ρυθμίσεις και τον Owner χρήστη. Εκτελείται μόνο μία φορά."""
    
    upload_folder = current_app.config['UPLOAD_FOLDER']
    
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
        print(f"Created upload folder: {upload_folder}")
        
    with current_app.app_context():
        try:
            db.create_all() 
            print("Database tables ensured.")
            
            initialize_settings()
            initialize_emoticons()
            print("Settings and Emoticons initialized.")
            
            owner_username = os.environ.get('OWNER_USERNAME')
            owner_email = os.environ.get('OWNER_EMAIL')
            owner_password = os.environ.get('OWNER_PASSWORD')
            
            if owner_username and owner_email:
                owner_exists = db.session.scalar(
                    select(User).filter_by(role='owner')
                )
                
                if not owner_exists:
                    if not owner_password:
                        owner_password = generate_random_password() 
                        print("⚠️ WARNING: OWNER_PASSWORD not set. Using a random password (check logs!).")

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
                    print(f"✅ Created default Owner user: {owner_username}.")
                else:
                    print("Default Owner user already exists.")
            else:
                print("Owner user check completed.")
            
        except ProgrammingError as e:
             print(f"SQLAlchemy Programming Error during setup: {e}. If this is a new Postgres setup, ensure the database is accessible.")
        except Exception as e:
             print(f"An unexpected error occurred during DB setup: {e}")


# ----------------------------------------------------
# --- Flask Application Factory ---
# ----------------------------------------------------

def create_app():
    """Δημιουργεί και ρυθμίζει την Flask εφαρμογή."""
    app = Flask(__name__)

    # --- CONFIGURATION & EXTENSIONS INIT ---
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_prefix=1, x_port=1, x_proto=1)

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(24)
    
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///chatbox.db')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
        
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions'
    app.config['SESSION_SQLALCHEMY_MODEL'] = Session # 🚨 ΝΕΑ ΡΥΘΜΙΣΗ: Χρήση του χειροκίνητα ορισμένου μοντέλου Session
    
    app.config['UPLOAD_FOLDER'] = 'uploads'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    # --- INITIALIZE EXTENSIONS (ΣΩΣΤΗ ΣΕΙΡΑ) ---
    db.init_app(app) 
    if app.config.get('SESSION_TYPE') == 'sqlalchemy':
        app.config['SESSION_SQLALCHEMY'] = db 
    sess.init_app(app) 
    
    # 💥 ΑΦΑΙΡΕΘΗΚΕ: Ο κώδικας για το SessionModel fix (τώρα είναι ενσωματωμένος στο μοντέλο)

    socketio.init_app(app, manage_session=False, cors_allowed_origins="*")
    oauth.init_app(app)

    # --- OAuth Configuration (Google) ---
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )
    
    # 💥 ΚΡΙΣΙΜΟ: ΟΛΕΣ ΟΙ ROUTE ΚΑΙ SOCKETIO ΣΥΝΑΡΤΗΣΕΙΣ ΜΠΑΙΝΟΥΝ ΕΔΩ
    
    # --- ROUTES ---

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Renders the login/signup page."""
        if get_current_user():
            return redirect(url_for('chat'))
            
        return render_template('login.html', google_client_id=app.config.get('GOOGLE_CLIENT_ID'))


    @app.route('/api/v1/sign_up', methods=['POST'])
    def sign_up():
        """Handles local user registration."""
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        with app.app_context():
            signup_setting = db.session.scalar(select(Setting).filter_by(key='signup_enabled'))
            if signup_setting and signup_setting.value == 'False':
                return jsonify({'error': 'Registration is currently disabled.'}), 403

            existing_user = db.session.scalar(select(User).filter((User.display_name == username) | (User.email == email)))
            if existing_user:
                return jsonify({'error': 'Username or Email already exists.'}), 409

            try:
                user_count = db.session.scalar(select(func.count()).select_from(User)) 
            except Exception:
                user_count = 0 
                
            if user_count == 0:
                role = 'owner'
            else:
                role = 'user' 
                
            try:
                new_user = User(username=username, email=email, role=role)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                
                session['user_id'] = new_user.id
                session['username'] = new_user.display_name
                session['role'] = new_user.role
                
                return jsonify({
                    'message': 'Registration successful and logged in.',
                    'redirect_url': url_for('chat')
                }), 200

            except IntegrityError:
                db.session.rollback()
                return jsonify({'error': 'Username or email already in use.'}), 409
            except Exception as e:
                db.session.rollback()
                print(f"Sign up error: {e}")
                return jsonify({'error': 'An unexpected error occurred.'}), 500


    @app.route('/api/v1/login', methods=['POST'])
    def handle_login():
        """Handles local user login."""
        data = request.get_json()
        username_or_email = data.get('username_or_email')
        password = data.get('password')

        with app.app_context():
            user = db.session.scalar(
                select(User).filter(
                    (User.display_name == username_or_email) | (User.email == username_or_email)
               ) 
            )
            
            if user and user.password_hash and user.check_password(password):
                session.permanent = True 
                session['user_id'] = user.id
                session['username'] = user.display_name 
                session['role'] = user.role
                
                return jsonify({
                    'message': 'Login successful.',
                    'redirect_url': url_for('chat')
                }), 200
            else:
                return jsonify({'error': 'Invalid credentials.'}), 401


    @app.route('/logout')
    def logout():
        """Handles user logout."""
        if 'user_id' in session:
            session.pop('user_id', None)
        if 'username' in session:
            session.pop('username', None)
        if 'role' in session:
            session.pop('role', None)
        
        session.pop('google_token', None)
        
        return redirect(url_for('login'))


    @app.route('/guest_login', methods=['GET', 'POST'])
    def guest_login():
        """Allows a user to join as a guest."""
        with app.app_context():
            guest_setting = db.session.scalar(select(Setting).filter_by(key='guest_mode_enabled'))
            if guest_setting and guest_setting.value == 'False':
                return redirect(url_for('login'))

            guest_id = str(uuid.uuid4())[:8]
            username = f"Guest-{guest_id}"
            
            try:
                guest_user = User(
                    username=username, 
                    email=f"guest_{guest_id}@temporary.com", 
                    role='guest',
                )
                db.session.add(guest_user)
                db.session.commit()
                
                session.permanent = False 
                session['user_id'] = guest_user.id
                session['username'] = guest_user.display_name
                session['role'] = 'guest'
                
                return redirect(url_for('chat'))
                
            except IntegrityError:
                db.session.rollback()
                return redirect(url_for('login'))
            except Exception as e:
                print(f"Guest login error: {e}")
                return redirect(url_for('login'))


    @app.route('/google_login')
    def google_login():
        """Redirects user to Google for OAuth."""
        redirect_uri = url_for('google_callback', _external=True)
        return google.authorize_redirect(redirect_uri)


    @app.route('/google_callback')
    def google_callback():
        try:
            token = oauth.google.authorize_access_token()
            
            if token is None:
                return redirect(url_for('login', error='Google login failed: Authorization failed or token expired.'))
                
            id_token_string = token.get('id_token')
            
            if not id_token_string:
                return redirect(url_for('login', error='Google login failed: ID token not found.'))
                
            nonce = session.pop(f'_authlib_oauth_nonce_{oauth.google.name}', None)
            user_info = oauth.google.parse_id_token(id_token_string, nonce=nonce)
            
            email = user_info.get('email')
            
            if not email:
                return redirect(url_for('login', error='Google login failed: No email provided.'))
            
            user = db.session.scalar(select(User).filter_by(email=email))
            
            if not user:
                base_display_name = user_info.get('name') or email.split('@')[0]
                current_display_name = base_display_name
                suffix = 1
                
                while db.session.scalar(select(User).filter_by(display_name=current_display_name)):
                    current_display_name = f"{base_display_name}_{suffix}"
                    suffix += 1

                new_user = User(
                    username=email, 
                    display_name=current_display_name, 
                    email=email,
                    role='user', 
                    is_google_user=True,
                    avatar_url=user_info.get('picture', '/static/default_avatar.png'),
                    color=generate_random_color()
                )
                new_user.set_password(generate_random_password()) 
                
                db.session.add(new_user)
                db.session.commit()
                user = new_user

            session.permanent = True
            session['user_id'] = user.id 
            session['username'] = user.display_name 
            session['role'] = user.role
            session['is_google_user'] = user.is_google_user
            
            return redirect(url_for('chat'))

        except MismatchingStateError:
            print("Mismatching State Error during Google login.")
            return redirect(url_for('login', error='Session expired or state mismatch. Please try logging in again.'))

        except Exception as e:
            db.session.rollback()
            print(f"FATAL ERROR IN GOOGLE CALLBACK: {e}") 
            return redirect(url_for('login', error='An unexpected error occurred during Google sign-in.'))


    @app.route('/')
    @login_required
    def chat():
        """Main chat page. Requires login."""
        user = get_current_user()
        
        settings_list = db.session.scalars(select(Setting)).all()
        settings_map = {s.key: s.value for s in settings_list}
        
        emoticons_list = db.session.scalars(select(Emoticon)).all()
        emoticons_map = {e.code: e.url for e in emoticons_list}
        
        limit = int(settings_map.get('chat_history_limit', 100))
        messages_query = select(Message).order_by(desc(Message.timestamp)).limit(limit)
        raw_messages = db.session.scalars(messages_query).all()
        messages = list(reversed(raw_messages)) 
        
        user_ids = list(set(m.user_id for m in messages))
        if user_ids:
            users_query = select(User).filter(User.id.in_(user_ids))
            message_users = db.session.scalars(users_query).all()
            user_map = {u.id: {'username': u.username, 'color': u.color, 'role': u.role, 'avatar_url': u.avatar_url, 'display_name': u.display_name} for u in message_users}
        else:
            user_map = {}

        chat_history = []
        for m in messages:
            user_data = user_map.get(m.user_id, {})
            chat_history.append({
                'id': m.id,
                'user_id': m.user_id,
                'username': user_data.get('username', 'Unknown'),
                'display_name': user_data.get('display_name', 'Unknown'),
                'role': user_data.get('role', 'guest'),
                'color': user_data.get('color', '#ffffff'),
                'avatar_url': user_data.get('avatar_url', '/static/default_avatar.png'),
                'content': m.content,
                'timestamp': m.timestamp.isoformat(),
                'system_message': m.system_message
            })
            
        return render_template(
            'chat.html', 
            user=user, 
            settings=settings_map, 
            emoticons=emoticons_map, 
            chat_history=chat_history
        )


    @app.route('/admin')
    @login_required
    def admin_panel():
        """Admin panel page. Requires admin or owner role."""
        user = get_current_user()
        if user and user.role in ['admin', 'owner']:
            return render_template('admin_panel.html', user=user)
        else:
            return redirect(url_for('chat'))


    @app.route('/check_login')
    def check_login():
        """API endpoint to check if user is logged in (used by JS)."""
        user = get_current_user()
        if user:
            return jsonify({
                'id': user.id,
                'username': user.display_name, 
                'display_name': user.display_name,
                'role': user.role,
                'color': user.color,
                'avatar_url': user.avatar_url
            }), 200
        else:
            return jsonify({'error': 'Not logged in'}), 401


    # --- UPLOAD ROUTE (για εικόνες) ---
    @app.route('/upload', methods=['POST'])
    @login_required
    def upload_file():
        user = get_current_user()
        if not user or user.role == 'guest':
            return jsonify({'error': 'Login required or Guests cannot upload.'}), 401

        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        # Εδώ το allowed_file χρησιμοποιεί το current_app.config
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            new_filename = f"{uuid.uuid4().hex}.{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            
            try:
                file.save(filepath)
                
                file_url = url_for('uploaded_file', filename=new_filename, _external=True)
                
                bbcode_content = f'[img]{file_url}[/img]'
                
                new_message = Message(
                    user_id=user.id,
                    content=bbcode_content,
                    system_message=False,
                    room='main' 
                )
                db.session.add(new_message)
                db.session.commit()
                
                socketio.emit('message', {
                    'id': new_message.id,
                    'user_id': user.id,
                    'username': user.display_name, 
                    'display_name': user.display_name,
                    'role': user.role,
                    'color': user.color,
                    'avatar_url': user.avatar_url,
                    'content': bbcode_content,
                    'timestamp': new_message.timestamp.isoformat(),
                    'system_message': False
                }, room='main', namespace='/')
                
                return jsonify({'url': file_url, 'bbcode': bbcode_content}), 200
            
            except Exception as e:
                print(f"File upload/save error: {e}")
                return jsonify({'error': f'Server error during file save: {e}'}), 500

        else:
            return jsonify({'error': 'File type not allowed'}), 400

    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        """Serves uploaded files from the /uploads folder."""
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


    # --- SOCKETIO EVENTS ---
    @socketio.on('connect')
    def handle_connect():
        user = get_current_user()
        if user:
            join_room('main')
            print(f"User {user.display_name} connected and joined room 'main'.")
        else:
            print("Unauthenticated user connected.")

    @socketio.on('disconnect')
    def handle_disconnect():
        user = get_current_user()
        if user:
            leave_room('main')
            print(f"User {user.display_name} disconnected.")
        else:
            print("Unauthenticated user disconnected.")

    @socketio.on('send_message')
    @login_required
    def handle_send_message(data):
        user = get_current_user()
        if not user:
            return 

        message_content = data.get('content', '').strip()
        room = data.get('room', 'main')

        if not message_content:
            return

        with current_app.app_context():
            max_len_setting = db.session.scalar(select(Setting).filter_by(key='max_message_length'))
            max_len = int(max_len_setting.value) if max_len_setting else 500
            
            if len(message_content) > max_len:
                emit('error_message', {'message': f'Message exceeds maximum length of {max_len} characters.'})
                return

            new_message = Message(
                user_id=user.id,
                content=message_content,
                system_message=False,
                room=room
            )
            db.session.add(new_message)
            db.session.commit()

            emit('message', {
                'id': new_message.id,
                'user_id': user.id,
                'username': user.display_name,
                'display_name': user.display_name,
                'role': user.role,
                'color': user.color,
                'avatar_url': user.avatar_url,
                'content': message_content,
                'timestamp': new_message.timestamp.isoformat(),
                'system_message': False
            }, room=room)
    
    return app


# ----------------------------------------------------
# --- Τερματικό Σημείο: Εκτέλεση & Deployment ---
# ----------------------------------------------------

# Δημιουργία του instance της εφαρμογής (Αυτό θα φορτωθεί από το Gunicorn/Render)
app = create_app()

# Καλούμε το setup ΜΟΝΟ μια φορά όταν η εφαρμογή είναι έτοιμη
with app.app_context():
    setup_app_on_startup() 

if __name__ == '__main__':
    print("Starting Flask-SocketIO server...")
    socketio.run(app, debug=True, port=int(os.environ.get('PORT', 5000)))