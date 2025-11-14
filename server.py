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
from flask import jsonify, url_for, request # Βεβαιωθείτε ότι έχετε εισάγει τα jsonify, url_for, request

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


# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app
db = SQLAlchemy()
sess = Session()
oauth = OAuth()


# --- Ρυθμίσεις Εφαρμογής & Flask App ---
app = Flask(__name__)
# 🚨 ΚΡΙΣΙΜΗ ΠΡΟΣΘΗΚΗ: ΕΦΑΡΜΟΓΗ PROXYFIX για το Render
app.wsgi_app = ProxyFix(app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# --- ΚΛΕΙΔΙΑ & ΡΥΘΜΙΣΕΙΣ (ΑΠΟ ENVIRONMENT VARIABLES) ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(24))
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 Megabytes max upload size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'svg'}

# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

# Owner/Admin Configuration (Defaults to avoid errors if missing)
OWNER_USERNAME = os.environ.get('OWNER_USERNAME', 'owner')
OWNER_EMAIL = os.environ.get('OWNER_EMAIL', 'owner@chatbox.com')
OWNER_PASSWORD = os.environ.get('OWNER_PASSWORD', secrets.token_urlsafe(16)) 


# 🚨 2. Συνδέουμε τα extensions με το app
# --- ΑΝΑΔΙΑΤΑΞΗ ΓΙΑ ΔΙΟΡΘΩΣΗ FLASK-SESSION/SQLALCHEMY ---
# 1. Συνδέουμε το SQLAlchemy (db) πρώτο.
db.init_app(app) 
# 2. Αφού συνδέθηκε το db, ορίζουμε το SESSION_SQLALCHEMY.
app.config['SESSION_SQLALCHEMY'] = db
# 3. Συνδέουμε το Session (sess).
sess.init_app(app) 
# 4. Συνδέουμε το OAuth.
oauth.init_app(app)

# --- SOCKETIO --
socketio = SocketIO(
    app, 
    manage_session=False, 
    cors_allowed_origins="*" 
)

# --- ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ (SQLAlchemy Models) ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True) # Allow null for OAuth
    password_hash = db.Column(db.String(128), nullable=True) # Allow null for OAuth
    role = db.Column(db.String(20), default='user') # 'user', 'moderator', 'admin', 'owner'
    is_active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    color = db.Column(db.String(7), nullable=False)
    avatar_url = db.Column(db.String(255), nullable=False, default='/static/default_avatar.png')
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    
    messages = db.relationship('Message', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    room = db.Column(db.String(50), default='general') 
    
class Setting(db.Model):
    __tablename__ = 'settings'
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(255))
    is_boolean = db.Column(db.Boolean, default=False)
    
class Emoticon(db.Model):
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), unique=True, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


# --- ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ ---

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_random_color():
    return '#' + ''.join(random.choices(string.hexdigits.upper(), k=6))

def requires_auth(f):
    """Decorator για να διασφαλιστεί ότι ο χρήστης είναι συνδεδεμένος."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 🚨 Η σύνδεση αποτυγχάνει εδώ αν το session χάνεται (π.χ. λόγω DB)
        if 'user_id' not in session:
            return redirect(url_for('login_page', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# (Οι υπόλοιπες βοηθητικές συναρτήσεις παραμένουν ίδιες)
# ...

def initialize_settings():
    """Διασφαλίζει ότι οι βασικές ρυθμίσεις υπάρχουν στη βάση."""
    default_settings = {
        'CHAT_ENABLED': {'value': 'True', 'description': 'Enable or disable the main chat function.', 'is_boolean': True},
        'REGISTRATION_ENABLED': {'value': 'True', 'description': 'Allow new users to register.', 'is_boolean': True},
        'MAX_MESSAGE_LENGTH': {'value': '500', 'description': 'Maximum number of characters allowed per message.', 'is_boolean': False},
        'ROOM_CREATION_ENABLED': {'value': 'True', 'description': 'Allow regular users to create new chat rooms.', 'is_boolean': True},
    }
    
    for key, data in default_settings.items():
        setting = db.session.execute(select(Setting).filter_by(key=key)).scalar_one_or_none()
        
        if not setting:
            new_setting = Setting(
                key=key, 
                value=data['value'], 
                description=data['description'], 
                is_boolean=data['is_boolean']
            )
            db.session.add(new_setting)
            print(f"Added new setting: {key}")
            
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        print("IntegrityError: Settings already exist. Rolled back.")
        
def get_setting(key, default=None):
    """Λαμβάνει μια ρύθμιση από τη βάση δεδομένων."""
    setting = db.session.execute(select(Setting).filter_by(key=key)).scalar_one_or_none()
    if setting:
        if setting.is_boolean:
            return setting.value.lower() == 'true'
        return setting.value
    return default

def initialize_emoticons():
    """Διασφαλίζει ότι τα βασικά emoticons υπάρχουν."""
    default_emoticons = {
        ':D': '/static/emoticons/happy.png',
        ':)': '/static/emoticons/smile.png',
        ':(': '/static/emoticons/sad.png',
        ';)': '/static/emoticons/wink.png',
        ':P': '/static/emoticons/tongue.png',
        '</3': '/static/emoticons/broken_heart.png',
    }

    for code, url in default_emoticons.items():
        emoticon = db.session.execute(select(Emoticon).filter_by(code=code)).scalar_one_or_none()
        
        if not emoticon:
            new_emoticon = Emoticon(code=code, image_url=url, is_active=True)
            db.session.add(new_emoticon)
            print(f"Added new emoticon: {code}")

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        print("IntegrityError: Emoticons already exist. Rolled back.")
        
def requires_role(required_role):
    """Decorator για έλεγχο ρόλου."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login_page', next=request.url))
            
            user = db.session.get(User, session['user_id'])
            if not user or user.role != required_role:
                return jsonify({'error': 'Permission denied'}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- ROUTES/VIEW FUNCTIONS ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    # Εάν η εφαρμογή είναι σε λειτουργία συντήρησης και η εγγραφή είναι απενεργοποιημένη, 
    # μπορεί να χρειαστεί να εμφανιστεί μήνυμα (αλλά αφήνουμε τον χρήστη να δοκιμάσει login)
    return render_template('login.html')

@app.route('/chat')
@requires_auth
def chat_page():
    if not get_setting('CHAT_ENABLED', True):
        return render_template('maintenance.html', message="Chat is currently disabled by the administrator.")

    user = db.session.get(User, session['user_id'])
    
    emoticons_results = db.session.execute(select(Emoticon).where(Emoticon.is_active == True)).scalars().all()
    emoticons_data = {e.code: url_for('static', filename=e.image_url.split('/')[-1]) for e in emoticons_results}

    return render_template('chat.html', user=user, emoticons=emoticons_data)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


# --- API ROUTES ---

@app.route('/api/v1/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = db.session.execute(select(User).filter_by(username=username)).scalar_one_or_none()

    if user and user.check_password(password):
        # 🚨 Η επιτυχής σύνδεση ΕΔΩ θα αποθηκεύσει τη συνεδρία στο DB
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        # Αν η αποθήκευση του session αποτύχει, το requires_auth θα ανακατευθύνει πίσω στο login_page
        return jsonify({'message': 'Login successful', 'redirect': url_for('chat_page')}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401
# (Οι υπόλοιπες API routes παραμένουν ίδιες)
# ...

@app.route('/api/v1/sign_up', methods=['POST'])
def api_sign_up():
    if not get_setting('REGISTRATION_ENABLED', True):
         return jsonify({'error': 'Registration is currently disabled.'}), 403

    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    if len(username) < 3 or len(password) < 6:
        return jsonify({'error': 'Username must be at least 3 chars, password 6 chars.'}), 400

    if db.session.execute(select(User).filter_by(username=username)).first():
        return jsonify({'error': 'Username already taken'}), 409

    if email and db.session.execute(select(User).filter_by(email=email)).first():
        return jsonify({'error': 'Email already registered'}), 409
        
    try:
        new_user = User(
            username=username,
            email=email if email else None,
            role='user',
            avatar_url='/static/default_avatar.png',
            color=generate_random_color()
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/api/v1/messages/<string:room>', methods=['GET'])
@requires_auth
def get_messages(room):
    messages_query = db.session.execute(
        select(Message)
        .filter_by(room=room)
        .order_by(desc(Message.timestamp))
        .limit(50)
    ).scalars().all()
    
    messages = messages_query[::-1]

    message_list = []
    for msg in messages:
        user = db.session.get(User, msg.user_id)
        if user:
            message_list.append({
                'id': msg.id,
                'username': user.username,
                'content': msg.content,
                'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'color': user.color
            })
    
    return jsonify(message_list), 200

# --- GOOGLE OAUTH ROUTES ---
GOOGLE_CONF = {
    'client_id': app.config['GOOGLE_CLIENT_ID'],
    'client_secret': app.config['GOOGLE_CLIENT_SECRET'],
    'api_base_url': 'https://www.googleapis.com/oauth2/v1/',
    'server_metadata_url': 'https://accounts.google.com/.well-known/openid-configuration',
    'client_kwargs': {'scope': 'openid email profile'},
}
oauth.register('google', **GOOGLE_CONF)

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/login/google/callback')
def authorize_google():
    try:
        token = oauth.google.authorize_access_token()
    except (MismatchingStateError, OAuthError) as e:
        print(f"OAuth Error during callback: {e}")
        return redirect(url_for('login_page'))
    
    user_info = oauth.google.get('userinfo', token=token).json()
    
    google_id = user_info.get('id')
    email = user_info.get('email')
    username = user_info.get('name')
    avatar_url = user_info.get('picture', '/static/default_avatar.png')

    user = db.session.execute(select(User).filter_by(google_id=google_id)).scalar_one_or_none()
    
    if not user:
        user = db.session.execute(select(User).filter_by(email=email)).scalar_one_or_none()
        
        if user:
            user.google_id = google_id
            db.session.commit()
            print(f"Linked Google ID to existing user: {user.username}")
        else:
            new_user = User(
                username=username,
                email=email,
                google_id=google_id,
                role='user',
                avatar_url=avatar_url,
                color=generate_random_color()
            )
            db.session.add(new_user)
            db.session.commit()
            user = new_user
            print(f"Created new user via Google: {user.username}")

    session.clear()
    session['user_id'] = user.id
    session['username'] = user.username
    
    return redirect(url_for('chat_page'))

# --- SOCKETIO EVENT HANDLERS (Παραμένουν ίδια) ---
# ...

@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        print("Unauthenticated user tried to connect to socket.")
        return False  

    user_id = session['user_id']
    user = db.session.get(User, user_id)
    if user:
        user.is_online = True
        user.last_seen = datetime.now(timezone.utc)
        db.session.commit()
        
        join_room('general')
        
        emit('user_status_change', {'username': user.username, 'is_online': True}, broadcast=True)
        print(f"User connected: {user.username} (ID: {user_id})")
        
    else:
        return False

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user_id = session['user_id']
        user = db.session.get(User, user_id)
        if user:
            user.is_online = False
            user.last_seen = datetime.now(timezone.utc)
            db.session.commit()
            
            emit('user_status_change', {'username': user.username, 'is_online': False}, broadcast=True)
            print(f"User disconnected: {user.username} (ID: {user_id})")

@socketio.on('send_message')
@requires_auth
def handle_send_message(data):
    user_id = session['user_id']
    content = data.get('content', '').strip()
    room = data.get('room', 'general')
    
    if not get_setting('CHAT_ENABLED', True):
        return emit('error_message', {'message': 'Chat is disabled.'})

    max_len = int(get_setting('MAX_MESSAGE_LENGTH', 500))
    if len(content) > max_len:
         return emit('error_message', {'message': f'Message exceeds maximum length of {max_len} characters.'})

    if content:
        user = db.session.get(User, user_id)
        if user:
            new_message = Message(user_id=user.id, content=content, room=room)
            db.session.add(new_message)
            db.session.commit()
            
            emoticons = db.session.execute(select(Emoticon).where(Emoticon.is_active == True)).scalars().all()
            
            processed_content = content
            for emo in emoticons:
                img_path = url_for('static', filename=emo.image_url.split('/')[-1])
                img_tag = f'<img src="{img_path}" alt="{emo.code}" class="emoticon">'
                processed_content = processed_content.replace(emo.code, img_tag)

            message_data = {
                'username': user.username,
                'content': processed_content,
                'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'color': user.color
            }
            emit('new_message', message_data, room=room)


# --- ΤΕΛΙΚΟΣ ΕΛΕΓΧΟΣ ΔΗΜΙΟΥΡΓΙΑΣ ΦΑΚΕΛΩΝ & ΕΚΤΕΛΕΣΗ SERVER ---

def setup_app_on_startup():
    """Ελέγχει και δημιουργεί φακέλους. Εκτελείται μόνο μία φορά."""
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        print(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
        
    with app.app_context():
        try:
            # Δημιουργία πινάκων (θα τους δημιουργήσει μόνο αν δεν υπάρχουν)
            # Αυτό περιλαμβάνει τον πίνακα flask_sessions για το session persistence
            db.create_all() 
            print("Database tables ensured.")
            
            initialize_settings()
            initialize_emoticons()
            print("Settings and Emoticons initialized.")
            
            # Δημιουργία Owner χρήστη αν δεν υπάρχει
            owner_user = db.session.execute(select(User).filter_by(role='owner')).scalar_one_or_none()

            if not owner_user:
                if not db.session.execute(select(User).filter_by(username=OWNER_USERNAME)).scalar_one_or_none():
                    default_owner = User(
                        username=OWNER_USERNAME,
                        email=OWNER_EMAIL,
                        role='owner',
                        avatar_url='/static/default_avatar.png',
                        color=generate_random_color()
                    )
                    default_owner.set_password(OWNER_PASSWORD)
                    db.session.add(default_owner)
                    db.session.commit()
                    print(f"✅ Created default Owner user: {OWNER_USERNAME}. Password is the one set in environment or a random one.")
                else:
                    print("Default Owner user already exists.")
            else:
                print("Owner user check completed.")
            
        except ProgrammingError as e:
             # 🚨 ΕΝΙΣΧΥΜΕΝΟ ΜΗΝΥΜΑ ΣΦΑΛΜΑΤΟΣ ΓΙΑ ΤΟΝ ΧΡΗΣΤΗ
             print(f"SQLAlchemy Programming Error during setup: {e}. "
                   f"CRITICAL: The database schema is likely inconsistent. "
                   f"ACTION REQUIRED: Run 'DROP TABLE IF EXISTS users, messages, settings, emoticons, flask_sessions CASCADE;' "
                   f"in your PostgreSQL client, then restart the server.")
        except Exception as e:
             print(f"An unexpected error occurred during DB setup: {e}")


# Call the setup function when the application context is ready
with app.app_context():
    setup_app_on_startup()


if __name__ == '__main__':
    print("Starting Flask-SocketIO server...")
    socketio.run(app, debug=True)