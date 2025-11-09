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
from sqlalchemy import select, desc, func # <-- ΠΡΟΣΘΗΚΗ ΤΟΥ func
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
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key')

# --- 🚨 ΝΕΕΣ ΡΥΘΜΙΣΕΙΣ ΓΙΑ ΒΑΣΗ ΔΕΔΟΜΕΝΩΝ (POSTGRESQL) ---
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    # Flask-SQLAlchemy expects 'postgresql' not 'postgres'
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    # Default SQLite for local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- ΡΥΘΜΙΣΕΙΣ FLASK-SESSION (Χρήσιμο για Render) ---
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'chatbox:'
app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7) # 1 week

# --- Ρυθμίσεις Google OAuth ---
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
# Set up Google OAuth client
oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# --- ΡΥΘΜΙΣΕΙΣ ΓΙΑ UPLOADS ---
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# --- 2. Συνδέουμε τα extensions με το app ---
db.init_app(app)
sess.init_app(app)
oauth.init_app(app)

# --- 3. Αρχικοποίηση SocketIO ---
socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*", async_mode='eventlet')


# --- 🚨 4. DATABASE MODELS (ΠΡΟΣΘΗΚΗ: Setting & Emoticon) ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), default='user') # user, admin, owner, banned
    avatar_url = db.Column(db.String(256), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default='#ffffff')
    google_id = db.Column(db.String(128), unique=True, nullable=True)
    
    # Συναρτήσεις για hashing κωδικού
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Συναρτήσεις για serialization
    @property
    def is_guest(self):
        return self.username.startswith('Guest-')
        
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'avatar_url': self.avatar_url,
            'color': self.color
        }

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False) # Redundant but useful for quick display
    role = db.Column(db.String(20), default='user')
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    color = db.Column(db.String(7), default='#ffffff')
    avatar_url = db.Column(db.String(256), default='/static/default_avatar.png')

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)

class Emoticon(db.Model):
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(50), unique=True, nullable=False) # e.g., :smile:
    url = db.Column(db.String(256), nullable=False) # URL to the GIF/Image
    is_enabled = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'tag': self.tag,
            'url': self.url,
            'is_enabled': self.is_enabled
        }


# --- Global Variables for Active Users & Rooms ---
active_sessions = {} # {session_id: {user_id, username, sid}}


# --- 🚨 5. INITIALIZATION FUNCTIONS (ΝΕΕΣ) ---

# Dictionary of default settings
DEFAULT_SETTINGS = {
    'feature_bold': 'True',
    'feature_italic': 'True',
    'feature_underline': 'True',
    'feature_url': 'True',
    'feature_img': 'True',
    'feature_size': 'True',
    'feature_color': 'True',
}

# List of default emoticons (Placeholder for actual emoticons)
DEFAULT_EMOTICONS = [
    { 'tag': ':smile:', 'url': '/static/emotes/smile.gif' },
    { 'tag': ':lol:', 'url': '/static/emotes/lol.gif' },
    { 'tag': ':sad:', 'url': '/static/emotes/sad.png' },
    { 'tag': ':cool:', 'url': '/static/emotes/cool.gif' },
    { 'tag': ':cat:', 'url': '/static/emotes/cat.gif' },
    { 'tag': ':heart:', 'url': '/static/emotes/heart.png' },
]


def initialize_settings():
    """Διασφαλίζει ότι όλες οι default ρυθμίσεις υπάρχουν στη βάση."""
    for key, default_value in DEFAULT_SETTINGS.items():
        # Χρησιμοποιούμε scalar για να είναι πιο αποδοτικό
        if not db.session.scalar(select(Setting).filter_by(key=key)):
            new_setting = Setting(key=key, value=default_value)
            db.session.add(new_setting)
    db.session.commit()

def initialize_emoticons():
    """Διασφαλίζει ότι όλα τα default emoticons υπάρχουν στη βάση."""
    for emote in DEFAULT_EMOTICONS:
        if not db.session.scalar(select(Emoticon).filter_by(tag=emote['tag'])):
            # Προσθέτουμε μόνο αν δεν υπάρχει το tag
            new_emoticon = Emoticon(tag=emote['tag'], url=emote['url'], is_enabled=True)
            db.session.add(new_emoticon)
    db.session.commit()
    
# --- 6. DECORATORS ---

def login_required(f):
    """Decorator για να απαιτείται σύνδεση (είτε Guest είτε Registered)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator για να απαιτείται ρόλος 'admin' ή 'owner'."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session.get('role') not in ['admin', 'owner']:
            return jsonify({'error': 'Permission Denied'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def add_system_message(content):
    """Προσθέτει ένα μήνυμα συστήματος στη βάση δεδομένων και το εκπέμπει."""
    try:
        new_message = Message(
            user_id=1, # System ID
            username='System',
            role='system',
            content=content,
            color='#ffc107', # Yellow/Amber for system
            avatar_url='/static/default_avatar.png'
        )
        db.session.add(new_message)
        db.session.commit()

        # Εκπομπή μέσω SocketIO
        message_data = {
            'username': 'System',
            'role': 'system',
            'content': content,
            'timestamp': new_message.timestamp.strftime('%H:%M'),
            'color': '#ffc107',
            'avatar_url': '/static/default_avatar.png'
        }
        socketio.emit('new_message', message_data, room='chat')

    except Exception as e:
        print(f"Error adding system message: {e}")
        db.session.rollback()

# --- 7. ΠΡΟΣΘΗΚΗ: ADMIN API ROUTES ---

@app.route('/admin_panel')
@login_required
def admin_panel():
    """Εμφανίζει το Admin Panel."""
    # Ο έλεγχος ρόλου γίνεται και στο JS, αλλά πρέπει να υπάρχει και εδώ.
    if session.get('role') not in ['admin', 'owner']:
        return redirect(url_for('chat')) # Redirect non-admins
    return render_template('admin_panel.html')

@app.route('/api/admin/set_setting', methods=['POST'])
@admin_required
def set_setting():
    """Admin route για να αλλάζει τις ρυθμίσεις της εφαρμογής (π.χ. feature toggles)."""
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')
    
    if not key or value is None:
        return jsonify({'error': 'Missing key or value'}), 400
        
    try:
        setting = db.session.scalar(select(Setting).filter_by(key=key))
        if setting:
            setting.value = value
        else:
            setting = Setting(key=key, value=value)
            db.session.add(setting)
            
        db.session.commit()
        
        # Ειδοποιούμε όλους τους clients για αλλαγή setting
        socketio.emit('setting_updated', {'key': key, 'value': value}, room='chat')
        
        add_system_message(f"Admin has set setting '{key}' to '{value}'.")
        
        return jsonify({'success': True, 'message': f'Setting {key} updated.'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Database error: {e}'}), 500

@app.route('/api/admin/add_emoticon', methods=['POST'])
@admin_required
def add_emoticon():
    """Admin route για να προσθέτει νέα emoticons."""
    data = request.get_json()
    tag = data.get('tag', '').strip()
    url = data.get('url', '').strip()

    if not tag or not url:
        return jsonify({'error': 'Emoticon tag and URL are required.'}), 400
    if not tag.startswith(':') or not tag.endswith(':'):
        return jsonify({'error': 'Emoticon tag must be in the format :tag:.'}), 400

    try:
        new_emoticon = Emoticon(tag=tag, url=url, is_enabled=True)
        db.session.add(new_emoticon)
        db.session.commit()
        
        # Ειδοποιούμε τους χρήστες για το νέο emoticon
        socketio.emit('emoticon_updated', {'message': 'New emoticons available.'}, room='chat')
        add_system_message(f"New emoticon {tag} added by Admin.")

        return jsonify({'success': True, 'message': f'Emoticon {tag} added.'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Emoticon tag already exists.'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Database error: {e}'}), 500

@app.route('/api/admin/toggle_emoticon', methods=['POST'])
@admin_required
def toggle_emoticon():
    """Admin route για να αλλάζει την κατάσταση (enabled/disabled) ενός emoticon."""
    data = request.get_json()
    emoticon_id = data.get('id')
    
    if not emoticon_id:
        return jsonify({'error': 'Missing emoticon ID'}), 400
        
    try:
        emoticon = db.session.get(Emoticon, emoticon_id)
        if not emoticon:
            return jsonify({'error': 'Emoticon not found.'}), 404
            
        emoticon.is_enabled = not emoticon.is_enabled
        db.session.commit()
        
        # Ειδοποιούμε τους χρήστες για την αλλαγή
        socketio.emit('emoticon_updated', {'message': 'Emoticons list updated.'}, room='chat')
        
        status = 'enabled' if emoticon.is_enabled else 'disabled'
        add_system_message(f"Emoticon {emoticon.tag} has been {status}.")
        
        return jsonify({'success': True, 'message': f'Emoticon {emoticon_id} toggled to {emoticon.is_enabled}.'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Database error: {e}'}), 500

@app.route('/api/admin/set_role', methods=['POST'])
@admin_required
def set_user_role():
    """Admin route για να αλλάζει τον ρόλο ενός χρήστη (User, Admin, Banned)."""
    data = request.get_json()
    user_id = data.get('user_id')
    role = data.get('role')
    
    if not user_id or role not in ['user', 'admin', 'banned', 'owner']:
        return jsonify({'error': 'Invalid user ID or role.'}), 400

    if user_id == session.get('user_id'):
        return jsonify({'error': 'Cannot change your own role via API.'}), 403

    # Ο Admin δεν μπορεί να αλλάξει ρόλο σε Owner ή άλλους Admins (εκτός αν είναι ο ίδιος Owner)
    if session.get('role') == 'admin' and (role == 'owner' or (db.session.get(User, user_id) and db.session.get(User, user_id).role == 'owner')):
        return jsonify({'error': 'Admins cannot modify Owner roles.'}), 403
    
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'error': 'User not found.'}), 404
            
        old_role = user.role
        user.role = role
        db.session.commit()
        
        # Ενημέρωση των συνδεδεμένων χρηστών (και του ίδιου του χρήστη)
        socketio.emit('user_role_updated', {'user_id': user.id, 'role': role}, room='chat')
        
        # Προσθήκη μηνύματος συστήματος
        add_system_message(f"User {user.username} role changed from '{old_role}' to '{role}'.")

        return jsonify({'success': True, 'message': f'User {user.username} role set to {role}.'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Database error: {e}'}), 500

# --- 8. ΠΡΟΣΘΗΚΗ: PUBLIC API ROUTES ΓΙΑ ΤΟ ADMIN PANEL (READ OPERATIONS) ---

@app.route('/api/settings', methods=['GET'])
@login_required
def get_all_settings():
    """Επιστρέφει όλες τις ρυθμίσεις ως dictionary."""
    try:
        settings_list = db.session.scalars(select(Setting)).all()
        settings_dict = {s.key: s.value for s in settings_list}
        return jsonify(settings_dict)
    except Exception as e:
        return jsonify({'error': f'Database error: {e}'}), 500

@app.route('/api/emoticons/all', methods=['GET'])
@login_required
def get_all_emoticons():
    """Επιστρέφει όλα τα emoticons (για το Admin Panel)."""
    try:
        emoticons = db.session.scalars(select(Emoticon).order_by(Emoticon.tag)).all()
        return jsonify([e.to_dict() for e in emoticons])
    except Exception as e:
        return jsonify({'error': f'Database error: {e}'}), 500

@app.route('/api/emoticons/enabled', methods=['GET'])
def get_enabled_emoticons():
    """Επιστρέφει μόνο τα ενεργοποιημένα emoticons (για το Chat)."""
    try:
        emoticons = db.session.scalars(select(Emoticon).filter_by(is_enabled=True).order_by(Emoticon.tag)).all()
        return jsonify({e.tag: e.url for e in emoticons})
    except Exception as e:
        return jsonify({'error': f'Database error: {e}'}), 500
        
@app.route('/api/users', methods=['GET'])
@admin_required
def get_all_users():
    """Επιστρέφει τη λίστα όλων των χρηστών (για το Admin Panel)."""
    try:
        # Φιλτράρουμε τους Guests για να μην εμφανίζονται
        users = db.session.scalars(select(User).filter(User.username.not_like('Guest-%')).order_by(User.id)).all()
        # Πρέπει να επιστρέψουμε μόνο τα to_dict() για ασφάλεια
        return jsonify([user.to_dict() for user in users])
    except Exception as e:
        return jsonify({'error': f'Database error: {e}'}), 500




@app.route('/check_login')
@login_required # <-- Προσθήκη του decorator, αν υπάρχει
def check_login():
    """Επιστρέφει τα βασικά δεδομένα του χρήστη για frontend check (π.χ. Admin Panel)."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    user_id = session['user_id']
    user = db.session.get(User, user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    return jsonify({
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'avatar_url': user.avatar_url,
        'color': user.color
    })
def generate_random_color():
    """Δημιουργεί ένα τυχαίο hex χρώμα, εξαιρώντας το λευκό και τα πολύ ανοιχτά."""
    import random
    
    # Επιλέγουμε ένα τυχαίο φωτεινό χρώμα (όχι πολύ ανοιχτό)
    r = random.randint(50, 255)
    g = random.randint(50, 255)
    b = random.randint(50, 255)
    
    # Εξασφαλίζουμε ότι δεν είναι πολύ κοντά στο λευκό
    if r > 200 and g > 200 and b > 200:
        index_to_lower = random.choice([0, 1, 2])
        if index_to_lower == 0: r = random.randint(50, 150)
        if index_to_lower == 1: g = random.randint(50, 150)
        if index_to_lower == 2: b = random.randint(50, 150)
        
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)
@app.route('/api/v1/sign_up', methods=['POST'])
def sign_up():
    # 1. Προσπαθούμε να πάρουμε δεδομένα από JSON (API call)
    data_json = request.get_json(silent=True)
    
    # Επιλέγουμε πηγή δεδομένων (JSON ή Form Data)
    if data_json:
        username = data_json.get('username')
        email = data_json.get('email')
        password = data_json.get('password')
    else:
        # Αν δεν υπάρχει JSON, ψάχνουμε στα form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

    # 2. Έλεγχος υποχρεωτικών πεδίων (το 400 Bad Request)
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    # 3. Έλεγχος μήκους
    if len(username) < 3 or len(password) < 6:
        return jsonify({'error': 'Username must be at least 3 chars, Password at least 6.'}), 400

    try:
             # 4. Έλεγχος ύπαρξης χρήστη/email
        existing_user = db.session.scalar(select(User).filter((User.username == username) | (User.email == email)))
        if existing_user:
            return jsonify({'error': 'Username or Email already registered'}), 409
            
        # 5. ΚΡΙΣΙΜΟΣ ΕΛΕΓΧΟΣ: Εάν είναι ο ΠΡΩΤΟΣ χρήστης, του δίνουμε ρόλο 'owner'
        # Μετράμε όλους τους χρήστες εκτός από τους Guests
        user_count = db.session.scalar(
    select(func.count())
    .select_from(User)
    .filter(User.role.not_in(['guest']))
)
        is_first_user = user_count == 0

        # 6. Δημιουργία και αποθήκευση νέου χρήστη
        new_user = User(
            username=username,
            email=email,
            # Ορίζουμε το ρόλο
            role='owner' if is_first_user else 'user',
            # Δίνουμε default avatar (όπως στον κώδικα σας)
            avatar_url='/static/default_avatar.png'
            color=generate_random_color()
            # Το color θα πάρει το default του μοντέλου, όπως επιθυμείτε.
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()

        # 7. Αυτόματη είσοδος (login) του χρήστη με Flask Session
        session['user_id'] = new_user.id
        session['username'] = new_user.username
        session['role'] = new_user.role
        session['color'] = new_user.color # Χρησιμοποιεί το default χρώμα
        
        # 8. Μήνυμα Συστήματος (Πρέπει να υπάρχει η συνάρτηση add_system_message)
        # add_system_message(f"User {new_user.username} has signed up.") # Προαιρετικό
        add_system_message(f"New user {new_user.username} has joined the chat!")

        # 9. Απάντηση επιτυχίας
        return jsonify({'message': 'Registration successful, redirecting to chat', 'redirect_url': url_for('chat')}), 201

    except Exception as e:
        db.session.rollback()
        # Εδώ χρησιμοποιούμε το print για debugging
        print(f"Error during sign up: {e}") 
        return jsonify({'error': f'An unexpected database error occurred during registration: {e}'}), 500

# 🚨 ΝΕΟ ROUTE: Προσθέστε αυτό για να "ιάσετε" το 404/api/v1/login


@app.route('/login_guest', methods=['POST'])
@app.route('/api/v1/login', methods=['POST'])
def login_guest():
    """Χειρίζεται το Login είτε μέσω φόρμας (ως login_guest) είτε ως API call (ως /api/v1/login)."""
    data_json = request.get_json(silent=True)    

    if data_json:
        username = data_json.get('username')
        password = data_json.get('password')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400


    user = db.session.scalar(select(User).filter_by(username=username))

    # 1. ΕΠΙΤΥΧΗΣ ΕΛΕΓΧΟΣ
    if user and user.check_password(password):
        if user.role == 'banned':
            return jsonify({'error': 'Your account has been banned.'}), 403
            
        # 🚨 ΚΡΙΣΙΜΟ: Πρέπει να καλέσετε το login_user για να γίνει η session
        # (Εφόσον δεν το κάνατε με flask_login, χρησιμοποιείτε απλώς το session dictionary)
        # login_user(user) # <- Αν χρησιμοποιούσατε Flask-Login

        # Ορισμός Session χειροκίνητα
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['color'] = user.color
        
        # Προσθήκη μηνύματος συστήματος
        # add_system_message(f"User {user.username} has logged in.") # <- Αν υπάρχει αυτή η συνάρτηση

        # Επιστροφή JSON επιτυχίας
        return jsonify({'message': 'Login successful', 'redirect_url': url_for('chat')}), 200
    
    # 2. ΑΠΟΤΥΧΗΜΕΝΟΣ ΕΛΕΓΧΟΣ
    return jsonify({'error': 'Invalid username or password'}), 401        
@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Guest')
    if 'user_id' in session:
        # Send system message before clearing session
        add_system_message(f"{username} has left the chat.")
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/login_google')
def login_google():
    # Set the redirect_uri dynamically based on the request environment
    # Crucial for deployment on platforms like Render or Heroku
    redirect_uri = url_for('google_callback', _external=True)
    
    # Force HTTPS scheme for external links if in a production environment
    if os.environ.get('RENDER') or os.environ.get('DYNO'):
          redirect_uri = url_for('google_callback', _external=True, _scheme='https')
          
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/google_callback')
def google_callback():
    try:
        # Get the token and profile information
        token = oauth.google.authorize_access_token()
        resp = oauth.google.get('userinfo')
        user_info = resp.json()
    except MismatchingStateError:
        return 'Session state mismatch. Please try logging in again.', 400
    except OAuthError as e:
        print(f"OAuth Error: {e}")
        return 'Google authentication failed.', 400
    except Exception as e:
        print(f"An unexpected error occurred during Google auth: {e}")
        return 'An unexpected error occurred.', 500


    google_id = user_info['id']
    email = user_info['email']
    username = user_info.get('name', 'GoogleUser')
    avatar_url = user_info.get('picture', '/static/default_avatar.png')

    with app.app_context():
        # 1. Check if user exists by google_id
        user = db.session.scalar(select(User).filter_by(google_id=google_id))
        
        if not user:
            # 2. Check if a user with the same email exists (and link accounts)
            user = db.session.scalar(select(User).filter_by(email=email))
            
            if user:
                # Link existing local account to Google ID
                user.google_id = google_id
                user.avatar_url = avatar_url # Update avatar from Google
                db.session.commit()
                
            else:
                # 3. Create a new user
                # Ensure username is unique (e.g. if a local user has the same name)
                base_username = username
                counter = 1
                while db.session.scalar(select(User).filter_by(username=username)):
                    username = f"{base_username}_{counter}"
                    counter += 1
                    
                is_first_user = db.session.scalar(
    select(func.count())
    .select_from(User)
    .filter(User.username.not_like('Guest-%'))
) == 0 # <--- ΣΩΣΤΗ ΧΡΗΣΗ func.count()

                new_user = User(
                    username=username,
                    email=email,
                    google_id=google_id,
                    role='owner' if is_first_user else 'user',
                    avatar_url=avatar_url,
                    color='#00e6e6' # Default color for Google logins
                )
                db.session.add(new_user)
                db.session.commit()
                user = new_user
                
                add_system_message(f"New user {user.username} has joined the chat via Google!")


        if user.role == 'banned':
            return render_template('banned.html') # Need to create this if it doesn't exist

        # Log in the user
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        session['color'] = user.color
        
        add_system_message(f"User {user.username} has logged in via Google.")

        return redirect(url_for('chat'))
    
@app.route('/guest_login', methods=['POST'])
def guest_login():
    """Επιτρέπει τη σύνδεση ως Guest με προσωρινό username."""
    with app.app_context():
        # Δημιουργία μοναδικού username για Guest
        guest_id = str(uuid.uuid4())[:8]
        username = f"Guest-{guest_id}"

        # Δημιουργία προσωρινού Guest User στη βάση
        new_user = User(
            username=username, 
            email=None, 
            password_hash=None, 
            role='guest', 
            color='#FFCC00', # Default color for guests
            avatar_url='/static/default_avatar.png'
        )
        db.session.add(new_user)
        db.session.commit()

        # Αποθήκευση στη session
        session['user_id'] = new_user.id
        session['username'] = new_user.username
        session['role'] = 'guest'
        session['color'] = '#FFCC00'
        
        add_system_message(f"{new_user.username} has entered as a Guest.")
        
        return redirect(url_for('chat'))

@app.route('/radio_proxy')
def radio_proxy():
    """Proxy για το Web Radio Stream."""
    # Placeholder URL - Αντικαταστήστε με τον πραγματικό URL του ραδιοφωνικού σταθμού
    # radio_url = "http://stream.akoume.gr:8000/live" 
    # Χρησιμοποιώ ένα πιο τυπικό παράδειγμα για δοκιμές αν δεν υπάρχει ο παραπάνω.
    radio_url = os.environ.get('RADIO_STREAM_URL', 'http://stream.akoume.gr:8000/live') # Placeholder for actual stream
    
    # Κάνουμε stream το περιεχόμενο από τον εξωτερικό URL
    try:
        response = requests.get(radio_url, stream=True, timeout=10)
        
        if response.status_code == 200:
            # Χρησιμοποιούμε Generator για να στείλουμε το stream κομμάτι-κομμάτι
            def generate():
                for chunk in response.iter_content(chunk_size=1024):
                    yield chunk
            
            return app.response_class(generate(), mimetype=response.headers['content-type'])
        else:
            return "Could not connect to radio stream.", 503
            
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to radio stream: {e}")
        # Επιστροφή ενός empty stream με 200 OK ή ενός static error file αν είναι απαραίτητο
        return "Could not connect to radio stream.", 503

@app.route('/file_upload', methods=['POST'])
def file_upload():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401

    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Χρησιμοποιούμε uuid για να διασφαλίσουμε μοναδικά ονόματα
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        # Δημιουργία του πλήρους URL για χρήση στο chat
        file_url = url_for('uploaded_file', filename=unique_filename, _external=True)

        return jsonify({'success': True, 'file_url': file_url}), 200
    else:
        return jsonify({'success': False, 'message': 'File type not allowed.'}), 400

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/settings/set_user_color', methods=['POST'])
def set_user_color():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401
    
    data = request.get_json()
    new_color = data.get('color')
    
    if not new_color or not new_color.startswith('#') or len(new_color) not in [4, 7]:
        return jsonify({'success': False, 'message': 'Invalid color format.'}), 400

    user_id = session['user_id']
    with app.app_context():
        user = db.session.get(User, user_id)
        if user:
            # For registered users, update the DB
            if user.role != 'guest':
                user.color = new_color
                db.session.commit()
                
            # Update session for immediate effect
            session['color'] = new_color
            
            # Notify all users in the chat room that the color has changed
            socketio.emit('user_color_updated', {
                'user_id': user.id,
                'color': new_color
            }, room='chat')
            
            return jsonify({'success': True, 'message': 'Color updated.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

@app.route('/settings/set_avatar_url', methods=['POST'])
def set_avatar_url():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401
    
    data = request.get_json()
    new_url = data.get('avatar_url')
    
    if not new_url:
        return jsonify({'success': False, 'message': 'Missing URL.'}), 400

    user_id = session['user_id']
    with app.app_context():
        if session.get('role') == 'guest':
             return jsonify({'success': True, 'message': 'Avatar URL set for this session.'})
             
        user = db.session.get(User, user_id)
        if user:
            user.avatar_url = new_url
            db.session.commit()
            
            socketio.emit('user_avatar_updated', {
                'user_id': user.id,
                'avatar_url': new_url
            }, room='chat')
            
            return jsonify({'success': True, 'message': 'Avatar URL updated.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
            
# --- 9. ΠΡΟΣΘΗΚΗ: Τροποποίηση chat() route για να στέλνει τα settings ---

@app.route('/')
@login_required
def chat():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    
    if not user:
        # Should not happen if login_required passed, but for safety
        session.clear()
        return redirect(url_for('login'))

    if user.role == 'banned':
        session.clear()
        return render_template('banned.html') # Assuming banned.html exists
    
    # 🚨 ΝΕΟ: Φορτώνουμε όλα τα settings για να τα περάσουμε στο chat.html
    settings_list = db.session.scalars(select(Setting)).all()
    settings = {s.key: s.value for s in settings_list}
    
    # 🚨 ΝΕΟ: Φορτώνουμε τα ενεργοποιημένα emoticons για το Chat (για το main.js)
    emoticons_list = db.session.scalars(select(Emoticon).filter_by(is_enabled=True)).all()
    # Επιστρέφουμε ένα dictionary {tag: url} για εύκολο lookup στο JS
    emoticons = {e.tag: e.url for e in emoticons_list}
    
    # Φόρτωση των 50 τελευταίων μηνυμάτων
    messages = db.session.scalars(select(Message).order_by(desc(Message.timestamp)).limit(50)).all()
    messages.reverse() # Εμφάνιση με τη σωστή σειρά
    
    current_user_data = user.to_dict()
    
    return render_template('chat.html', user=current_user_data, messages=messages, 
                           settings=settings, emoticons=emoticons)


# --- SOCKETIO EVENTS ---

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    # Check if session has user info
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        role = session['role']
        color = session['color']
        
        # Add to active sessions if not already added
        if sid not in active_sessions:
            active_sessions[sid] = {'user_id': user_id, 'username': username, 'role': role, 'color': color, 'sid': sid}
            
        join_room('chat') # Join the main chat room

        # Send updated user list to all
        online_users = get_online_users()
        emit('user_list_update', online_users, room='chat')

        print(f"User {username} ({user_id}) connected with SID: {sid}")

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    
    if sid in active_sessions:
        # Check if the user has other active connections (sessions)
        user_id_to_check = active_sessions[sid]['user_id']
        username_to_check = active_sessions[sid]['username']
        
        # Remove the session
        del active_sessions[sid]
        
        # Check if user is still connected with another SID
        is_still_online = any(data['user_id'] == user_id_to_check for data in active_sessions.values())

        if not is_still_online:
            # Only emit user_left if this was the last connection for that user
            print(f"User {username_to_check} ({user_id_to_check}) fully disconnected.")
            
            # Send updated user list to all
            online_users = get_online_users()
            emit('user_list_update', online_users, room='chat')
        
        print(f"SID {sid} disconnected.")

def get_online_users():
    """Επιστρέφει μια μοναδική λίστα online χρηστών (αφαιρεί τα διπλά sessions)."""
    unique_users = {}
    for data in active_sessions.values():
        user_id = data['user_id']
        # Χρησιμοποιούμε το user_id ως κλειδί για να κρατήσουμε μόνο ένα instance
        if user_id not in unique_users:
            unique_users[user_id] = {
                'id': data['user_id'],
                'username': data['username'],
                'role': data['role'],
                'color': data['color']
            }
            
    # Μετατροπή σε λίστα και ταξινόμηση (π.χ., Owner > Admin > User > Guest)
    order = {'owner': 4, 'admin': 3, 'user': 2, 'guest': 1}
    sorted_users = sorted(
        unique_users.values(), 
        key=lambda x: (order.get(x['role'], 0), x['username']) ,
        reverse=True # Για να εμφανίζεται ο Owner πρώτος
    )
    return sorted_users


@socketio.on('send_message')
def handle_send_message(data):
    # Retrieve user info from session
    if 'user_id' not in session:
        return # Drop message if not authenticated

    user_id = session['user_id']
    username = session['username']
    role = session['role']
    color = session['color']
    
    # Fetch avatar_url from DB (important, as it might have changed)
    user = db.session.get(User, user_id)
    if not user:
        return # Should not happen
        
    if user.role == 'banned':
        return # Banned users cannot send messages
    
    content = data.get('content')
    if not content:
        return

    # Basic content sanitization (server-side safety check for length/type)
    content = str(content).strip()
    if not content:
        return

    # 1. Save to Database
    try:
        new_message = Message(
            user_id=user_id,
            username=username,
            role=role,
            content=content,
            color=color,
            avatar_url=user.avatar_url
        )
        db.session.add(new_message)
        db.session.commit()
    except Exception as e:
        print(f"Database error during message save: {e}")
        db.session.rollback()
        # You might want to emit an error back to the sender
        return

    # 2. Emit to all clients in the room
    message_data = {
        'username': username,
        'role': role,
        'content': content,
        'timestamp': new_message.timestamp.strftime('%H:%M'),
        'color': color,
        'avatar_url': user.avatar_url
    }
    emit('new_message', message_data, room='chat')

# --- ΠΡΟΣΘΗΚΗ: ΚΡΙΣΙΜΟΣ ΕΛΕΓΧΟΣ ΔΗΜΙΟΥΡΓΙΑΣ ΦΑΚΕΛΩΝ & ΕΚΤΕΛΕΣΗ SERVER ---

def setup_app_on_startup():
    """Ελέγχει και δημιουργεί φακέλους. Εκτελείται μόνο μία φορά."""
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        print(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
        
    with app.app_context():
        try:
            # Δημιουργία πινάκων (θα τους δημιουργήσει μόνο αν δεν υπάρχουν)
            # Χρησιμοποιείται η κλήση `db.create_all()` που διαβάζει τα Models
            db.create_all() 
            print("Database tables ensured.")
            
            # Αρχικοποίηση ρυθμίσεων & emoticons
            initialize_settings()
            initialize_emoticons()
            print("Settings and Emoticons initialized.")
# 🚨 3. ΚΡΙΣΙΜΟ: ΕΛΕΓΧΟΣ & ΔΗΜΙΟΥΡΓΙΑ ΤΟΥ ΠΡΩΤΟΥ OWNER
            from sqlalchemy import select, func # Αυτό είναι ασφαλές εδώ (αν και υπάρχει στην κορυφή)

            # ΣΩΣΤΗ ΜΕΤΡΗΣΗ: Μετράμε όλους τους μη-guest χρήστες
            user_count = db.session.scalar(
                select(func.count())
                .select_from(User)
                .filter(User.role.not_in(['guest']))
            )
            
            if user_count == 0:
                # Δημιουργία του default Owner χρήστη
                owner_username = os.environ.get('DEFAULT_ADMIN_USERNAME', 'ChatOwner')
                owner_email = os.environ.get('DEFAULT_ADMIN_EMAIL', 'owner@chat.com')
                owner_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', secrets.token_urlsafe(16)) 
                
                # Έλεγχος για να μην υπάρχει ήδη με το ίδιο όνομα (για ασφάλεια)
                if not db.session.scalar(select(User).filter_by(username=owner_username)):
                    default_owner = User(
                        username=owner_username,
                        email=owner_email,
                        role='owner',
                        avatar_url='/static/default_avatar.png',
                        color=generate_random_color() # Υποθέτουμε ότι η συνάρτηση είναι διαθέσιμη
                    )
                    default_owner.set_password(owner_password)
                    db.session.add(default_owner)
                    db.session.commit()
                    print(f"✅ Created default Owner user: {owner_username}. Password is the one set in environment or a random one.")
                else:
                    print("Default Owner user already exists.")
            else:
                print("Owner user check completed.")
            
        except ProgrammingError as e:
             print(f"SQLAlchemy Programming Error during setup: {e}. If this is a new Postgres setup, ensure the database is accessible.")
        except Exception as e:
             print(f"An unexpected error occurred during DB setup: {e}")

# Call the setup function when the application context is ready
with app.app_context():
    # 🚨 ΚΑΛΟΥΜΕ ΤΗΝ ΑΡΧΙΚΟΠΟΙΗΣΗ ΤΩΝ ΠΑΓΚΟΣΜΙΩΝ ΡΥΘΜΙΣΕΩΝ ΚΑΙ ΦΑΚΕΛΩΝ
    setup_app_on_startup()


if __name__ == '__main__':
    # Flask-SocketIO runs the Flask app
    print("Starting Flask-SocketIO server...")
    socketio.run(app, debug=True, port=int(os.environ.get('PORT', 5000)))