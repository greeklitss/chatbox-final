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
from sqlalchemy import select, desc, func # ✅ ΚΡΙΣΙΜΗ ΕΙΣΑΓΩΓΗ ΤΟΥ func
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates # Για τον έλεγχο ρόλου

# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app
db = SQLAlchemy()
sess = Session()
oauth = OAuth()

# --- Ρυθμίσεις Εφαρμογής & Flask App ---
app = Flask(__name__)
# 🚨 ΚΡΙΣΙΜΗ ΠΡΟΣΘΗΚΗ: ΕΦΑΡΜΟΓΗ PROXYFIX για το Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_for_dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chatbox.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'sqlalchemy' # Χρησιμοποιούμε SQLAlchemy για session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions' # Νέος πίνακας για sessions
app.config['SESSION_SQLALCHEMY'] = db
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

# --- INITIALIZE EXTENSIONS ---
db.init_app(app)
sess.init_app(app)
socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*")

# --- OAuth Configuration (Google) ---
oauth.init_app(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)

# --- MODELS ---
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
    role = db.Column(db.String(20), default='guest') # guest, user, admin, owner
    avatar_url = db.Column(db.String(200), default='/static/default_avatar.png')
    display_name = db.Column(db.String(80), nullable=False)
    color = db.Column(db.String(7), default=generate_random_color)
    is_google_user = db.Column(db.Boolean, default=False)
    
    # Relationships
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

class Setting(db.Model):
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

# --- HELPER FUNCTIONS ---
def get_current_user():
    """Returns the current User object or None."""
    user_id = session.get('user_id')
    if user_id:
        return db.session.scalar(select(User).filter_by(id=user_id))
    return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def initialize_settings():
    """Initializes default application settings."""
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
    """Initializes default emoticons."""
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

# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            # For API calls, return JSON error
            if request.path.startswith('/api'):
                 return jsonify({'error': 'Login required'}), 401
            # For regular route, redirect to login page
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Renders the login/signup page."""
    # Αν ο χρήστης είναι ήδη συνδεδεμένος, τον στέλνουμε στο chat
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
        # 1. Έλεγχος αν επιτρέπεται η εγγραφή
        signup_setting = db.session.scalar(select(Setting).filter_by(key='signup_enabled'))
        if signup_setting and signup_setting.value == 'False':
            return jsonify({'error': 'Registration is currently disabled.'}), 403

        # 2. Έλεγχος αν υπάρχει ήδη
        existing_user = db.session.scalar(select(User).filter(User.display_name == username) | (User.email == email)))
        if existing_user:
            return jsonify({'error': 'Username or Email already exists.'}), 409

        # 3. Καθορισμός ρόλου (ο πρώτος χρήστης είναι ο owner, εκτός αν έχει ήδη δημιουργηθεί)
        try:
            # ✅ ΔΙΟΡΘΩΣΗ: Χρήση func.count()
            user_count = db.session.scalar(select(func.count()).select_from(User)) 
        except Exception:
            # Fallback σε περίπτωση που ο πίνακας δεν υπάρχει ακόμα (δεν πρέπει να συμβαίνει μετά το setup)
            user_count = 0 
            
        # Ο πρώτος χρήστης που κάνει εγγραφή (αν δεν έχει δημιουργηθεί Owner από μεταβλητές περιβάλλοντος)
        if user_count == 0:
            role = 'owner'
        else:
            role = 'user' # default role
            
        # 4. Δημιουργία χρήστη
        try:
            new_user = User(display_name=username, email=email, role=role) # ✅ ΣΩΣΤΟ
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            # 5. Αυτόματη σύνδεση μετά την εγγραφή (προαιρετικό)
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
        # Αναζήτηση χρήστη με username ή email
        user = db.session.scalar(
            select(User).filter((User.display_name == username_or_email)
            )
        )
        
        if user and user.password_hash and user.check_password(password):
            # Επιτυχής σύνδεση
            session.permanent = True # Set session to permanent
            session['user_id'] = user.id
            session['username'] = 
            session['role'] = user.role # Store role in session
            
            return jsonify({
                'message': 'Login successful.',
                'redirect_url': url_for('chat')
            }), 200
        else:
            # Αποτυχία σύνδεσης
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
    
    # Διαγράφουμε και τυχόν session keys του Authlib
    session.pop('google_token', None)
    
    return redirect(url_for('login'))


@app.route('/guest_login', methods=['GET', 'POST'])
def guest_login():
    """Allows a user to join as a guest."""
    with app.app_context():
        guest_setting = db.session.scalar(select(Setting).filter_by(key='guest_mode_enabled'))
        if guest_setting and guest_setting.value == 'False':
            return redirect(url_for('login'))

        # Δημιουργία μοναδικού username για τον Guest
        guest_id = str(uuid.uuid4())[:8]
        username = f"Guest-{guest_id}"
        
        # Εισαγωγή του Guest χρήστη στη βάση (χωρίς password)
        try:
                guest_user = User(display_name=username, 
                email=f"guest_{guest_id}@temporary.com", 
                role='guest',
            )
            # Δεν χρειάζεται set_password
            db.session.add(guest_user)
            db.session.commit()
            
            # Σύνδεση του Guest
            session.permanent = False # Guest session is temporary
            session['user_id'] = guest_user.id
            session['username'] = guest_user.display_name
            session['role'] = 'guest'
            
            return redirect(url_for('chat'))
            
        except IntegrityError:
            db.session.rollback()
            # Σπάνιο: αν υπάρχει ήδη το τυχαίο username, ξαναδοκιμάζουμε login
            return redirect(url_for('guest_login'))
        except Exception as e:
            print(f"Guest login error: {e}")
            return redirect(url_for('login'))


@app.route('/google_login')
def google_login():
    """Redirects user to Google for OAuth."""
    # Το Authlib θα χειριστεί το redirect
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/google_callback')
def google_callback():
    """Handles the callback from Google OAuth."""
    try:
        token = google.authorize_access_token()
        user_info = google.parse_id_token(token)

        email = user_info.get('email')
        name = user_info.get('name')
        picture = user_info.get('picture')

        with app.app_context():
            # 1. Αναζήτηση χρήστη
            user = db.session.scalar(select(User).filter_by(email=email))
            
            # 2. Καθορισμός ρόλου (πρώτος χρήστης = owner, εκτός αν υπάρχει ήδη)
            try:
                # ✅ ΔΙΟΡΘΩΣΗ: Χρήση func.count()
                user_count = db.session.scalar(select(func.count()).select_from(User)) 
            except Exception:
                user_count = 0 
                
            if user:
                # Υπάρχων χρήστης: Ενημέρωση στοιχείων και σύνδεση
                user.avatar_url = picture
                 = name
                user.is_google_user = True
                if user.role == 'guest':
                    user.role = 'user' # Αναβαθμίζουμε τον guest σε user
                
                db.session.commit()

            else:
                # Νέος χρήστης: Δημιουργία λογαριασμού
                # Καθορισμός ρόλου
                if user_count == 0:
                    role = 'owner'
                else:
                    role = 'user'
                    
                # Δημιουργούμε ένα μοναδικό username από το email
                username = email.split('@')[0] 
                
                new_user = User(
                    username=username, 
                    email=email, 
                    role=role, 
                    avatar_url=picture, 
                    display_name=name,
                    is_google_user=True
                )
                
                # Ορισμός τυχαίου hash password για να μην είναι null, αλλά δεν μπορεί να συνδεθεί με local login
                new_user.set_password(generate_random_password()) 
                
                db.session.add(new_user)
                db.session.commit()
                user = new_user

            # 3. Σύνδεση
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.display_name
            session['role'] = user.role
            
            return redirect(url_for('chat'))

    except MismatchingStateError as e:
        print(f"Google OAuth Error (State Mismatch): {e}")
        return redirect(url_for('login', error="State Mismatch Error. Please try again."))
    except OAuthError as e:
        print(f"Google OAuth Error: {e}")
        return redirect(url_for('login', error="Authentication failed. Check logs."))
    except Exception as e:
        print(f"An unexpected error occurred during Google OAuth: {e}")
        return redirect(url_for('login', error="An unexpected error occurred."))


# --- CHAT ROUTES & SOCKETIO LOGIC (Ο υπόλοιπος κώδικας) ---

@app.route('/')
@login_required
def chat():
    """Main chat page. Requires login."""
    user = get_current_user()
    
    # 1. Φόρτωση ρυθμίσεων
    settings_list = db.session.scalars(select(Setting)).all()
    settings_map = {s.key: s.value for s in settings_list}
    
    # 2. Φόρτωση emoticons
    emoticons_list = db.session.scalars(select(Emoticon)).all()
    emoticons_map = {e.code: e.url for e in emoticons_list}
    
    # 3. Φόρτωση ιστορικού (πρόσφατα μηνύματα)
    limit = int(settings_map.get('chat_history_limit', 100))
    messages_query = select(Message).order_by(desc(Message.timestamp)).limit(limit)
    raw_messages = db.session.scalars(messages_query).all()
    # Αντιστροφή σειράς για να εμφανιστούν από το παλιότερο στο νεότερο
    messages = list(reversed(raw_messages)) 
    
    # 4. Φόρτωση πληροφοριών χρηστών για το ιστορικό
    # Συλλέγουμε όλα τα user_ids από τα μηνύματα
    user_ids = list(set(m.user_id for m in messages))
    if user_ids:
        users_query = select(User).filter(User.id.in_(user_ids))
        message_users = db.session.scalars(users_query).all()
        # Δημιουργούμε έναν χάρτη (map) για γρήγορη αναζήτηση
        user_map = {u.id: {'username': u.username, 'color': u.color, 'role': u.role, 'avatar_url': u.avatar_url, 'display_name': u.display_name} for u in message_users}
    else:
        user_map = {}

    # Εμπλουτίζουμε τα μηνύματα με τα user data
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
            'username': user.display_name, & 'display_name': user.display_name,
            'role': user.role,
            'color': user.color,
            'avatar_url': user.avatar_url
        }), 200
    else:
        return jsonify({'error': 'Not logged in'}), 401

# --- API Endpoints for Admin Panel ---
# ... (Admin routes for settings, users, etc. - Left out for brevity)

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
    
    if file and allowed_file(file.filename):
        # Δημιουργία μοναδικού filename
        ext = file.filename.rsplit('.', 1)[1].lower()
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        
        try:
            file.save(filepath)
            
            file_url = url_for('uploaded_file', filename=new_filename, _external=True)
            
            # Στέλνουμε το BBCode στο chat
            bbcode_content = f'[img]{file_url}[/img]'
            
            # Αποθήκευση μηνύματος στη βάση
            new_message = Message(
                user_id=user.id,
                content=bbcode_content,
                system_message=False,
                room='main' # Default room
            )
            db.session.add(new_message)
            db.session.commit()
            
            # Εκπέμπουμε το μήνυμα στο chat
            emit('message', {
                'id': new_message.id,
                'user_id': user.id,
                'username': user.display_name, & 'display_name': user.display_name, ,
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
# ... (SocketIO events - Left out for brevity)


# --- ΚΡΙΣΙΜΟΣ ΕΛΕΓΧΟΣ ΔΗΜΙΟΥΡΓΙΑΣ ΦΑΚΕΛΩΝ & ΕΚΤΕΛΕΣΗ SERVER ---

def setup_app_on_startup():
    """Ελέγχει και δημιουργεί φακέλους, ρυθμίσεις και τον Owner χρήστη. Εκτελείται μόνο μία φορά."""
    
    # 1. Δημιουργία φακέλου uploads
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        print(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")
        
    with app.app_context():
        try:
            # 2. Δημιουργία πινάκων (θα τους δημιουργήσει μόνο αν δεν υπάρχουν)
            db.create_all() 
            print("Database tables ensured.")
            
            # 3. Αρχικοποίηση ρυθμίσεων & emoticons
            initialize_settings()
            initialize_emoticons()
            print("Settings and Emoticons initialized.")
            
            # 4. Έλεγχος και δημιουργία Default Owner χρήστη (αν οριστεί μέσω environment variables)
            owner_username = os.environ.get('OWNER_USERNAME')
            owner_email = os.environ.get('OWNER_EMAIL')
            owner_password = os.environ.get('OWNER_PASSWORD')
            
            if owner_username and owner_email:
                # Έλεγχος αν υπάρχει ήδη Owner (χρήστης με role='owner')
                owner_exists = db.session.scalar(
                    select(User).filter_by(role='owner')
                )
                
                if not owner_exists:
                    # Αν δεν υπάρχει Owner, δημιουργούμε έναν
                    if not owner_password:
                        # Δημιουργούμε ένα τυχαίο password αν δεν έχει δοθεί
                        owner_password = generate_random_password() 
                        print("⚠️ WARNING: OWNER_PASSWORD not set. Using a random password (check logs!).")

                    default_owner = User(
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


