import os
import json
import uuid
import time
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix # 🚨 ΚΡΙΣΙΜΗ ΠΡΟΣΘΗΚΗ: ΔΙΟΡΘΩΣΗ HTTPS/Render

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash 
from flask_session import Session 
from sqlalchemy.sql import text 
from sqlalchemy.exc import IntegrityError, ProgrammingError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError 


# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app (Application Factory Pattern)
db = SQLAlchemy()
sess = Session()
oauth = OAuth()


# --- Ρυθμίσεις Εφαρμογής & Flask App ---
# Χρησιμοποιούμε τη default ρύθμιση για templates/static folders.
app = Flask(__name__) 
# 🚨 ΕΦΑΡΜΟΓΗ PROXYFIX: Διορθώνει τα headers (http -> https) για σωστό Google OAuth
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1) 
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'a_default_secret_key_for_local_dev')

# --- Ρυθμίσεις Βάσης Δεδομένων ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Fix for older SQLAlchemy versions in Render/PostgreSQL
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # FIX: Χωρίς αυτό, το session χάνεται


db.init_app(app)
sess.init_app(app)


# --- Ρυθμίσεις OAuth (Google) ---
oauth.init_app(app)

oauth.register(
    'google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
    # Το ProxyFix διορθώνει το redirect_uri σε HTTPS, επιτρέποντας το Google Login
)


# --- Ρυθμίσεις SocketIO ---
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False, async_mode='eventlet', logger=True, engineio_logger=True)


# --- Μοντέλα Βάσης Δεδομένων ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user') # user, admin, owner
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    # Νέα πεδία για Google OAuth
    google_id = db.Column(db.String(120), unique=True, nullable=True) 
    avatar_url = db.Column(db.String(255), nullable=True)
    # Ένα πεδίο για την τελευταία φορά που ο χρήστης ήταν συνδεδεμένος.
    last_seen = db.Column(db.DateTime, default=datetime.now)
    # Σχέση με τα μηνύματα
    messages = db.relationship('Message', backref='author', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(password, self.password_hash) # Σωστή σειρά arguments

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

class Emoticon(db.Model):
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False) # π.χ. :smile:
    url = db.Column(db.String(255), nullable=False) # π.χ. /static/emoticons/smile.gif
    is_active = db.Column(db.Boolean, default=True)

    
# --- Βοηθητικές Συναρτήσεις & Decorators ---

# Decorator για έλεγχο login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Αποστολή απάντησης 401 για AJAX/API requests
            if request.path.startswith('/api/') or request.path.startswith('/settings/'):
                return jsonify({'success': False, 'message': 'Authentication required.'}), 401
            # Redirect για HTML requests
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Decorator για έλεγχο ρόλου
def requires_role(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in roles:
                return jsonify({'success': False, 'message': 'Access denied: Insufficient privileges.'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper
    
def get_user_info_from_session():
    """Επιστρέφει ένα dict με τα βασικά στοιχεία του χρήστη ή None."""
    user_id = session.get('user_id')
    role = session.get('role')
    display_name = session.get('display_name')
    
    if user_id and role and display_name:
        # Αναζήτηση του URL Avatar αν υπάρχει (μόνο για registered users)
        avatar_url = None
        if role != 'guest':
            with app.app_context():
                user_instance = db.session.get(User, user_id)
                if user_instance:
                    avatar_url = user_instance.avatar_url
        
        return {
            'id': user_id,
            'display_name': display_name,
            'role': role,
            'avatar_url': avatar_url or url_for('static', filename='default-avatar.png')
        }
    return None

def is_username_available(username):
     with app.app_context():
        # Ελέγχουμε αν υπάρχει ήδη χρήστης με αυτό το username ή display_name
        return User.query.filter((User.username == username) | (User.display_name == username)).first() is None
        
def create_initial_settings():
    """Δημιουργεί αρχικές ρυθμίσεις αν δεν υπάρχουν."""
    initial_settings = [
        ('allow_guests', 'True'),
        ('max_users', '100'),
        ('stream_url', 'http://example.com/radio.mp3'), # Default stream URL (ΑΛΛΑΞΤΕ ΑΥΤΟ!)
        ('max_message_length', '500')
    ]
    
    with app.app_context():
        for key, default_value in initial_settings:
            if not Setting.query.filter_by(key=key).first():
                new_setting = Setting(key=key, value=default_value)
                db.session.add(new_setting)
        
        # Προσθήκη default emoticons αν δεν υπάρχουν
        initial_emoticons = [
            (':smile:', 'https://i.ibb.co/6y4T3bY/smile.gif'),
            (':sad:', 'https://i.ibb.co/3W6m0c7/sad.gif'),
            (':wink:', 'https://i.ibb.co/L9vH2jK/wink.gif')
        ]
        for code, url in initial_emoticons:
            if not Emoticon.query.filter_by(code=code).first():
                new_emoticon = Emoticon(code=code, url=url, is_active=True)
                db.session.add(new_emoticon)
                
        try:
            db.session.commit()
        except Exception as e:
            # Πιθανό σφάλμα αν τρέχει το create_all() ενώ η βάση υπάρχει
            db.session.rollback()
            # print(f"Error during initial setting creation: {e}")

# --- Context Processor για πρόσβαση σε user_info στο Jinja2 ---
@app.context_processor
def inject_user():
    return dict(user=get_user_info_from_session())

# --- Διαδρομές (Routes) ---

@app.before_first_request
def create_tables():
    with app.app_context():
        # Δημιουργία πινάκων αν δεν υπάρχουν
        db.create_all()
        # Δημιουργία αρχικών ρυθμίσεων (συμπεριλαμβανομένου του stream URL)
        create_initial_settings()
        
        # Ελέγχουμε αν υπάρχει ο default 'owner' χρήστης
        if not User.query.filter_by(role='owner').first():
             # Δημιουργούμε έναν ψεύτικο owner αν δεν υπάρχει
             # print("WARNING: Creating default 'owner' user. Please change the password immediately!")
             default_owner = User(
                 username='owner', 
                 email='owner@example.com', 
                 display_name='Owner', 
                 role='owner'
             )
             default_owner.set_password('123456') # Default password: 123456
             db.session.add(default_owner)
             db.session.commit()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('display_name', None)
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    # Παίρνουμε τα τελευταία 50 μηνύματα για να γεμίσουμε το chatbox
    with app.app_context():
        # Παίρνουμε το stream URL από τις ρυθμίσεις
        stream_setting = Setting.query.filter_by(key='stream_url').first()
        stream_url = stream_setting.value if stream_setting else 'http://example.com/radio.mp3'
        
        messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
        # Τα αντιστρέφουμε για να είναι στη σωστή σειρά
        messages.reverse()
        
        # Επίσης, περνάμε τη λίστα των ενεργών emoticons
        emoticons = Emoticon.query.filter_by(is_active=True).all()
        
        return render_template('chat.html', messages=messages, stream_url=stream_url, emoticons=emoticons)


# --- API/AJAX Routes ---

@app.route('/api/v1/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['display_name'] = user.display_name
            
            # Ενημέρωση last_seen
            user.last_seen = datetime.now()
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Login successful.'})
        else:
            return jsonify({'success': False, 'error': 'Invalid username or password.'}), 401

@app.route('/api/v1/sign_up', methods=['POST'])
def api_signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'success': False, 'error': 'All fields are required.'}), 400

    with app.app_context():
        # Έλεγχος αν υπάρχει ήδη
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already exists.'}), 409
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered.'}), 409
            
        try:
            new_user = User(username=username, email=email, display_name=username, role='user')
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Registration successful. Please log in.'})
        except IntegrityError:
            db.session.rollback()
            return jsonify({'success': False, 'error': 'A user with this data already exists.'}), 409
        except Exception as e:
            db.session.rollback()
            # print(f"Signup error: {e}")
            return jsonify({'success': False, 'error': 'An unknown error occurred during registration.'}), 500

@app.route('/api/v1/guest_login', methods=['POST'])
def guest_login():
    data = request.get_json()
    display_name = data.get('display_name')
    
    with app.app_context():
        allow_guests = Setting.query.filter_by(key='allow_guests').first()
        if not allow_guests or allow_guests.value.lower() != 'true':
            return jsonify({'success': False, 'error': 'Guest access is currently disabled.'}), 403

    if not display_name:
        return jsonify({'success': False, 'error': 'Display name is required.'}), 400
        
    # Έλεγχος αν το display name υπάρχει ήδη ως registered user
    if not is_username_available(display_name):
         return jsonify({'success': False, 'error': 'This name is taken by a registered user.'}), 409

    # Δημιουργία προσωρινής guest session
    session['user_id'] = f'GUEST-{uuid.uuid4()}'
    session['role'] = 'guest'
    session['display_name'] = display_name
    
    return jsonify({'success': True, 'message': 'Logged in as guest.'})

@app.route('/oauth/google')
def google_login():
    # Το redirect_uri τώρα θα είναι HTTPS λόγω του ProxyFix
    return oauth.google.authorize_redirect(url_for('google_authorize', _external=True))

@app.route('/oauth/google/authorize')
def google_authorize():
    try:
        # Το ProxyFix διασφαλίζει ότι η κλήση γίνεται με HTTPS
        token = oauth.google.authorize_access_token()
    except MismatchingStateError:
         return redirect(url_for('login')) # Απλά κάνε redirect
    except OAuthError as e:
         # print(f"An unexpected error occurred during authorization: {e}")
         return render_template('login.html', error=f"Google Login Failed: {e}")
    except Exception as e:
         # print(f"An unexpected error occurred during authorization: {e}")
         return render_template('login.html', error=f"Google Login Failed: {e}")
    
    user_info = oauth.google.parse_id_token(token)

    with app.app_context():
        user = User.query.filter_by(google_id=user_info['sub']).first()
        
        if user:
            # Υπάρχων χρήστης
            pass
        else:
            # Νέος χρήστης - ελέγχουμε αν υπάρχει ήδη με το email
            user = User.query.filter_by(email=user_info['email']).first()
            if user:
                 # Συνδέουμε τον υπάρχοντα λογαριασμό με το Google ID
                 user.google_id = user_info['sub']
            else:
                # Δημιουργούμε νέο χρήστη
                # Βρίσκουμε ένα μοναδικό display_name αν το όνομα χρήστη υπάρχει ήδη
                base_name = user_info.get('name', user_info['email'].split('@')[0])
                display_name = base_name
                counter = 1
                while User.query.filter_by(display_name=display_name).first():
                    display_name = f"{base_name}_{counter}"
                    counter += 1
                
                user = User(
                    google_id=user_info['sub'],
                    email=user_info['email'],
                    display_name=display_name,
                    role='user',
                    # Το username μπορεί να είναι None αν δεν το δίνει η Google ή το ορίζουμε ως display_name
                    username=display_name
                )
                db.session.add(user)
        
        user.avatar_url = user_info.get('picture', user.avatar_url) # Ενημέρωση avatar
        user.last_seen = datetime.now() # Ενημέρωση last_seen
        db.session.commit()
            
        session['user_id'] = user.id
        session['role'] = user.role
        session['display_name'] = user.display_name
        
        return redirect(url_for('chat'))

# --- Ρυθμίσεις Χρήστη (Settings) ---

@app.route('/check_login', methods=['GET'])
def check_login():
    """Επιστρέφει τα βασικά στοιχεία χρήστη για έλεγχο από το frontend/admin panel."""
    user_info = get_user_info_from_session()
    if user_info:
        return jsonify(user_info), 200
    return jsonify({'message': 'Not authenticated'}), 401

@app.route('/settings/get_all', methods=['GET'])
@requires_role('owner', 'admin')
def get_all_settings():
    with app.app_context():
        settings_list = Setting.query.all()
        settings_data = {s.key: s.value for s in settings_list}
        return jsonify(settings_data)

@app.route('/settings/set', methods=['POST'])
@requires_role('owner', 'admin')
def set_setting():
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')
    
    if not key or value is None:
        return jsonify({'success': False, 'message': 'Invalid data.'}), 400

    with app.app_context():
        setting = Setting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
            db.session.commit()
            return jsonify({'success': True, 'message': f'Setting {key} updated.'})
        else:
            return jsonify({'success': False, 'message': f'Setting {key} not found.'}), 404

@app.route('/settings/emoticons', methods=['GET'])
@login_required
def get_active_emoticons():
    with app.app_context():
        emoticons = Emoticon.query.filter_by(is_active=True).all()
        emoticon_list = [{'code': e.code, 'url': e.url} for e in emoticons]
        return jsonify(emoticon_list)

@app.route('/settings/all_emoticons', methods=['GET'])
@requires_role('owner', 'admin')
def get_all_emoticons_admin():
    with app.app_context():
        emoticons = Emoticon.query.all()
        emoticon_list = [{'id': e.id, 'code': e.code, 'url': e.url, 'is_active': e.is_active} for e in emoticons]
        return jsonify(emoticon_list)

@app.route('/settings/toggle_emoticon', methods=['POST'])
@requires_role('owner', 'admin')
def toggle_emoticon():
    data = request.get_json()
    emoticon_id = data.get('id')
    
    if not emoticon_id:
        return jsonify({'success': False, 'message': 'Missing emoticon ID.'}), 400
        
    with app.app_context():
        emoticon = db.session.get(Emoticon, emoticon_id)
        if emoticon:
            emoticon.is_active = not emoticon.is_active
            db.session.commit()
            return jsonify({'success': True, 'is_active': emoticon.is_active})
        else:
            return jsonify({'success': False, 'message': 'Emoticon not found.'}), 404
            
@app.route('/settings/add_emoticon', methods=['POST'])
@requires_role('owner', 'admin')
def add_emoticon():
    data = request.get_json()
    code = data.get('code')
    url = data.get('url')
    
    if not code or not url:
        return jsonify({'success': False, 'message': 'Code and URL are required.'}), 400
        
    with app.app_context():
        if Emoticon.query.filter_by(code=code).first():
            return jsonify({'success': False, 'message': 'Emoticon code already exists.'}), 409
            
        new_emoticon = Emoticon(code=code, url=url, is_active=True)
        db.session.add(new_emoticon)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Emoticon added successfully.'})

@app.route('/settings/set_avatar_url', methods=['POST'])
@login_required
def set_avatar_url():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401
    
    data = request.get_json()
    new_url = data.get('avatar_url')
    
    if not new_url:
        return jsonify({'success': False, 'message': 'Missing URL.'}), 400

    user_id = session['user_id']
    with app.app_context():
        # Guests (GUEST-...) δεν έχουν πεδίο στη βάση, οπότε δεν το αποθηκεύουμε.
        if session.get('role') == 'guest':
            # Για guests, απλά επιστρέφουμε επιτυχία (το JS θα το διαχειριστεί τοπικά αν χρειαστεί)
             return jsonify({'success': True, 'message': 'Avatar URL set for this session.'})
             
        user = db.session.get(User, user_id)
        if user:
            user.avatar_url = new_url
            db.session.commit()
            
            # 🚨 ΝΕΟ: Ενημερώνουμε όλους μέσω SocketIO για την αλλαγή avatar
            socketio.emit('user_avatar_updated', {
                'user_id': user.id,
                'avatar_url': new_url
            }, room='chat')
            
            return jsonify({'success': True, 'message': 'Avatar URL updated.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404


# --- SocketIO Events ---

@socketio.on('connect')
def handle_connect():
    """Διαχειρίζεται τη σύνδεση ενός client."""
    user_info = get_user_info_from_session()
    if not user_info:
        # Αποσύνδεση αν δεν υπάρχει session (π.χ. session expired)
        return False
        
    join_room('chat') # Όλοι μπαίνουν στο ίδιο δωμάτιο
    
    user_id = user_info['id']
    display_name = user_info['display_name']
    
    # 🚨 Ενημέρωση last_seen για εγγεγραμμένους χρήστες
    if user_info['role'] != 'guest':
        with app.app_context():
            user = db.session.get(User, user_id)
            if user:
                user.last_seen = datetime.now()
                db.session.commit()
    
    # Ενημέρωση όλων των clients για τον νέο online χρήστη
    emit('user_online', {
        'id': user_id, 
        'display_name': display_name, 
        'role': user_info['role'],
        'avatar_url': user_info['avatar_url']
    }, broadcast=True)
    
    # Επιστροφή της λίστας online χρηστών μόνο στον συνδεδεμένο χρήστη
    online_users = get_online_users()
    emit('online_users_list', {'users': online_users})
    
    print(f"Client connected: {display_name} ({user_id})")

@socketio.on('disconnect')
def handle_disconnect():
    """Διαχειρίζεται την αποσύνδεση ενός client."""
    user_info = get_user_info_from_session()
    if not user_info:
        return
        
    user_id = user_info['id']
    display_name = user_info['display_name']
    
    leave_room('chat')
    
    # Ενημέρωση όλων των clients για τον offline χρήστη
    emit('user_offline', {'id': user_id, 'display_name': display_name}, broadcast=True)
    
    print(f"Client disconnected: {display_name} ({user_id})")
    
@socketio.on('send_message')
def handle_message(data):
    """Διαχειρίζεται την αποστολή ενός νέου μηνύματος."""
    if 'user_id' not in session:
        return # Δεν επιτρέπεται η αποστολή μηνύματος χωρίς session
        
    user_id = session['user_id']
    user_role = session.get('role', 'guest')
    display_name = session.get('display_name', 'Guest')
    
    # Έλεγχος για το μήνυμα
    message_text = data['message'].strip()
    if not message_text:
        return
        
    # Έλεγχος μήκους
    max_len = 500 # default
    try:
        with app.app_context():
            max_len_setting = Setting.query.filter_by(key='max_message_length').first()
            if max_len_setting:
                max_len = int(max_len_setting.value)
    except:
        pass # Αγνόησε αν δεν βρει setting
        
    if len(message_text) > max_len:
         # Προαιρετικά: Μπορείτε να στείλετε ένα error πίσω στον αποστολέα
         return 
         
    # 🚨 1. Αποθήκευση του μηνύματος (μόνο για registered users)
    if user_role != 'guest':
        try:
            with app.app_context():
                user_instance = db.session.get(User, user_id)
                if not user_instance:
                    return # Μην σώζεις αν δεν υπάρχει χρήστης
                
                new_message = Message(
                    user_id=user_id, 
                    text=message_text,
                    timestamp=datetime.now()
                )
                db.session.add(new_message)
                db.session.commit()
        except Exception as e:
            # print(f"Error saving message: {e}") 
            pass # Συνέχισε με την εκπομπή, ακόμα κι αν η αποθήκευση αποτύχει
            
    # 🚨 2. Εκπομπή του μηνύματος στους clients (για εμφάνιση και ήχο)
    emit('new_message', {
        'message': message_text,
        'username': display_name,
        'role': user_role, # ΚΡΙΣΙΜΟ: Στέλνουμε το ρόλο για χρωματισμό
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }, broadcast=True)
    
    # print(f"Message from {display_name} ({user_role}): {message_text[:30]}...")

# --- Βοηθητική συνάρτηση για τη λίστα online χρηστών ---
def get_online_users():
    """Επιστρέφει τη λίστα των χρηστών που είναι συνδεδεμένοι μέσω SocketIO."""
    users = []
    # Ο SocketIO manager κρατάει τα sid (session IDs) για κάθε δωμάτιο.
    # Πρέπει να ανακτήσουμε τα στοιχεία του χρήστη από το Flask Session.
    
    # 🚨 Προσοχή: Δεν υπάρχει απευθείας τρόπος να αντιστοιχίσουμε το SID με το Flask Session
    # χωρίς να το αποθηκεύσουμε. Η απλοϊκή λύση είναι να χρησιμοποιήσουμε τα sessions.
    
    # Εδώ θα πρέπει να βρείτε έναν τρόπο να βρείτε ποια SIDs αντιστοιχούν σε ποια sessions
    # που περιέχουν τους χρήστες. 
    # ΠΡΟΣΟΧΗ: Η παρακάτω υλοποίηση είναι ψευδής/απλοϊκή, καθώς δεν παρακολουθεί 
    # αξιόπιστα ποιος client αντιστοιχεί σε ποιο Flask session SID.
    
    # Απλοϊκή υλοποίηση: Βρίσκουμε τους εγγεγραμμένους χρήστες που ήταν ενεργοί πρόσφατα
    # Αυτή η προσέγγιση είναι ΜΟΝΟ για development/simple chat, δεν είναι scalable.
    
    # Αντί να βασιστούμε στο SocketIO state, βασιζόμαστε στο Flask Session data 
    # (αν έχουμε αποθηκεύσει το SID/Session ID), Ή απλά επιστρέφουμε τους πάντες
    # με βάση το last_seen αν είναι admin panel.
    
    # Για το απλό chat, θα χρησιμοποιήσουμε μια κοινή πρακτική:
    # τη λίστα των ενεργών sessions που είναι *γνωστές* στο SocketIO
    
    # Λόγω της πολυπλοκότητας του session management σε συνδυασμό με το SocketIO,
    # θα χρησιμοποιήσουμε μια απλή προσέγγιση: την εκπομπή του user_online/user_offline
    # και το frontend θα διατηρεί τη λίστα (όπως φαίνεται στο main.js)
    
    # Εδώ, επιστρέφουμε τη λίστα των εγγεγραμμένων χρηστών που συνδέθηκαν πρόσφατα (π.χ. τελευταία ώρα)
    # Ή, πιο απλά, επιστρέφουμε όλους τους *συνδεδεμένους* χρήστες από τη μνήμη.
    # Εφόσον στέλνουμε 'user_online' και 'user_offline', το frontend φτιάχνει τη λίστα.
    
    # Για να φτιάξουμε την αρχική λίστα:
    if socketio.server:
        # Ανακτάμε όλα τα sessions που βρίσκονται στο δωμάτιο 'chat'
        sids_in_room = socketio.server.manager.rooms.get('/chat', {}).keys()
        
        # 🚨 Κρίσιμη Λύση: Πρέπει να ανακτήσουμε τα sessions από τη βάση (SQLAlchemy Session Store)
        # Αυτό είναι ΠΟΛΥ αργό, αλλά απαραίτητο για σωστή λίστα.
        
        # Επειδή αυτό απαιτεί να ψάχνουμε όλα τα sessions στη βάση, το αποφεύγουμε.
        # Θα αφήσουμε το frontend να διαχειριστεί τη λίστα μέσω των events,
        # αλλά για την αρχική φόρτωση του chat, θα βασιστούμε στο 'connect' event.
        
        # Μπορούμε να χρησιμοποιήσουμε ένα dictionary στη μνήμη του server (Global State)
        # για να κρατάμε τα στοιχεία των online χρηστών.

        current_users_data = {}
        
        # Αν η εφαρμογή είναι σε production (π.χ. Render) όπου τρέχει με `eventlet`, 
        # τότε η global list `online_users_map` θα λειτουργήσει.
        
        # Για να αποφύγουμε την πολυπλοκότητα του Session Store query:
        # Το frontend θα λάβει τη λίστα μέσω του 'online_users_list' event
        # (το οποίο εκπέμπεται στο 'connect' event).
        
        # Για να λειτουργήσει το `emit('online_users_list', {'users': online_users})` στο connect,
        # πρέπει να έχουμε ένα αξιόπιστο online_users_map.
        
        # ⚠️ Για την υλοποίηση με eventlet, θα χρησιμοποιήσουμε μια global map:
        global online_users_map
        if 'online_users_map' not in globals():
            online_users_map = {}
            
        # 🚨 ΣΗΜΕΙΩΣΗ: Πρέπει να ενημερώσουμε το 'handle_connect' και 'handle_disconnect' 
        # ώστε να διαχειρίζονται αυτό το map.

        # Επιστρέφουμε τη λίστα των χρηστών από το global map
        return list(online_users_map.values())
        
    return []

# 🚨 ΔΙΟΡΘΩΣΗ: Προσθέτουμε τη διαχείριση του global online_users_map
online_users_map = {} 

@socketio.on('connect')
def handle_connect_with_map():
    """Διαχειρίζεται τη σύνδεση ενός client και ενημερώνει το global map."""
    user_info = get_user_info_from_session()
    if not user_info:
        return False
        
    user_id = user_info['id']
    display_name = user_info['display_name']
    
    # 1. Ενημέρωση last_seen (όπως πριν)
    if user_info['role'] != 'guest':
        with app.app_context():
            user = db.session.get(User, user_id)
            if user:
                user.last_seen = datetime.now()
                db.session.commit()
    
    # 2. Εγγραφή στο δωμάτιο
    join_room('chat') 
    
    # 3. Ενημέρωση Global Map (χρησιμοποιούμε το SID ως κλειδί)
    sid = request.sid
    online_users_map[sid] = user_info
    
    # 4. Ενημέρωση όλων για τον νέο online χρήστη
    emit('user_online', user_info, broadcast=True)
    
    # 5. Επιστροφή της πλήρους λίστας μόνο στον συνδεδεμένο χρήστη
    # Εδώ πρέπει να στείλουμε ΟΛΟΥΣ τους χρήστες που είναι στο map, όχι μόνο τον καινούργιο.
    current_list = list(online_users_map.values())
    emit('online_users_list', {'users': current_list})
    
    # print(f"Client connected: {display_name} ({user_id}). Total online: {len(online_users_map)}")

@socketio.on('disconnect')
def handle_disconnect_with_map():
    """Διαχειρίζεται την αποσύνδεση ενός client και ενημερώνει το global map."""
    sid = request.sid
    user_info = online_users_map.pop(sid, None)
    
    if not user_info:
        return
        
    user_id = user_info['id']
    display_name = user_info['display_name']
    
    leave_room('chat')
    
    # Ενημέρωση όλων των clients για τον offline χρήστη
    emit('user_offline', {'id': user_id, 'display_name': display_name}, broadcast=True)
    
    # print(f"Client disconnected: {display_name} ({user_id}). Total online: {len(online_users_map)}")


if __name__ == '__main__':
    # Χρησιμοποιούμε eventlet ή gevent για production (όπως στο Render)
    # Αλλά για τοπικό dev, ο socketio.run είναι εντάξει
    # Επειδή η εντολή εκτέλεσης στο Render είναι 'eventlet', η χρήση του eventlet είναι σωστή.
    try:
        import eventlet
        eventlet.wsgi.server(eventlet.listen(('', int(os.environ.get("PORT", 5000)))), app)
    except ImportError:
        socketio.run(app, debug=True, port=int(os.environ.get("PORT", 5000)))

# ΤΕΛΟΣ server.py