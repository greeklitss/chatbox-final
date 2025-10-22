import os
import json
import uuid
import time

# Λεξικό για τη διαχείριση ενεργών χρηστών {user_id: username/data}
active_users = {}


from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from functools import wraps

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix 
from sqlalchemy import select 
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
app = Flask(__name__) 
# 🚨 ΚΡΙΣΙΜΗ ΠΡΟΣΘΗΚΗ: ΕΦΑΡΜΟΓΗ PROXYFIX για το Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1) 
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'a_default_secret_key_for_local_dev')


# --- Ρυθμίσεις Βάσης Δεδομένων ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Αντικατάσταση του postgres:// με postgresql:// για συμβατότητα με SQLAlchemy
    database_url = database_url.replace("postgres://", "postgresql://", 1)
    
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///local_db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🚨 Ρυθμίσεις για Session σε SQL DB (Διορθωμένες για Render/HTTPS)

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_TYPE'] = 'sqlalchemy' 
app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions' 
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True      # Τα cookies αποστέλλονται μόνο μέσω HTTPS (Απαραίτητο για Render)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # 🚨 ΔΙΟΡΘΩΣΗ: Αλλάχτηκε από 'None' σε 'Lax' για συμβατότητα με Google OAuth redirect
app.config["SESSION_USE_SIGNER"] = True # Συνιστάται

# 🚨 ΚΡΙΣΙΜΗ & ΟΡΙΣΤΙΚΗ ΔΙΟΡΘΩΣΗ: Περνάμε το αντικείμενο 'db' στο Flask-Session configuration
app.config['SESSION_SQLALCHEMY'] = db 

# --- ΣΥΝΔΕΣΗ ΤΩΝ EXTENSIONS ΜΕ ΤΗΝ ΕΦΑΡΜΟΓΗ (Application Factory Pattern) ---
db.init_app(app) # 1. Συνδέουμε το SQLAlchemy
sess.init_app(app) # 2. Συνδέουμε το Session

# 3. Συνδέουμε το OAuth
oauth.init_app(app) 

# Google config
oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
    redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI")
)


# --- FLASK-SOCKETIO ---
# 4. Συνδέουμε το SocketIO
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='eventlet',
# 🚨 ΚΡΙΣΙΜΟ: ΠΡΟΣΘΕΣΤΕ ΑΥΤΗ ΤΗ ΓΡΑΜΜΗ
    manage_session=False, 
    # 🚨 ΝΕΑ ΠΡΟΣΘΗΚΗ: Βοηθάει με τους Load Balancers
    path='/socket.io/', 
    transports=['websocket', 'polling'] 
)


# --- MODELS ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='user') # guest, user, admin, owner
    password_hash = db.Column(db.String(256), nullable=True) # Για local login
    avatar_url = db.Column(db.String(256), nullable=True)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc)) 
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password, check_password_hash=check_password_hash):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False

# 🚨 ΔΙΟΡΘΩΣΗ MODEL MESSAGE: Προσθέτουμε username, role, και αλλάζουμε το πεδίο text σε content. 
# user_id: Αλλάχτηκε σε String(100) και αφαιρέθηκε το ForeignKey για να υποστηρίξει GUEST IDs
class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False) # 🚨 ΔΙΟΡΘΩΣΗ: Αλλάχτηκε σε String
    
    username = db.Column(db.String(100), nullable=False) # 🚨 ΠΡΟΣΘΗΚΗ
    role = db.Column(db.String(50), nullable=False, default='user') # 🚨 ΠΡΟΣΘΗΚΗ

    content = db.Column(db.Text, nullable=False) # 🚨 ΔΙΟΡΘΩΣΗ: Αλλάχτηκε από 'text' σε 'content'
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc)) 

# 🚨 ΔΙΟΡΘΩΜΕΝΟ SETTING MODEL
class Setting(db.Model):
    __tablename__ = 'setting'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True) 
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(255))

    def __repr__(self):
        return f"<Setting {self.key}: {self.value}>"

class Emoticon(db.Model):
    __tablename__ = 'emoticon'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    url = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)


# --- HELPER CLASS/FUNCTION ΓΙΑ GUEST LOGIN ---
class GuestUser:
    """Προσωρινή κλάση που μιμείται τη δομή του User για τους επισκέπτες."""
    def __init__(self, user_id, display_name):
        self.id = user_id
        self.display_name = display_name
        self.role = 'guest'
        self.avatar_url = None
        self.color = '#AAAAAA' # Default γκρι χρώμα για guests
        self.is_active = True

def get_current_user_or_guest():
    """
    Ανακτά τον χρήστη από τη βάση δεδομένων ή δημιουργεί ένα προσωρινό 
    αντικείμενο GuestUser αν η συνεδρία έχει role 'guest'.
    """
    user_id = session.get('user_id')
    role = session.get('role')

    if role == 'guest' and user_id:
        # Retrieve display_name from session for guests
        display_name = session.get('display_name', f"Guest-{user_id.split('-')[-1]}")
        return GuestUser(user_id, display_name)

    elif user_id:
        # Regular user, fetch from DB
        return db.session.get(User, user_id)

    return None

# --- HELPER FUNCTIONS ---
def requires_role(*roles):
    """Decorator που ελέγχει αν ο χρήστης έχει έναν από τους απαιτούμενους ρόλους."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            with app.app_context():
                user = get_current_user_or_guest() # 🚨 Χρήση helper function
                if user and user.role in roles:
                    return f(*args, **kwargs)
                
            return jsonify({'error': 'Unauthorized or Insufficient Role'}), 403
        return decorated
    return wrapper


# --- ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with app.app_context():
        user = get_current_user_or_guest()
        
    return render_template('chat.html', user=user) 


# --- LOCAL LOGIN & SIGN UP ---
@app.route('/api/v1/login', methods=['POST']) 
def local_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Missing email or password.'}), 400 
    
    with app.app_context():
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['display_name'] = user.display_name
            return jsonify({'success': True, 'redirect': url_for('chat')})
        else:
            return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/v1/sign_up', methods=['POST'])
def local_sign_up():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    display_name = data.get('username')     
    
    if not email or not password or not display_name:
        return jsonify({'error': 'Missing email, password, or display name.'}), 400

    with app.app_context():
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'User with this email already exists.'}), 409

        try:
            new_user = User(
                email=email,
                display_name=display_name,
                role='user' 
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'User created successfully. You can now log in.'}), 201

        except Exception as e:
            db.session.rollback()
            print(f"Database error during sign up: {e}") 
            return jsonify({'error': 'An internal server error occurred during registration.'}), 500

# --- GOOGLE AUTH ROUTES (Συμπληρωμένες) ---

@app.route('/login/google')
def login_google():
    return oauth.google.authorize_redirect(redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI"))

@app.route('/login/google/authorize') 
def authorize_google():
    try:
        token = oauth.google.authorize_access_token()
        nonce = session.pop('nonce', None) 
        user_info = oauth.google.parse_id_token(token, nonce=nonce)

    except MismatchingStateError:
        return redirect(url_for('login'))
    except OAuthError as e:
        print(f"OAuth Error: {e}")
        return redirect(url_for('login'))

    email = user_info.get('email')
    display_name = user_info.get('name')
    avatar_url = user_info.get('picture')

    with app.app_context():
        user = User.query.filter_by(email=email).first()

        if user is None:
            user = User(
                email=email,
                display_name=display_name,
                role='user',
                avatar_url=avatar_url,
            )
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                return redirect(url_for('login'))

        session['user_id'] = user.id
        session['role'] = user.role
        session['display_name'] = user.display_name
        return redirect(url_for('chat'))


# --- GUEST LOGIN ROUTE ---
@app.route('/login/guest', methods=['POST'])
def login_guest():
    guest_uuid = f"GUEST-{uuid.uuid4().hex[:8]}"
    display_name = f"Guest-{uuid.uuid4().hex[:4].upper()}"

    session.clear() 
    session['user_id'] = guest_uuid
    session['role'] = 'guest'
    session['display_name'] = display_name 
    
    return redirect(url_for('chat'))


# --- LOGOUT ---
@app.route('/logout')
def logout():
    session.clear() 
    return redirect(url_for('login'))


# --- SOCKETIO EVENTS (ΚΡΙΣΙΜΕΣ ΔΙΟΡΘΩΣΕΙΣ) ---

@socketio.on('connect')
def handle_connect():
    s_id = request.args.get('session_id')
    
    if s_id:
        session.sid = s_id 
        session.get('user_id') # Φορτώνει τη session
        session.modified = True 
        
    print(f'Client connected: {request.sid}, User ID: {session.get("user_id")}')

@socketio.on('join')
def on_join():
    """Χειρισμός σύνδεσης στο κύριο chat room."""
    
    if not session.get('user_id'):
         print(f"ERROR: Client tried to join but session not loaded.")
         return
         
    join_room('chat') 
    
    username = session.get('display_name')
    if username:
        emit('status_message', {'msg': f'{username} joined the chat.'}, 
             room='chat', include_self=False)
    
    print(f"{username} joined room 'chat'")
    
    # 🚨 ΚΡΙΣΙΜΟ: Φόρτωση Ιστορικού Μηνυμάτων
    with app.app_context():
        recent_messages = db.session.execute(
            db.select(Message)
            .order_by(Message.timestamp.desc())
            .limit(100)
        ).scalars().all()
        
        recent_messages.reverse() 
        
        history_data = [
            {
                'username': msg.username,
                'msg': msg.content, 
                'timestamp': msg.timestamp.isoformat(),
                'role': msg.role,
                'user_id': msg.user_id 
            }
            for msg in recent_messages
        ]
        
        emit('history', history_data, room=request.sid)


@socketio.on('message')
def handle_message(data):
    user_id = session.get('user_id')
    username = session.get('display_name')
    role = session.get('role', 'user')
     
    if not user_id or not username:
        return
     
    msg = data.get('msg')
    if not msg:
        return

    # 🚨 ΚΡΙΣΙΜΟ: Αποθήκευση του μηνύματος στη βάση δεδομένων (τώρα το μοντέλο είναι σωστό)
    with app.app_context():
        new_message = Message(
            user_id=user_id,
            username=username, 
            role=role,         
            content=msg,       
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(new_message)
        db.session.commit()
        
    # 3. Εκπομπή: Στέλνουμε το μήνυμα πίσω
    emit('message', {
        'user_id': user_id,
        'username': username,
        'msg': msg,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'role': role
    }, room='chat')
    
    print(f"DEBUG: Server received and emitted message from {username}: {msg}")


# --- ADMIN PANEL & SETTINGS ROUTES (Διορθωμένες) ---

@app.route('/check_login')
def check_login():
    """Ελέγχει αν υπάρχει ενεργή συνεδρία χρήστη."""
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'user_id': session['user_id'], 'role': session.get('role')}), 200
    else:
        return jsonify({'logged_in': False}), 401 

@app.route('/admin_panel')
@requires_role('owner', 'admin')
def admin_panel():
    """Εμφανίζει το βασικό Admin Panel με τη λίστα των χρηστών."""
    with app.app_context():
        users = User.query.all()
        return render_template('admin_panel.html', users=users)

@app.route('/admin/set_role', methods=['POST'])
@requires_role('owner', 'admin')
def set_user_role():
    data = request.get_json()
    user_id = data.get('user_id')
    new_role = data.get('role')
    
    if not user_id or new_role not in ['user', 'admin', 'owner']:
        return jsonify({'success': False, 'message': 'Invalid data.'}), 400

    with app.app_context():
        user = db.session.get(User, user_id)
        if user:
            if user.id == session['user_id']:
                 return jsonify({'success': False, 'message': 'Cannot change your own role.'}), 403
            
            user.role = new_role
            db.session.commit()
            return jsonify({'success': True, 'message': f'User {user.display_name} role set to {new_role}.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

@app.route('/api/settings', methods=['GET'])
def get_settings():
    settings_data = {}
    with app.app_context():
        try:
            settings = db.session.execute(db.select(Setting)).scalars().all()
        except ProgrammingError:
            settings = [] 
            
        for setting in settings:
            if setting.value.lower() == 'true':
                val = True
            elif setting.value.lower() == 'false':
                val = False
            else:
                val = setting.value
            settings_data[setting.key] = val
    
    return jsonify(settings_data)

@app.route('/api/admin/set_setting', methods=['POST'])
@requires_role('owner', 'admin')
def set_setting():
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')

    if not key or value is None:
        return jsonify({'success': False, 'message': 'Missing key or value.'}), 400

    try:
        with app.app_context():
            stmt = select(Setting).filter_by(key=key)
            setting = db.session.scalar(stmt)
            value_str = str(value)

            if setting:
                setting.value = value_str
            else:
                new_setting = Setting(key=key, value=value_str)
                db.session.add(new_setting)
            
            db.session.commit()
            
            return jsonify({'success': True, 'message': f'Setting {key} updated.'})

    except Exception as e:
        db.session.rollback()
        print(f"FATAL DB ERROR IN SETTING: {e}") 
        return jsonify({'success': False, 'error': 'Internal database error during save.'}), 500

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
            return jsonify({'success': False, 'message': 'User not found.'}), 40
            

# --- ΠΡΟΣΘΗΚΗ: ΚΡΙΣΙΜΟΣ ΕΛΕΓΧΟΣ ΔΗΜΙΟΥΡΓΙΑΣ ΒΑΣΗΣ ---
# Εκτελείται όταν φορτώνεται η εφαρμογή (ακόμα και από gunicorn/Render)
with app.app_context():
    # Δημιουργεί όλους τους πίνακες (User, Message, Setting κ.λπ.) αν δεν υπάρχουν
    db.create_all() 
    
    # 🚨 Εάν έχετε τις συναρτήσεις αρχικοποίησης ρυθμίσεων/emoticons, προσθέστε τις εδώ:
    # initialize_settings() 
    # initialize_emoticons() 
    
    # Αυτός ο κώδικας θα εκτελεστεί μία φορά στην εκκίνηση του service
    # και θα διορθώσει το UndefinedTable.


# --- MAIN EXECUTION ---
if __name__ == '__main__':
    # 🚨 Η κλήση db_setup_check(app) αφαιρέθηκε, γίνεται πλέον από το db_init.py
    print("Starting Flask/SocketIO Server...")
    socketio.run(app, debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))
