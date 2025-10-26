import os
import json
import uuid
import time
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from functools import wraps

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix 
from sqlalchemy import select, desc 
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
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'a_default_secret_key_for_local_dev')


# --- Ρυθμίσεις Βάσης Δεδομένων (ΔΙΟΡΘΩΜΕΝΟ) ---
database_url = os.environ.get("DATABASE_URL")

if database_url:
    # 1. Αντικατάσταση του postgres:// με postgresql://
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
        
    # 🚨 2. ΚΡΙΣΙΜΟ: Προσθήκη της παραμέτρου SSL
    if "sslmode=require" not in database_url:
        separator = '&' if '?' in database_url else '?'
        database_url = f"{database_url}{separator}sslmode=require"
        
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///local_db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🚨 Ρυθμίσεις για Session σε SQL DB
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_TYPE'] = 'sqlalchemy' 
app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions' 
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True      
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   
app.config["SESSION_USE_SIGNER"] = True 
app.config['SESSION_SQLALCHEMY'] = db 

# --- ΣΥΝΔΕΣΗ ΤΩΝ EXTENSIONS ΜΕ ΤΗΝ ΕΦΑΡΜΟΓΗ (Application Factory Pattern) ---
db.init_app(app) 
sess.init_app(app) 
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
    manage_session=False, 
    path='/socket.io/', 
    transports=['websocket', 'polling'] 
)


# --- DATABASE MODELS ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='user') # guest, user, admin, owner
    password_hash = db.Column(db.String(256), nullable=True) 
    avatar_url = db.Column(db.String(256), nullable=True)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc)) 
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False) 
    
    username = db.Column(db.String(100), nullable=False) 
    role = db.Column(db.String(50), nullable=False, default='user') 

    content = db.Column(db.Text, nullable=False) 
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    color = db.Column(db.String(7), nullable=True, default='#FFFFFF')

class Setting(db.Model):
    __tablename__ = 'setting'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True) 
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(255))
    description = db.Column(db.String(255), nullable=True) 

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
        display_name = session.get('display_name', f"Guest-{user_id.split('-')[-1]}")
        return GuestUser(user_id, display_name)

    elif user_id:
        return db.session.get(User, user_id)

    return None

# --- HELPER FUNCTIONS & DECORATORS ---
def requires_role(*roles):
    """Decorator που ελέγχει αν ο χρήστης έχει έναν από τους απαιτούμενους ρόλους."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            with app.app_context():
                user = get_current_user_or_guest() 
                if user and user.role in roles:
                    return f(*args, **kwargs)
                
            return jsonify({'error': 'Unauthorized or Insufficient Role'}), 403
        return decorated
    return wrapper

# 🚨 ΝΕΟ: GLOBAL DATA & ΛΟΓΙΚΗ ONLINE ΧΡΗΣΤΩΝ
active_sessions = {} # {sid: {'user_id': id, 'display_name': name, 'role': role, 'color': color, 'guest_id': guest_id}}

def get_online_users_data():
    """Συλλέγει τα δεδομένα των online χρηστών."""
    users_data = []
    unique_user_identifiers = set() 
    
    for sess_id, user_info in active_sessions.items():
        identifier = user_info.get('user_id') if user_info.get('user_id') else user_info.get('guest_id')
        
        if identifier and identifier not in unique_user_identifiers:
            unique_user_identifiers.add(identifier)
            users_data.append({
                'display_name': user_info.get('display_name', 'Guest'),
                'role': user_info.get('role', 'guest'),
                'color': user_info.get('color', '#AAAAAA') 
            })
            
    # Ταξινόμηση: owner/admin στην κορυφή
    role_order = {'owner': 0, 'admin': 1, 'user': 2, 'guest': 3}
    users_data.sort(key=lambda x: (role_order.get(x['role'], 99), x['display_name']))
    
    return {
        'count': len(unique_user_identifiers),
        'users': users_data
    }

def emit_online_users():
    """Εκπέμπει την ενημερωμένη λίστα online χρηστών σε όλους."""
    data = get_online_users_data()
    socketio.emit('update_online_users', data, room='chat')


# 🚨 ΑΡΧΙΚΟΠΟΙΗΣΗ ΡΥΘΜΙΣΕΩΝ & EMOTICONS
def initialize_settings():
    """Δημιουργεί default ρυθμίσεις αν δεν υπάρχουν."""
    with app.app_context():
        default_settings = {
            'chat_name': ('AkoY Me Chat', 'Το όνομα της εφαρμογής chat.'),
            'emoticons_enabled': ('True', 'Ενεργοποίηση/Απενεργοποίηση Emoticons (True/False).'),
            'max_message_length': ('500', 'Μέγιστο μήκος μηνύματος.')
        }
        
        for key, (default_value, description) in default_settings.items():
            if not db.session.execute(select(Setting).filter_by(key=key)).scalar_one_or_none():
                new_setting = Setting(key=key, value=default_value, description=description)
                db.session.add(new_setting)
                print(f"Initialized Setting: {key}")
        db.session.commit()

def initialize_emoticons():
    """Δημιουργεί default emoticons αν δεν υπάρχουν."""
    with app.app_context():
        # Αυτό το table μπορεί να χρησιμοποιηθεί για Admin Panel Emoticon Management, αν και το front-end χρησιμοποιεί CDN.
        default_emoticons = [
            (':smile:', 'https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f603.png'),
            (':heart:', 'https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/2764.png')
        ]
        
        for code, url in default_emoticons:
            if not db.session.execute(select(Emoticon).filter_by(code=code)).scalar_one_or_none():
                new_emoticon = Emoticon(code=code, url=url)
                db.session.add(new_emoticon)
                print(f"Initialized Emoticon: {code}")
        db.session.commit()


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
            is_first_user = db.session.execute(db.select(db.func.count(User.id))).scalar() == 0
            role = 'owner' if is_first_user else 'user'
            
            new_user = User(
                email=email,
                display_name=display_name,
                role=role 
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'User created successfully. You can now log in.'}), 201

        except Exception as e:
            db.session.rollback()
            print(f"Database error during sign up: {e}") 
            return jsonify({'error': 'An internal server error occurred during registration.'}), 500

# --- GOOGLE AUTH ROUTES ---

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
        session.get('user_id') 
        session.modified = True 
        
    print(f'Client connected: {request.sid}, User ID: {session.get("user_id")}')


@socketio.on('join')
def on_join():
    """Χειρισμός σύνδεσης στο κύριο chat room, φόρτωση ιστορικού & ενημέρωση online λίστας."""
    
    user_id = session.get('user_id')
    
    if not user_id:
         print(f"ERROR: Client tried to join but session not loaded.")
         return
         
    join_room('chat') 
    
    # 🚨 ΝΕΟ: Ενημέρωση active_sessions & συλλογή δεδομένων
    with app.app_context():
        user = get_current_user_or_guest()
        
        session_info = {
            'user_id': user.id if user.role != 'guest' else None,
            'guest_id': user.id if user.role == 'guest' else None,
            'display_name': user.display_name,
            'role': user.role,
            # Εδώ θα μπορούσαμε να πάρουμε το χρώμα αν το είχαμε αποθηκεύσει στο session/DB
            'color': user.color if user.role == 'guest' else '#FFFFFF' 
        }
        active_sessions[request.sid] = session_info

    username = session.get('display_name')
    if username:
        emit('status_message', {'msg': f'{username} joined the chat.'}, 
             room='chat', include_self=False)
    
    print(f"{username} joined room 'chat'")
    
    # 🚨 ΚΑΛΕΣΤΕ: Εκπομπή της ενημερωμένης λίστας σε όλους
    emit_online_users()
    
    # Φόρτωση Ιστορικού Μηνυμάτων
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
                'user_id': msg.user_id,
                'color': msg.color # 👈 Προστέθηκε
            }
            for msg in recent_messages
        ]
        
        emit('history', history_data, room=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    username = active_sessions.get(request.sid, {}).get('display_name', 'A user')
    
    # 🚨 ΝΕΟ: Διαγραφή από active_sessions
    if request.sid in active_sessions:
        del active_sessions[request.sid]
        
    # 🚨 ΚΑΛΕΣΤΕ: Εκπομπή της ενημερωμένης λίστας σε όλους
    emit_online_users()
    
    # Ενημέρωση των άλλων χρηστών
    emit('status_message', {'msg': f'{username} left the chat.'}, 
         room='chat', include_self=False)
    
    leave_room('chat')
    print(f"{username} left the chat (SID: {request.sid})")


@socketio.on('message')
def handle_message(data):
    user_id = session.get('user_id')
    
    if not user_id:
        return
    
    msg_content = data.get('msg')
    # 🚨 ΝΕΟ: Χρησιμοποιούμε default color αν δεν σταλεί
    color = data.get('color') or '#FFFFFF' 

    if not msg_content:
        return

    with app.app_context():
        user = get_current_user_or_guest() 
        if not user:
            return

        # 🚨 ΔΙΟΡΘΩΣΗ: Σύνταξη και αποθήκευση χρώματος
        new_message = Message(
            user_id=user.id,
            username=user.display_name, 
            role=user.role,       
            content=msg_content,     
            timestamp=datetime.now(timezone.utc),
            color=color 
        )
        db.session.add(new_message)
        db.session.commit()
            
    # 3. Εκπομπή: Στέλνουμε το μήνυμα πίσω (Μαζί με τα κρίσιμα data)
    emit('message', { 
        'user_id': user_id,
        'username': user.display_name,
        'msg': msg_content,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'role': user.role,
        'avatar_url': user.avatar_url if hasattr(user, 'avatar_url') and user.avatar_url else '/static/default_avatar.png',
        'color': color 
    }, room='chat')

    print(f"DEBUG: Server received and emitted message from {user.display_name}: {msg_content}")

# --- ADMIN PANEL & SETTINGS ROUTES ---

@app.route('/check_login')
def check_login():
    """Ελέγχει αν υπάρχει ενεργή συνεδρία χρήστη."""
    if 'user_id' in session:
        return jsonify({'logged_in': True, 'user_id': session['user_id'], 'role': session.get('role'), 'display_name': session.get('display_name')}), 200
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
    
    if not user_id or new_role not in ['user', 'admin', 'owner', 'guest']:
        return jsonify({'success': False, 'message': 'Invalid data.'}), 400

    with app.app_context():
        user = db.session.get(User, user_id)
        if user:
            if user.id == session['user_id']:
                 return jsonify({'success': False, 'message': 'Cannot change your own role.'}), 403
            
            current_user = db.session.get(User, session['user_id'])
            if (new_role in ['owner', 'admin'] or user.role in ['owner', 'admin']) and current_user.role != 'owner':
                return jsonify({'success': False, 'message': 'Only the owner can manage admin/owner roles.'}), 403
                
            user.role = new_role
            db.session.commit()
            
            # 🚨 ΝΕΟ: Ενημερώνουμε τους online χρήστες για την αλλαγή ρόλου
            emit_online_users() 
            
            return jsonify({'success': True, 'message': f'User {user.display_name} role set to {new_role}.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

@app.route('/api/settings', methods=['GET'])
def get_settings():
    settings_data = {}
    with app.app_context():
        try:
            settings = db.session.execute(db.select(Setting)).scalars().all()
        except ProgrammingError as e:
            print(f"ProgrammingError fetching settings: {e}")
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
                new_setting = Setting(key=key, value=value_str, description="Custom setting added by admin.")
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
            return jsonify({'success': False, 'message': 'User not found.'}), 404
            

# --- ΠΡΟΣΘΗΚΗ: ΚΡΙΣΙΜΟΣ ΕΛΕΓΧΟΣ ΔΗΜΙΟΥΡΓΙΑΣ ΒΑΣΗΣ ---
with app.app_context():
    db.create_all() 
    initialize_settings() 
    initialize_emoticons() 
    

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    print("Starting Flask/SocketIO Server...")
    socketio.run(app, debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))