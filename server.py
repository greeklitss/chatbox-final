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

    def check_password(self, password):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc)) 
    user = db.relationship('User', backref='messages')

# 🚨 ΔΙΟΡΘΩΜΕΝΟ SETTING MODEL: Χρησιμοποιεί το 'key' ως PK και μεγαλύτερο 'value' field
class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=True) # Μπορεί να αποθηκεύει 'True'/'False' ως string

    def __repr__(self):
        return f"<Setting {self.key}: {self.value}>

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
        user = get_current_user_or_guest() # 🚨 ΝΕΑ ΧΡΗΣΗ: Υποστήριξη Guest
        # 🚨 ΔΙΟΡΘΩΣΗ: Αφαιρούμε την ανάγνωση ρυθμίσεων από εδώ, θα γίνεται μέσω AJAX/API
        # current_settings = {s.key: s.value for s in Setting.query.all()}
        
    return render_template('chat.html', user=user) # Αφαιρέθηκε το current_settings


# --- LOCAL LOGIN (Η ΣΩΣΤΗ ΔΙΑΔΡΟΜΗ ΓΙΑ ΣΥΝΔΕΣΗ) ---
@app.route('/api/v1/login', methods=['POST']) 
def local_login():
    """Διαχειρίζεται την τοπική σύνδεση χρήστη."""
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
            session['display_name'] = user.display_name # Προσθήκη display_name για συνέπεια
            return jsonify({'success': True, 'redirect': url_for('chat')})
        else:
            return jsonify({'error': 'Invalid credentials'}), 401

# --- LOCAL SIGN UP (Η ΜΟΝΗ & ΣΩΣΤΗ ΔΙΑΔΡΟΜΗ ΓΙΑ ΕΓΓΡΑΦΗ) ---
@app.route('/api/v1/sign_up', methods=['POST'])
def local_sign_up():
    """Διαχειρίζεται την τοπική εγγραφή χρήστη."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    display_name = data.get('username')     
    
    # 1. Έλεγχος για ελλιπή στοιχεία
    if not email or not password or not display_name:
        return jsonify({'error': 'Missing email, password, or display name.'}), 400

    with app.app_context():
        # 2. Έλεγχος αν ο χρήστης υπάρχει
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'User with this email already exists.'}), 409

        # 3. Δημιουργία νέου χρήστη
        try:
            new_user = User(
                email=email,
                display_name=display_name,
                role='user' 
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            # Επιτυχία: Επιστρέφουμε μήνυμα επιτυχίας
            return jsonify({'success': True, 'message': 'User created successfully. You can now log in.'}), 201

        except Exception as e:
            db.session.rollback()
            print(f"Database error during sign up: {e}") 
            return jsonify({'error': 'An internal server error occurred during registration.'}), 500

# --- GOOGLE AUTH ROUTES ---

@app.route('/login/google')
def login_google():
    # Χρησιμοποιεί το GOOGLE_REDIRECT_URI που ορίστηκε στο περιβάλλοντος
    return oauth.google.authorize_redirect(redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI"))

# 🚨 ΔΙΟΡΘΩΣΗ: ΠΛΗΡΗΣ ΛΟΓΙΚΗ ΓΙΑ ΤΟ GOOGLE CALLBACK
@app.route('/login/google/authorize') 
def authorize_google():
    """Διαχειρίζεται την επιστροφή από το Google OAuth και συνδέει τον χρήστη."""
    try:
        # 1. Παίρνουμε το token και τα user info
        token = oauth.google.authorize_access_token()
        
        # 🚨 ΔΙΟΡΘΩΣΗ: Προσθήκη nonce και σωστό διάστημα (indentation)
        nonce = session.pop('nonce', None) 
        user_info = oauth.google.parse_id_token(token, nonce=nonce)

    except MismatchingStateError:
        # Εάν χαθεί το state (π.χ. λόγω λάθους SAMESITE cookie), τον στέλνουμε πίσω
        return redirect(url_for('login'))
    except OAuthError as e:
        # Χειρισμός άλλων OAuth σφαλμάτων
        print(f"OAuth Error: {e}")
        return redirect(url_for('login'))

    # 2. Επεξεργασία επιτυχούς σύνδεσης
    email = user_info.get('email')
    display_name = user_info.get('name')
    avatar_url = user_info.get('picture')

    # ... Ο υπόλοιπος κώδικας σας για την εύρεση/δημιουργία χρήστη ...

    with app.app_context():
        # 3. Αναζήτηση χρήστη στη βάση δεδομένων
        user = User.query.filter_by(email=email).first()

        if user is None:
            # 4. Εγγραφή νέου χρήστη
            user = User(
                email=email,
                display_name=display_name,
                role='user', # Default role
                avatar_url=avatar_url,
            )
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                # Εάν αποτύχει η εγγραφή (π.χ. λόγω unique constraint), τον στέλνουμε πίσω
                return redirect(url_for('login'))


        # 5. Ορισμός Session (για υπάρχοντα ή νέο χρήστη)
        session['user_id'] = user.id
        session['role'] = user.role
        session['display_name'] = user.display_name
        # 6. Τελική ανακατεύθυνση στο chat
        return redirect(url_for('chat'))


# --- GUEST LOGIN ROUTE ---
@app.route('/login/guest', methods=['POST'])
def login_guest():
    """Συνδέει τον χρήστη ως προσωρινός επισκέπτης (guest)."""
    # Δημιουργία μοναδικού, μη-DB user ID και ονόματος
    guest_uuid = f"GUEST-{uuid.uuid4().hex[:8]}"
    display_name = f"Guest-{uuid.uuid4().hex[:4].upper()}"

    # Ορισμός session variables
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


# --- SOCKETIO EVENTS ---

# server.py (Προσθήκη στο τέλος του αρχείου, πριν το if __name__ == '__main__':)

@socketio.on('connect')
def handle_connect():
    # Αυτό εκτελείται μόλις ο client συνδεθεί, αλλά δεν μπαίνει ακόμα στο chat room.
    print(f'Client connected: {request.sid}')

@socketio.on('join')
def on_join():
    """Χειρισμός σύνδεσης στο κύριο chat room."""
    # Κάνουμε τον χρήστη join στο 'chat' room για να λαμβάνει μηνύματα
    join_room('chat') 
    
    # 🚨 Ενημερώνουμε όλους ότι συνδέθηκε ο χρήστης
    if session.get('username'):
        username = session['username']
        # Ενημερώνουμε τους άλλους, αλλά όχι τον ίδιο (include_self=False)
        emit('status_message', {'msg': f'{username} joined the chat.'}, 
             room='chat', include_self=False)
    
    print(f"{session.get('username')} joined room 'chat'")
    # (Εδώ θα έπρεπε να καλείται μια συνάρτηση για την ενημέρωση online list)

@socketio.on('message')
def handle_message(data):
    """Χειρισμός incoming μηνυμάτων και εκπομπή τους."""
    user_id = session.get('user_id')
    username = session.get('username')
    
    if not user_id or not username:
        return # Δεν επιτρέπουμε μηνύματα χωρίς ταυτότητα
        
    msg = data.get('msg')
    
    # 🚨 ΕΚΠΟΜΠΗ: Στέλνουμε το μήνυμα πίσω σε ΟΛΟΥΣ τους χρήστες στο 'chat' room
    # Το 'message' event θα το διαχειριστεί ο client (main.js)
    emit('message', {
        'user_id': user_id,
        'username': username,
        'msg': msg,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }, room='chat')
    
@socketio.on('disconnect')
def handle_disconnect():
    """Χειρισμός αποσύνδεσης χρήστη."""
    username = session.get('username', 'A Guest')
    leave_room('chat')
    
    # 🚨 Ενημερώνουμε όλους ότι αποσυνδέθηκε ο χρήστης
    emit('status_message', {'msg': f'{username} left the chat.'}, room='chat')
    print(f'Client disconnected: {request.sid}')

# --- ADMIN PANEL & SETTINGS ROUTES ---

@app.route('/check_login')
def check_login():
    """Ελέγχει αν υπάρχει ενεργή συνεδρία χρήστη."""
    if 'user_id' in session:
        # Επιστρέφει επιτυχία αν υπάρχει user_id στη session
        return jsonify({'logged_in': True, 'user_id': session['user_id'], 'role': session.get('role')}), 200
    else:
        # Επιστρέφει αποτυχία αν ο χρήστης δεν είναι συνδεδεμένος
        return jsonify({'logged_in': False}), 401 

@app.route('/admin_panel')
@requires_role('owner', 'admin')
def admin_panel():
    """Εμφανίζει το βασικό Admin Panel με τη λίστα των χρηστών."""
    with app.app_context():
        # Παίρνουμε όλους τους χρήστες 
        users = User.query.all()
        return render_template('admin_panel.html', users=users)

@app.route('/admin/set_role', methods=['POST'])
@requires_role('owner', 'admin')
def set_user_role():
    """Επιτρέπει στον admin να αλλάξει τον ρόλο ενός άλλου χρήστη (μέσω AJAX)."""
    data = request.get_json()
    user_id = data.get('user_id')
    new_role = data.get('role')
    
    if not user_id or new_role not in ['user', 'admin', 'owner']:
        return jsonify({'success': False, 'message': 'Invalid data.'}), 400

    with app.app_context():
        user = db.session.get(User, user_id)
        if user:
            # Απαγόρευση αλλαγής του ρόλου του ίδιου του χρήστη μέσω αυτής της διαδρομής
            if user.id == session['user_id']:
                 return jsonify({'success': False, 'message': 'Cannot change your own role.'}), 403
            
            user.role = new_role
            db.session.commit()
            return jsonify({'success': True, 'message': f'User {user.display_name} role set to {new_role}.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

# --- ΝΕΕΣ SETTINGS ROUTES ΓΙΑ ΤΟ ADMIN PANEL (ΕΠΑΝΑΦΕΡΟΝΤΑΙ) ---

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Παρέχει όλες τις ρυθμίσεις στο frontend (για Admin Panel & Chat)."""
    settings_data = {}
    with app.app_context():
        try:
            settings = db.session.execute(db.select(Setting)).scalars().all()
        except ProgrammingError:
            settings = [] # Αν ο πίνακας δεν υπάρχει
            
        for setting in settings:
            # Μετατρέπουμε τα strings 'True'/'False' σε booleans (ή κρατάμε το string)
            if setting.value.lower() == 'true':
                val = True
            elif setting.value.lower() == 'false':
                val = False
            else:
                val = setting.value
            settings_data[setting.key] = val
    
    return jsonify(settings_data)



# server.py (περίπου γραμμή 505)

@app.route('/api/admin/set_setting', methods=['POST'])
@requires_role('owner', 'admin') # 🚨 Βεβαιωθείτε ότι ο ρόλος σας είναι σωστός
def set_setting():
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')
    
    if not key or value is None:
        return jsonify({'success': False, 'error': 'Missing key or value.'}), 400

    try:
        with app.app_context():
            # 1. Προσπαθούμε να βρούμε την υπάρχουσα ρύθμιση
            # Χρησιμοποιούμε text() για ευκολότερο συμβατό SQL
            stmt = text("SELECT id, value FROM setting WHERE key = :key").bindparams(key=key)
            result = db.session.execute(stmt).fetchone()
            
            if result:
                # 2. Αν υπάρχει, την ενημερώνουμε (UPDATE)
                update_stmt = text("UPDATE setting SET value = :value WHERE key = :key").bindparams(value=value, key=key)
                db.session.execute(update_stmt)
            else:
                # 3. Αν δεν υπάρχει, την εισάγουμε (INSERT)
                insert_stmt = text("INSERT INTO setting (key, value) VALUES (:key, :value)").bindparams(key=key, value=value)
                db.session.execute(insert_stmt)
            
            # 4. Ολοκληρώνουμε τη συναλλαγή
            db.session.commit()
            
            # 5. Ενημερώνουμε όλους τους συνδεδεμένους χρήστες για την αλλαγή
            socketio.emit('setting_updated', {'key': key, 'value': value}, room='chat')
            
            return jsonify({'success': True, 'message': f'Setting {key} updated.'})

    except Exception as e:
        db.session.rollback()
        # 🚨 ΚΑΤΑΓΡΑΦΗ ΛΑΘΟΥΣ: Αυτό θα εμφανιστεί στα logs του Render
        print(f"Database Error setting {key}: {e}") 
        return jsonify({'success': False, 'error': 'Internal database error during save.'}), 500        
# --- SETTINGS ROUTES (ΟΜΑΔΑ 3 - ΑΣΠΡΟ) ---
@app.route('/settings/set_avatar_url', methods=['POST'])
def set_avatar_url():
    """Επιτρέπει στον χρήστη να αλλάξει το avatar του μέσω URL (μέσω AJAX)."""
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
            

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    # 🚨 Η κλήση db_setup_check(app) αφαιρέθηκε, γίνεται πλέον από το db_init.py
    print("Starting Flask/SocketIO Server...")
    socketio.run(app, debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))