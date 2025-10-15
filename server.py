import os
import json
import uuid
import time
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps

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
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'a_default_secret_key_for_local_dev')

# --- Ρυθμίσεις Βάσης Δεδομένων ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Αντικατάσταση του postgres:// με postgresql:// για συμβατότητα με SQLAlchemy
    database_url = database_url.replace("postgres://", "postgresql://", 1)
    
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///local_db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 🚨 Ρυθμίσεις για Session σε SQL DB (Διορθωμένες για Render/HTTPS)
app.config['SESSION_TYPE'] = 'sqlalchemy' 
app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions' 
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True      # Τα cookies αποστέλλονται μόνο μέσω HTTPS (Απαραίτητο για Render)
app.config['SESSION_COOKIE_SAMESITE'] = 'None'   # 🚨 ΔΙΟΡΘΩΣΗ: Αλλάχτηκε από 'Lax' σε 'None' για συμβατότητα με Google OAuth redirect
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
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet') 

# --- MODELS ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='user') # guest, user, admin, owner
    password_hash = db.Column(db.String(256), nullable=True) # Για local login
    avatar_url = db.Column(db.String(256), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False

class Setting(db.Model):
    __tablename__ = 'setting'
    id = db.Column(db.String(50), primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(50), nullable=False)

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
        current_settings = {s.key: s.value for s in Setting.query.all()}
        
    return render_template('chat.html', user=user, current_settings=current_settings)


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
        user_info = oauth.google.parse_id_token(token)
    except MismatchingStateError:
        # Εάν χαθεί το state (π.χ. λόγω λάθους SAMESITE cookie), τον στέλνουμε πίσω
        return redirect(url_for('login'))
    except OAuthError as e:
        print(f"OAuth Error: {e}")
        return redirect(url_for('login'))

    # 2. Επεξεργασία επιτυχούς σύνδεσης
    email = user_info.get('email')
    display_name = user_info.get('name')
    avatar_url = user_info.get('picture')

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

@socketio.on('connect')
def handle_connect():
    """Διαχειρίζεται τη σύνδεση ενός χρήστη στο SocketIO."""
    if 'user_id' in session:
        with app.app_context():
            user = get_current_user_or_guest() # 🚨 ΑΛΛΑΓΗ ΕΔΩ: Υποστήριξη Guest
            if user:
                # Χρησιμοποιούμε το user.id ως όνομα δωματίου για το προσωπικό κανάλι του χρήστη
                # και τους βάζουμε στο γενικό δωμάτιο 'chat'
                join_room('chat') 
                print(f"User {user.display_name} ({user.id}) connected and joined 'chat' room.")
                
                # Ενημέρωση του χρήστη ότι συνδέθηκε
                emit('status', {'msg': f'Welcome, {user.display_name}. You are connected to the chat.'})
                
                # Ενημέρωση όλων (εκτός από τον ίδιο) ότι συνδέθηκε
                emit('status', {'msg': f'{user.display_name} has joined the room.'}, room='chat', include_self=False)
            else:
                print("Session found, but user not found in DB. Disconnecting.")
                # Αν δεν βρεθεί ο χρήστης, αποσυνδέουμε το socket
                return False 
    else:
        # Αν δεν υπάρχει session, δεν επιτρέπουμε τη σύνδεση SocketIO
        print("Unauthenticated user tried to connect to SocketIO. Disconnecting.")
        return False


@socketio.on('send_message')
def handle_message(data):
    """Λαμβάνει ένα μήνυμα από έναν χρήστη και το στέλνει σε όλους τους άλλους."""
    if 'user_id' in session and 'message' in data:
        with app.app_context():
            user = get_current_user_or_guest() # 🚨 ΑΛΛΑΓΗ ΕΔΩ: Υποστήριξη Guest
            if user:
                message_text = data['message']
                # 🚨 ΝΕΟ: Λαμβάνουμε το format.
                message_format = data.get('format', {}) 
                
                # Εκπομπή του μηνύματος σε όλους στο δωμάτιο 'chat'
                emit('new_message', {
                    'user_id': user.id,
                    'user': user.display_name,
                    'message': message_text,
                    'format': message_format, # 🚨 ΝΕΟ: Περιλαμβάνουμε το format
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                }, room='chat')
                
                print(f"Message from {user.display_name}: {message_text}")
@socketio.on('disconnect')
def handle_disconnect():
    """Διαχειρίζεται την αποσύνδεση ενός χρήστη."""
    if 'user_id' in session:
        with app.app_context():
            user = get_current_user_or_guest() # 🚨 ΑΛΛΑΓΗ ΕΔΩ: Υποστήριξη Guest
            if user:
                leave_room('chat')
                print(f"User {user.display_name} ({user.id}) disconnected.")
                
                # Ενημέρωση όλων ότι αποσυνδέθηκε
                emit('status', {'msg': f'{user.display_name} has left the room.'}, room='chat', include_self=False)# ...


# --- ADMIN PANEL ROUTES ---
# server.py

# ... (υπάρχοντα imports) ...

@app.route('/check_login')
def check_login():
    """
    Ελέγχει αν υπάρχει ενεργή συνεδρία χρήστη.
    Χρησιμοποιείται από το client-side JS (π.χ., admin_panel.html) για έλεγχο.
    """
    if 'user_id' in session:
        # Επιστρέφει επιτυχία αν υπάρχει user_id στη session
        return jsonify({'logged_in': True, 'user_id': session['user_id']}), 200
    else:
        # Επιστρέφει αποτυχία αν ο χρήστης δεν είναι συνδεδεμένος
        return jsonify({'logged_in': False}), 401 # 401 Unauthorized

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


# --- MAIN EXECUTION ---
if __name__ == '__main__':
    # 🚨 Η κλήση db_setup_check(app) αφαιρέθηκε, γίνεται πλέον από το db_init.py
    print("Starting Flask/SocketIO Server...")
    socketio.run(app, debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))