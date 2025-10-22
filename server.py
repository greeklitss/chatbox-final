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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key')

# --- DB Configuration ---
# Χρησιμοποιούμε την μεταβλητή περιβάλλοντος ή SQLite default
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Session Configuration (Χρήση SQLAlchemy για συνεδρίες) ---
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_COOKIE_NAME'] = 'flask_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# --- Initializations ---
db.init_app(app)
sess.init_app(app)
# 🚨 ΚΡΙΣΙΜΟ path='/socket.io' για Render
socketio = SocketIO(app, manage_session=False, cors_allowed_origins='*', path='/socket.io') 
oauth.init_app(app)


# --- DATABASE MODELS (ΤΩΡΑ ΠΛΗΡΗΣ ΛΙΣΤΑ) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    # 🚨 ΚΡΙΣΙΜΟ: 'user', 'admin', 'owner', 'guest'
    role = db.Column(db.String(20), default='user') 
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')
    
    messages = db.relationship('Message', backref='author', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.id} by {self.user_id}>'
    
class Setting(db.Model):
    """Ρυθμίσεις του Chat (π.χ. ενεργοποίηση Emoticons, όνομα Chat)"""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<Setting {self.key}: {self.value}>'

class Emoticon(db.Model):
    """Emoticons που μπορούν να χρησιμοποιηθούν (π.χ. :smile: -> 😊)"""
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), unique=True, nullable=False) # π.χ. :smile:
    image_url = db.Column(db.String(255), nullable=False)        # π.χ. /static/emoticons/smile.png
    
    def __repr__(self):
        return f'<Emoticon {self.code}>'


# --- GLOBAL CHAT DATA ---
# Λεξικό για τη διαχείριση ενεργών χρηστών {user_id: {'username': str, 'role': str, 'sids': set}}
active_users = {}


# --- AUTH DECORATOR & PERMISSION CHECKER ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Αποθηκεύουμε το URL για να επιστρέψουμε μετά το login
            return redirect(url_for('login_page', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in ['owner', 'admin', role]:
                # 🚨 ΣΗΜΑΝΤΙΚΟ: Αλλάξτε το σε 403.html αν υπάρχει
                return "Permission Denied", 403 
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- HELPER FUNCTIONS ΓΙΑ ΕΝΕΡΓΟΥΣ ΧΡΗΣΤΕΣ ---
def get_online_users():
    """Επιστρέφει μια λίστα με τους ενεργούς χρήστες για μετάδοση (με avatar)."""
    with app.app_context():
        users_list = []
        for user_id, data in active_users.items():
            user_data_from_db = db.session.get(User, user_id)
            # Βρίσκει το avatar_url από τη βάση ή χρησιμοποιεί το default
            avatar = user_data_from_db.avatar_url if user_data_from_db else '/static/default_avatar.png'
            users_list.append({
                'id': user_id, 
                'username': data['username'], 
                'role': data['role'],
                'avatar_url': avatar
            })
        return users_list

# --- HELPER FUNCTIONS ΓΙΑ ΑΡΧΙΚΟΠΟΙΗΣΗ DB ---
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
        # Υποθέτουμε ότι αυτά τα αρχεία εικόνων υπάρχουν στον φάκελο /static/emoticons/
        default_emoticons = [
            (':smile:', '/static/emoticons/smile.png'),
            (':sad:', '/static/emoticons/sad.png'),
            (':heart:', '/static/emoticons/heart.png')
        ]
        
        for code, url in default_emoticons:
            if not db.session.execute(select(Emoticon).filter_by(code=code)).scalar_one_or_none():
                new_emoticon = Emoticon(code=code, image_url=url)
                db.session.add(new_emoticon)
                print(f"Initialized Emoticon: {code}")
        db.session.commit()

# --- FLASK ROUTES (Chat, Ιστορικό & Auth) ---

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    # Υποθέτουμε ότι έχετε το login.html
    return render_template('login.html') 

@app.route('/chat')
@login_required
def chat_page():
    user_data = {
        'username': session.get('username'),
        'role': session.get('role'),
        'id': session.get('user_id'),
    }
    # Υποθέτουμε ότι έχετε το chat.html
    return render_template('chat.html', user=user_data)

@app.route('/admin')
@role_required('admin') # Απαιτείται Admin ή Owner
def admin_page():
    user_data = {
        'username': session.get('username'),
        'role': session.get('role'),
    }
    # Υποθέτουμε ότι έχετε το admin_panel.html
    return render_template('admin_panel.html', user=user_data)


# 🚨 ΝΕΟ: ROUTE ΓΙΑ ΙΣΤΟΡΙΚΟ ΜΗΝΥΜΑΤΩΝ (ΚΡΙΣΙΜΟ ΓΙΑ ΤΗ ΜΝΗΜΗ)
@app.route('/api/v1/messages', methods=['GET'])
@login_required 
def get_message_history():
    try:
        with app.app_context():
            # Φόρτωση των τελευταίων 50 μηνυμάτων
            messages = db.session.execute(
                select(Message)
                .order_by(desc(Message.timestamp))
                .limit(50)
            ).scalars().all()
            
            messages.reverse() # Αντιστροφή της λίστας για χρονολογική σειρά
            
            history = []
            for msg in messages:
                user = db.session.get(User, msg.user_id)
                
                username = user.username if user else 'Unknown'
                role = user.role if user else 'guest' 
                avatar = user.avatar_url if user else '/static/default_avatar.png' 

                history.append({
                    'username': username,
                    'role': role,
                    'msg': msg.content,
                    # Εξασφαλίζουμε ότι η ώρα είναι σε μορφή ISO για το JS
                    'timestamp': msg.timestamp.isoformat(), 
                    'user_id': msg.user_id,
                    'avatar_url': avatar
                })

            return jsonify(history), 200
    except Exception as e:
        print(f"Error loading message history: {e}")
        return jsonify([]), 500


# ----------------------------------------------------
# --- AUTHENTICATION API ROUTES (ΚΡΙΣΙΜΟ) ---
# ----------------------------------------------------

@app.route('/api/v1/sign_up', methods=['POST'])
def sign_up():
    data = request.get_json()
    username = data.get('username').strip()
    email = data.get('email').lower().strip()
    password = data.get('password')
    
    if not (username and email and password):
        return jsonify({'error': 'Please fill in all fields.'}), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters long.'}), 400
        
    try:
        with app.app_context():
            # Έλεγχος αν ο χρήστης ή το email υπάρχει
            if db.session.execute(select(User).filter_by(username=username)).scalar_one_or_none():
                return jsonify({'error': 'Username already taken.'}), 409
            if db.session.execute(select(User).filter_by(email=email)).scalar_one_or_none():
                return jsonify({'error': 'Email already registered.'}), 409

            # Δημιουργία hash κωδικού
            hashed_password = generate_password_hash(password, method='sha256')
            
            # 🚨 ΣΗΜΑΝΤΙΚΟ: Ο πρώτος χρήστης που εγγράφεται γίνεται 'owner'
            is_first_user = db.session.execute(select(db.func.count(User.id))).scalar() == 0
            role = 'owner' if is_first_user else 'user'
            
            new_user = User(username=username, email=email, password_hash=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({'message': f'Registration successful! Welcome, {username} ({role.upper()}).'}), 201

    except Exception as e:
        print(f"Sign up error: {e}")
        return jsonify({'error': 'Server error during registration.'}), 500


@app.route('/api/v1/login', methods=['POST'])
def login():
    data = request.get_json()
    username_or_email = data.get('username_or_email').strip()
    password = data.get('password')
    
    if not (username_or_email and password):
        return jsonify({'error': 'Missing username/email or password.'}), 400

    with app.app_context():
        # Αναζήτηση χρήστη με username ή email
        user = db.session.execute(select(User).filter(
            (User.username == username_or_email) | (User.email == username_or_email.lower())
        )).scalar_one_or_none()

        if user and check_password_hash(user.password_hash, password):
            # Επιτυχές login: Ορίζουμε τα δεδομένα συνεδρίας
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            return jsonify({'message': 'Login successful.', 'redirect': url_for('chat_page')}), 200
        else:
            return jsonify({'error': 'Invalid credentials.'}), 401

@app.route('/logout')
def logout():
    # Εάν ο χρήστης είναι συνδεδεμένος μέσω socket.io, η αποσύνδεση session θα
    # προκαλέσει disconnect event (SocketIO handles disconnect)
    # Θα πρέπει να διαχειριστείτε την αποσύνδεση του socket από το client-side
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/check_login', methods=['GET'])
def check_login():
    """Επιστρέφει τα βασικά δεδομένα χρήστη για το client-side JS."""
    if 'user_id' in session:
        with app.app_context():
            user = db.session.get(User, session['user_id'])
            avatar_url = user.avatar_url if user else '/static/default_avatar.png'
            
        return jsonify({
            'id': session['user_id'],
            'username': session['username'],
            'role': session['role'],
            'avatar_url': avatar_url, # Προσθήκη avatar_url για το chat
            'is_logged_in': True
        }), 200
    return jsonify({'is_logged_in': False}), 401
    
# ----------------------------------------------------
# --- AVATAR & ADMIN API ROUTES ---
# ----------------------------------------------------

@app.route('/settings/set_avatar_url', methods=['POST'])
@login_required
def set_avatar_url():
    data = request.get_json()
    new_url = data.get('avatar_url')
    
    if not new_url:
        return jsonify({'success': False, 'message': 'Missing URL.'}), 400

    user_id = session['user_id']
    with app.app_context():
        # Guests (GUEST-...) δεν έχουν πεδίο στη βάση, οπότε δεν το αποθηκεύουμε.
        if session.get('role') == 'guest':
             return jsonify({'success': True, 'message': 'Avatar URL set for this session.'})
             
        user = db.session.get(User, user_id)
        if user:
            user.avatar_url = new_url
            db.session.commit()
            
            # 🚨 Ενημερώνουμε όλους μέσω SocketIO για την αλλαγή avatar
            socketio.emit('user_avatar_updated', {
                'user_id': user.id,
                'avatar_url': new_url
            }, room='chat')
            
            return jsonify({'success': True, 'message': 'Avatar URL updated.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
            
# ----------------------------------------------------
# --- SOCKETIO EVENTS (ΔΕΝ ΑΛΛΑΖΟΥΝ) ---
# ----------------------------------------------------

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        role = session['role']
        sid = request.sid

        join_room('chat')

        if user_id not in active_users:
            active_users[user_id] = {'username': username, 'role': role, 'sids': {sid}}
            # Ενημερώνουμε όλους για τον νέο χρήστη
            emit('update_active_users', get_online_users(), broadcast=True)
        else:
            # Ο χρήστης συνδέθηκε ξανά από άλλη καρτέλα/συσκευή
            active_users[user_id]['sids'].add(sid)
            # Ενημερώνουμε μόνο τον ίδιο για τους ενεργούς χρήστες
            emit('update_active_users', get_online_users(), room=sid)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user_id = session['user_id']
        sid = request.sid
        
        if user_id in active_users:
            active_users[user_id]['sids'].discard(sid)
            
            # Εάν δεν υπάρχουν άλλα SIDs για αυτόν τον χρήστη, τον αφαιρούμε από τους ενεργούς
            if not active_users[user_id]['sids']:
                del active_users[user_id]
                emit('update_active_users', get_online_users(), broadcast=True)

@socketio.on('message')
def handle_message(data):
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    username = session['username']
    role = session['role']
    msg_content = data.get('msg')
    
    if not msg_content:
        return

    timestamp = datetime.now(timezone.utc)
    
    # 1. Αποθήκευση στη Βάση Δεδομένων
    try:
        with app.app_context():
            new_message = Message(user_id=user_id, content=msg_content, timestamp=timestamp)
            db.session.add(new_message)
            db.session.commit()
            
            # Βρίσκουμε το avatar_url για να το στείλουμε στο frontend
            user = db.session.get(User, user_id)
            avatar_url = user.avatar_url if user else '/static/default_avatar.png'
            
    except Exception as e:
        print(f"Database error saving message: {e}")
        # Χρησιμοποιούμε fallback τιμές σε περίπτωση σφάλματος
        avatar_url = '/static/default_avatar.png'
        
    # 2. Αποστολή σε όλους
    message_data = {
        'username': username,
        'role': role,
        'msg': msg_content,
        'timestamp': timestamp.isoformat(),
        'user_id': user_id,
        'avatar_url': avatar_url # Στέλνουμε και το avatar
    }
    emit('new_message', message_data, room='chat', include_self=True)
    

# ----------------------------------------------------
# --- ΠΡΟΣΘΗΚΗ: ΚΡΙΣΙΜΟΣ ΕΛΕΓΧΟΣ ΔΗΜΙΟΥΡΓΙΑΣ ΒΑΣΗΣ ---
# ----------------------------------------------------
with app.app_context():
    # Δημιουργεί όλους τους πίνακες (User, Message, Setting κ.λπ.) αν δεν υπάρχουν
    db.create_all() 
    
    # 🚨 ΝΕΟ: Αρχικοποίηση Ρυθμίσεων & Emoticons
    initialize_settings()
    initialize_emoticons() 

if __name__ == '__main__':
    # Χρησιμοποιούμε gunicorn στον production server (όπως το Render), αλλά socketio.run
    # είναι καλό για τοπική ανάπτυξη (development).
    # Στο Render, το Procfile θα πρέπει να είναι: web: gunicorn --worker-class eventlet server:app
    socketio.run(app, debug=True, port=os.environ.get('PORT', 5000))