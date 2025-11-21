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

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH --
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import select, desc, func 
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, OperationalError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates 

# --- Global Real-time State (Safe for -w 1 eventlet worker) ---
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'

# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app, για να χρησιμοποιηθούν στο factory pattern
db = SQLAlchemy()
sess = Session()
oauth = OAuth()
socketio = SocketIO()

# --- Μοντέλα Βάσης Δεδομένων ---

class User(db.Model):
    """Μοντέλο Χρήστη."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True) # Για local login
    display_name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user') # 'user', 'admin', 'owner'
    avatar_url = db.Column(db.String(256), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default='#ffffff')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, default=datetime.now)
    # Νέα πεδία για OAuth (π.χ. Google)
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(256), nullable=True)

    @validates('username', 'email')
    def validate_unique(self, key, value):
        if not value: return value
        # Αποφυγή προβλημάτων με Whitespace/Case-sensitivity
        if key == 'username':
            return value.strip()
        if key == 'email':
            return value.lower().strip()
        return value

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.display_name} ({self.role})>'


class Message(db.Model):
    """Μοντέλο Μηνύματος."""
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    room = db.Column(db.String(50), default='main') # Για μελλοντική χρήση (π.χ. private rooms)
    
    # Σχέση με τον χρήστη
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

    def __repr__(self):
        return f'<Message {self.id} from {self.user_id}>'
    
class Setting(db.Model):
    """Μοντέλο Ρυθμίσεων (για Admin Panel)."""
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.String(256), nullable=False)
    description = db.Column(db.String(256), nullable=True)

    def __repr__(self):
        return f'<Setting {self.key}: {self.value}>'

class Emoticon(db.Model):
    """Μοντέλο Emoticons (για Admin Panel)."""
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False) # π.χ. :smile:
    url = db.Column(db.String(256), nullable=False) # π.χ. /static/emoticons/smile.gif

    def __repr__(self):
        return f'<Emoticon {self.code}: {self.url}>'


# --- Helper Functions ---

def login_required(f):
    """Decorator για έλεγχο αν ο χρήστης είναι συνδεδεμένος."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# ... (λοιπές helper functions, π.χ. role_required, get_current_user_from_session, κλπ. παραμένουν ίδιες) ...

def get_current_user_from_session():
    """Επιστρέφει το User object από το session."""
    user_id = session.get('user_id')
    if user_id:
        return db.session.get(User, user_id)
    return None

def get_settings():
    """Ανακτά όλες τις ρυθμίσεις ως dictionary."""
    settings = db.session.execute(select(Setting)).scalars().all()
    return {s.key: s.value for s in settings}

def get_emoticons():
    """Ανακτά όλα τα emoticons ως dictionary."""
    emoticons = db.session.execute(select(Emoticon)).scalars().all()
    return {e.code: e.url for e in emoticons}

def get_messages(room=GLOBAL_ROOM, limit=50):
    """Ανακτά τα τελευταία μηνύματα για ένα δωμάτιο."""
    messages = db.session.execute(
        select(Message)
        .where(Message.room == room)
        .order_by(desc(Message.timestamp))
        .limit(limit)
    ).scalars().all()
    return reversed(messages) # Τα θέλουμε με χρονολογική σειρά

def initialize_settings():
    """
    Αρχικοποιεί τις default ρυθμίσεις και τον Owner χρήστη αν δεν υπάρχουν.
    Πρέπει να τρέχει μέσα σε app_context().
    """
    
    # --- 1. Αρχικοποίηση Ρυθμίσεων ---
    default_settings = {
        'max_message_length': '300',
        'feature_bold': 'True',
        'feature_italic': 'True',
        'feature_underline': 'True',
        'feature_img_gif': 'True',
        'feature_radio': 'True',
        'global_chat_enabled': 'True'
    }
    
    for key, default_value in default_settings.items():
        existing_setting = db.session.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
        if not existing_setting:
            new_setting = Setting(key=key, value=default_value, description=f"Toggle for {key}")
            db.session.add(new_setting)

    # --- 2. Δημιουργία Owner Χρήστη ---
    owner_username = os.environ.get('OWNER_USERNAME', 'owner')
    owner_email = os.environ.get('OWNER_EMAIL', 'owner@example.com')
    # ΚΡΙΣΙΜΟ: Αυτός είναι ο default κωδικός για την πρώτη σας σύνδεση
    owner_password = os.environ.get('OWNER_PASSWORD', '123456') 

    existing_owner = db.session.execute(select(User).where(User.username == owner_username)).scalar_one_or_none()
    
    if not existing_owner:
        owner = User(
            username=owner_username,
            email=owner_email,
            display_name='Admin Owner',
            role='owner',
            avatar_url='/static/default_avatar.png'
        )
        owner.set_password(owner_password)
        db.session.add(owner)
        print(f"!!! Owner user '{owner_username}' created with password '{owner_password}' !!!")
        
    db.session.commit()

def initialize_emoticons():
    """Αρχικοποιεί default emoticons με χρήση εξωτερικών URLs αν δεν υπάρχουν."""
    
    # 🚨 Χρησιμοποιούμε εξωτερικά URLs για τα default emoticons
    default_emoticons = {
        ':smile:': 'https://example.com/emoticons/smile.gif',
        ':lol:': 'https://example.com/emoticons/lol.gif',
        ':love:': 'https://example.com/emoticons/love.gif',
        ':cry:': 'https://example.com/emoticons/cry.gif',
        ':p:': 'https://example.com/emoticons/tongue.gif'
    }
    
    for code, url in default_emoticons.items():
        existing_emoticon = db.session.execute(select(Emoticon).where(Emoticon.code == code)).scalar_one_or_none()
        if not existing_emoticon:
            new_emoticon = Emoticon(code=code, url=url)
            db.session.add(new_emoticon)
        # Εάν υπάρχει, ενημερώνουμε το URL μόνο αν είναι διαφορετικό
        elif existing_emoticon.url != url:
            existing_emoticon.url = url
    db.session.commit()
    
# --- Utility Functions for Real-Time Events (παραμένουν ίδιες) ---
def emit_online_users_list():
    """Δημιουργεί και στέλνει την τρέχουσα λίστα των online χρηστών."""
    # ... (ο κώδικας παραμένει ίδιος) ...
    # ... (για λόγους συντομίας) ...
    active_user_ids = list(set(ONLINE_SIDS.values()))
    
    if not active_user_ids:
        socketio.emit('online_users_update', {'users': []}, room=GLOBAL_ROOM)
        return

    try:
        with app.app_context():
            online_users = db.session.execute(
                select(User.id, User.display_name, User.role, User.avatar_url, User.color)
                .where(User.id.in_(active_user_ids))
            ).all()
            
            users_data = [
                {
                    'id': user.id,
                    'display_name': user.display_name,
                    'role': user.role,
                    'avatar_url': user.avatar_url,
                    'color': user.color
                } 
                for user in online_users
            ]

            socketio.emit('online_users_update', {'users': users_data}, room=GLOBAL_ROOM)
            print(f"Online list emitted: {len(users_data)} users.")
        
    except Exception as e:
        print(f"Error fetching and emitting online users: {e}")


# --- Factory Function για τη δημιουργία της εφαρμογής ---

def create_app(test_config=None):
    # 🚨 Ρύθμιση της εφαρμογής
    app = Flask(__name__, static_folder='static', template_folder='templates')
    
    # ... (ρυθμίσεις configuration παραμένουν ίδιες) ...
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', ''.join(random.choices(string.ascii_letters + string.digits, k=64)))
    
    # --- Ρυθμίσεις Database (SQLAlchemy) ---
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chatbox.db').replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # --- Ρυθμίσεις Session ---
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions'
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    
    # --- Αρχικοποίηση Extensions ---
    db.init_app(app)
    app.config['SESSION_SQLALCHEMY'] = db # Κρίσιμο για το SQLAlchemy Session Type
    sess.init_app(app)

    # --- Δημιουργία Πινάκων και Αρχικοποίηση Δεδομένων ---
    with app.app_context():
        try:
            # 1. Δημιουργία των πινάκων (θα τρέξει μόνο αν δεν υπάρχουν)
            db.create_all() 
            # 2. Αρχικοποίηση ρυθμίσεων και Owner
            initialize_settings() 
            # 3. Αρχικοποίηση emoticons
            initialize_emoticons()
            print("Database initialized successfully, settings and owner user ensured.")
        except Exception as e:
            print(f"!!! CRITICAL DB SETUP ERROR: {e} !!!")

    # Η αρχικοποίηση του OAuth εξαρτάται από τις μεταβλητές περιβάλλοντος. 
    # ... (Ο κώδικας αρχικοποίησης OAuth παραμένει ίδιος) ...
    if os.environ.get('GOOGLE_CLIENT_ID'):
        app.config['OAUTH_GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
        app.config['OAUTH_GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
        oauth.init_app(app)
        oauth.register(
            name='google',
            client_id=app.config['OAUTH_GOOGLE_CLIENT_ID'],
            client_secret=app.config['OAUTH_GOOGLE_CLIENT_SECRET'],
            access_token_url='https://oauth2.googleapis.com/token',
            access_token_params=None,
            authorize_url='https://accounts.google.com/o/oauth2/auth',
            authorize_params=None,
            api_base_url='https://www.googleapis.com/oauth2/v1/',
            client_kwargs={'scope': 'openid email profile'},
        )
    
    socketio.init_app(app, 
        cors_allowed_origins="*", # Επιτρέπει όλες τις πηγές
        message_queue=os.environ.get('MESSAGE_QUEUE_URL'), # Χρησιμοποιεί Redis ή άλλο
        async_mode='eventlet', # Για καλύτερη απόδοση
        ping_timeout=25,
        ping_interval=10
    )

    # --- Routes ---
    
    @app.route('/')
    @login_required
    def index():
        current_user = get_current_user_from_session()
        settings = get_settings()
        emoticons = get_emoticons()
        messages = get_messages()
        
        # Προσαρμογή των μηνυμάτων για το template
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                'id': msg.id,
                'user_id': msg.user_id,
                'username': msg.user.display_name,
                'avatar_url': msg.user.avatar_url,
                'color': msg.user.color,
                'content': msg.content,
                'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'room': msg.room
            })

        # ΣΗΜΑΝΤΙΚΟ: Χρειάζεστε το template 'chat.html'
        return render_template('chat.html', 
                               user=current_user, 
                               settings=settings, 
                               emoticons=emoticons, 
                               initial_messages=formatted_messages,
                               radio_url="https://live2.dikosmas.fm/8004/stream.mp3"
                              )

    # --- Authentication Routes ---
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # Αν ο χρήστης είναι ήδη συνδεδεμένος, τον στέλνουμε στο chat
        if 'user_id' in session:
            return redirect(url_for('index'))
            
        error = None
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            user = db.session.execute(select(User).where(User.username == username)).scalar_one_or_none()
            
            if user and user.check_password(password):
                # Επιτυχής σύνδεση
                session.clear() # Καθαρίζουμε τυχόν παλιά δεδομένα session
                session['user_id'] = user.id
                session['username'] = user.username
                user.last_login = datetime.now()
                db.session.commit()
                
                # Ανακατεύθυνση
                next_url = request.args.get('next') or url_for('index')
                return redirect(next_url)
            else:
                error = 'Λάθος όνομα χρήστη ή κωδικός.'

        # ΣΗΜΑΝΤΙΚΟ: Χρειάζεστε το template 'login.html'
        return render_template('login.html', error=error)


    @app.route('/logout')
    def logout():
        # Καθαρίζουμε το session
        session.clear()
        return redirect(url_for('login'))


    # ... (socketio event handlers παραμένουν ίδια) ...
    # ... (για λόγους συντομίας) ...
    
    @socketio.on('connect')
    def on_connect():
        # ... (ο κώδικας παραμένει ίδιος) ...

    @socketio.on('disconnect')
    def handle_disconnect():
        # 💡 ΔΙΟΡΘΩΣΗ: Προσθέστε 'pass' αν δεν θέλετε να κάνει τίποτα
        pass

    @socketio.on('new_message')
    def handle_new_message(data):
        # ... (ο κώδικας παραμένει ίδιος) ...

    return app


# --- Τερματικό Σημείο: Εκτέλεση του Server (για local dev) ---

if __name__ == '__main__':
    app = create_app()
<<<<<<< HEAD
    port = int(os.environ.get('PORT', 10000))
    print("Starting Flask-SocketIO server locally with default mode...")
    # 🚨 ΤΡΕΞΤΕ ΧΩΡΙΣ EVENTLET/GUNICORN ΓΙΑ ΝΑ ΔΕΙΤΕ ΤΟ ΣΦΑΛΜΑ
    socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)
=======
    # ... (ο κώδικας εκτέλεσης παραμένει ίδιος) ...
    port = int(os.environ.get('PORT', 10000)) 
    
    try:
        import eventlet
        eventlet.monkey_patch() 
        print("Using eventlet for SocketIO.")
        socketio.run(app, host='0.0.0.0', port=port, debug=True)
    except ImportError:
        print("Eventlet not found. Running with default Flask server. WARNING: Not suitable for production.")
        socketio.run(app, host='0.0.0.0', port=port, debug=True)
>>>>>>> db06065a26cd62870dff87667687bf148f2b9b21
