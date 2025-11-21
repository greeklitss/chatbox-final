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
# Χρησιμοποιείται για να κρατάμε ποιους χρήστες έχουμε συνδέσει, map από sid σε user_id
# Αυτό είναι ασφαλές εφόσον το Procfile χρησιμοποιεί -w 1 worker.
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'

# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app, για να χρησιμοποιηθούν στο factory pattern
db = SQLAlchemy()
sess = Session()
oauth = OAuth()
socketio = SocketIO()

# --- Μοντέλα Βάσης Δεδομένων ---
# (Τα models παραμένουν ίδια)

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


# --- Helper Functions (ΔΕΝ ΧΡΗΣΙΜΟΠΟΙΟΥΝΤΑΙ ΣΤΗΝ ΔΙΑΔΙΚΑΣΙΑ ΑΡΧΙΚΟΠΟΙΗΣΗΣ ΤΗΣ ΕΦΑΡΜΟΓΗΣ) ---

def login_required(f):
    """Decorator για έλεγχο αν ο χρήστης είναι συνδεδεμένος."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role_names):
    """Decorator για έλεγχο ρόλου."""
    if not isinstance(role_names, list):
        role_names = [role_names]
    
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            user = db.session.get(User, user_id)
            if not user or user.role not in role_names:
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

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
    """Αρχικοποιεί τις default ρυθμίσεις αν δεν υπάρχουν."""
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
    db.session.commit()

def initialize_emoticons():
    """Αρχικοποιεί default emoticons αν δεν υπάρχουν."""
    default_emoticons = {
        ':smile:': '/static/emoticons/smile.gif',
        ':lol:': '/static/emoticons/lol.gif',
        ':love:': '/static/emoticons/love.gif',
        ':cry:': '/static/emoticons/cry.gif',
        ':p:': '/static/emoticons/tongue.gif'
    }
    
    for code, url in default_emoticons.items():
        existing_emoticon = db.session.execute(select(Emoticon).where(Emoticon.code == code)).scalar_one_or_none()
        if not existing_emoticon:
            new_emoticon = Emoticon(code=code, url=url)
            db.session.add(new_emoticon)
        # 🚨 Ενημέρωση: Αν υπάρχει, ενημερώνουμε το URL (για τοπική ανάπτυξη)
        elif existing_emoticon.url != url:
            existing_emoticon.url = url
    db.session.commit()
    
# --- Utility Functions for Real-Time Events ---

def emit_online_users_list():
    """Δημιουργεί και στέλνει την τρέχουσα λίστα των online χρηστών."""
    # Παίρνουμε τα μοναδικά user IDs από τους ενεργούς SIDs
    active_user_ids = list(set(ONLINE_SIDS.values()))
    
    if not active_user_ids:
        # Αν δεν υπάρχουν ενεργοί χρήστες, στέλνουμε κενή λίστα
        socketio.emit('online_users_update', {'users': []}, room=GLOBAL_ROOM)
        return

    try:
        # Ανακτούμε τα δεδομένα των χρηστών από τη βάση
        # Προσοχή: Επειδή η κλήση γίνεται εκτός Flask request context, ίσως χρειαστεί
        # να τυλιχτεί σε app_context() αν το db.session δεν είναι διαθέσιμο.
        # Ωστόσο, εφόσον το socketio.run() ξεκινά το app, συνήθως λειτουργεί.
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

            # Εκπομπή της ενημερωμένης λίστας σε όλους στο GLOBAL_ROOM
            socketio.emit('online_users_update', {'users': users_data}, room=GLOBAL_ROOM)
            print(f"Online list emitted: {len(users_data)} users.")
        
    except Exception as e:
        print(f"Error fetching and emitting online users: {e}")


# --- Factory Function για τη δημιουργία της εφαρμογής ---

def create_app(test_config=None):
    # 🚨 Ρύθμιση της εφαρμογής
    app = Flask(__name__, static_folder='static', template_folder='templates')
    # ... (ρυθμίσεις configuration παραμένουν ίδιες) ...
    # ...
    
    # Τοποθετούμε το app.secret_key εδώ.
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', ''.join(random.choices(string.ascii_letters + string.digits, k=64)))
    
    # --- Ρυθμίσεις Database (SQLAlchemy) ---
    # ... (ρυθμίσεις DB παραμένουν ίδιες) ...
    
    # --- Αρχικοποίηση Extensions ---
    # ... (αρχικοποίηση extensions παραμένουν ίδιες) ...
    db.init_app(app)
    sess.init_app(app)
    # Η αρχικοποίηση του OAuth εξαρτάται από τις μεταβλητές περιβάλλοντος. 
    # Εάν δεν έχουν οριστεί, δεν γίνεται.
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

        return render_template('chat.html', 
                               user=current_user, 
                               settings=settings, 
                               emoticons=emoticons, 
                               initial_messages=formatted_messages,
                               radio_url="https://live2.dikosmas.fm/8004/stream.mp3" # Default ραδιοφωνική πηγή
                              )

    # ... (login/logout/oauth/api routes παραμένουν ίδια) ...

    # --- SocketIO Event Handlers ---
    
    @socketio.on('connect')
    def on_connect():
        # 1. Έλεγχος Αυθεντικοποίησης
        current_user = get_current_user_from_session()
        if not current_user:
            print(f"Unauthenticated connection rejected. SID: {request.sid}")
            return False # Απορρίπτει τη σύνδεση
        
        # 2. Προσθήκη σε δωμάτια
        join_room(GLOBAL_ROOM)
        join_room(f"user_{current_user.id}") # Ιδιωτικό δωμάτιο για τον χρήστη
        
        # 3. Ενημέρωση Online SIDs
        # Χρησιμοποιούμε το SID του request για να κάνουμε map τον user_id
        is_new_connection = current_user.id not in ONLINE_SIDS.values()
        ONLINE_SIDS[request.sid] = current_user.id
        
        print(f"User {current_user.display_name} connected. SID: {request.sid}")
        
        # 4. Ενημέρωση λίστας online (μόνο αν ήταν η πρώτη σύνδεση του χρήστη)
        if is_new_connection:
            emit_online_users_list()

    @socketio.on('disconnect')
    def on_disconnect():
        current_user = get_current_user_from_session()
        sid = request.sid

        if sid in ONLINE_SIDS:
            del ONLINE_SIDS[sid]
            print(f"User SID {sid} disconnected.")

            # Ελέγχουμε αν υπάρχουν άλλοι SIDs για αυτόν τον χρήστη
            is_still_online = current_user and current_user.id in ONLINE_SIDS.values()
            
            # Αν ο χρήστης δεν έχει πλέον ενεργές συνδέσεις, ενημερώνουμε τη λίστα
            if current_user and not is_still_online:
                print(f"User {current_user.display_name} fully disconnected. Emitting update.")
                emit_online_users_list()
        else:
            print(f"Unknown SID {sid} disconnected.")

    @socketio.on('new_message')
    def handle_new_message(data):
        current_user = get_current_user_from_session()
        settings = get_settings()
        
        if not current_user or settings.get('global_chat_enabled') != 'True':
            print(f"Message attempt rejected from {current_user.display_name if current_user else 'Guest'}.")
            return

        content = data.get('content', '').strip()
        room_name = GLOBAL_ROOM # Μπορεί να αλλάξει σε data.get('room', GLOBAL_ROOM)
        
        if content:
            # Έλεγχος μήκους μηνύματος
            max_len = int(settings.get('max_message_length', 300))
            if len(content) > max_len:
                emit('error_message', {'error': f'Message exceeds max length of {max_len} characters.'}, room=f"user_{current_user.id}")
                return
            
            # Αποθήκευση στη βάση δεδομένων
            try:
                new_message = Message(
                    user_id=current_user.id, 
                    content=content,
                    room=room_name
                )
                db.session.add(new_message)
                db.session.commit()
                
                message_data = {
                    'id': new_message.id,
                    'user_id': current_user.id,
                    'username': current_user.display_name,
                    'avatar_url': current_user.avatar_url,
                    'color': current_user.color,
                    'content': content,
                    'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'room': room_name
                }
                
                emit('new_message', message_data, room=room_name)
                
            except Exception as e:
                db.session.rollback()
                print(f"Error saving message: {e}")
                emit('error_message', {'error': 'Failed to send message.'}, room=f"user_{current_user.id}")
                
    return app


# --- Τερματικό Σημείο: Εκτέλεση του Server ---

# Αυτό το block είναι μόνο για τοπική εκτέλεση (π.χ. python server.py)
if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 10000))
    print("Starting Flask-SocketIO server locally with default mode...")
    # 🚨 ΤΡΕΞΤΕ ΧΩΡΙΣ EVENTLET/GUNICORN ΓΙΑ ΝΑ ΔΕΙΤΕ ΤΟ ΣΦΑΛΜΑ
    socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)