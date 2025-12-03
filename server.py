import requests
import os
import json
import uuid
import time
import random
import secrets
import string
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from functools import wraps
from sqlalchemy import select, desc, func 
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, OperationalError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates 

# --- Global Real-time State --
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'

# --- Βοηθητικές Συναρτήσεις (Θεωρούμε ότι υπάρχουν) ---

# 🚨 Placeholder Models - ΠΡΟΣΟΧΗ: ΠΡΕΠΕΙ ΝΑ ΕΦΑΡΜΟΣΕΙΣ ΠΛΗΡΩΣ ΤΑ MODELS ΣΟΥ
db = SQLAlchemy()
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True) # Μπορεί να είναι Null αν μπαίνει με Google
    email = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user') # user, admin, owner
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default='#ffffff')
    
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
class Setting(db.Model):
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(255))
    
class Emoticon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), unique=True, nullable=False)
    url = db.Column(db.String(255), nullable=False)

# 🚨 Βοηθητικές Συναρτήσεις (Πρέπει να υπάρχουν στο αρχείο)
def get_current_user_from_session():
    user_id = session.get('user_id')
    return db.session.get(User, user_id) if user_id else None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user_from_session()
            if not user or user.role not in roles:
                return jsonify({"error": "Forbidden. Insufficient role."}), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

def get_settings():
    """Επιστρέφει όλες τις ρυθμίσεις ως dictionary."""
    settings = db.session.execute(select(Setting)).scalars().all()
    return {s.key: s.value for s in settings}

def get_emoticons():
    """Επιστρέφει όλα τα emoticons ως dictionary."""
    emoticons = db.session.execute(select(Emoticon)).scalars().all()
    # Επιστρέφουμε {":code:": "/url/..."}
    return {e.code: {'code': e.code, 'url': e.url} for e in emoticons}


# --- Κύρια Συνάρτηση Εφαρμογής ---

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=secrets.token_hex(16),
        SQLALCHEMY_DATABASE_URI='sqlite:///chat.db',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_TYPE='filesystem', # Χρήση filesystem για session
        # 🚨 Google OAuth Config (Πρέπει να οριστούν στο περιβάλλον)
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", "default_client_id_if_missing"),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET", "default_client_secret_if_missing"),
    )

    db.init_app(app)
    Session(app) # Ενεργοποίηση Session
    oauth = OAuth(app)
    socketio = SocketIO(app, manage_session=False) # manage_session=False λόγω της Flask-Session

    # 🚨 Ρύθμιση Google OAuth
    oauth.register(
        name='google',
        client_id=app.config.get('GOOGLE_CLIENT_ID'),
        client_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
        access_token_url='https://oauth2.googleapis.com/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        api_base_url='https://www.googleapis.com/oauth2/v3/',
        client_kwargs={
            'scope': 'openid email profile',
            'token_endpoint_auth_method': 'client_secret_post'
        },
        # Κρίσιμο: Χρησιμοποιούμε url_for για να πάρουμε το σωστό callback URL
        redirect_to='auth_google' 
    )

    # --- ΒΑΣΙΚΗ ΛΟΓΙΚΗ ΕΚΚΙΝΗΣΗΣ ---

    with app.app_context():
        db.create_all()
        # 🚨 Αρχικοποίηση ρυθμίσεων αν δεν υπάρχουν
        initialize_settings(app)

    def initialize_settings(app):
        # 🚨 ΠΡΟΣΘΗΚΗ ΡΥΘΜΙΣΕΩΝ ΓΙΑ RADIO & CHAT ON/OFF
        default_settings = {
            'feature_bold': 'True',
            'feature_italic': 'True',
            'feature_underline': 'True',
            'feature_color': 'True',
            'feature_img': 'True',
            'feature_emoticons': 'True',
            'feature_gif': 'True',
            'feature_radio': 'True', 
            'radio_stream_url': 'http://127.0.0.1:8000/stream.mp3', # 🚨 ΑΛΛΑΞΕ ΑΥΤΟ ΤΟ URL!
            'global_chat_enabled': 'True', # Νέα ρύθμιση για το chat on/off
            'welcome_message': 'Welcome to the chat!'
        }
        for key, value in default_settings.items():
            if not db.session.get(Setting, key):
                new_setting = Setting(key=key, value=value, description=f"Setting for {key}")
                db.session.add(new_setting)
        
        db.session.commit()
        
    # --- ROUTES ΓΙΑ AUTHENTICATION ---

    @app.route('/login')
    def login():
        return render_template('login.html') # Υποθέτουμε ότι υπάρχει login.html

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        session.pop('google_token', None)
        return redirect(url_for('login'))
        
    # 🚨 ΝΕΟ: Google Login Route
    @app.route('/login/google')
    def login_google():
        redirect_uri = url_for('auth_google', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    # 🚨 ΝΕΟ: Google Callback Route
    @app.route('/auth/google')
    def auth_google():
        try:
            token = oauth.google.authorize_access_token()
            userinfo = oauth.google.parse_id_token(token)

            # 1. Βρίσκουμε ή δημιουργούμε χρήστη
            user = db.session.execute(select(User).where(User.email == userinfo['email'])).scalar_one_or_none()
            if not user:
                user = User(
                    email=userinfo['email'],
                    display_name=userinfo.get('name', userinfo['email'].split('@')[0]),
                    avatar_url=userinfo.get('picture', '/static/default_avatar.png'),
                    username=None # Όχι τοπικό username αν μπαίνει με Google
                )
                db.session.add(user)
                db.session.commit()
            
            # 2. Θέτουμε session
            session['user_id'] = user.id
            session['google_token'] = token
            
            return redirect(url_for('index'))

        except (MismatchingStateError, OAuthError, Exception) as e:
            print(f"OAuth Error: {e}")
            return redirect(url_for('login'))


    # --- ΒΑΣΙΚΑ APPLICATION ROUTES ---

    @app.route('/')
    @login_required
    def index():
        user = get_current_user_from_session()
        settings = get_settings()
        emoticons = get_emoticons()
        # 🚨 Προσοχή: Εδώ το chat.html θα χρησιμοποιήσει το url_for('radio_proxy') για την πηγή
        return render_template('chat.html', user=user, settings=settings, emoticons=emoticons)

    # 🚨 ΝΕΟ: Admin Panel Route
    @app.route('/admin_panel')
    @role_required(['admin', 'owner'])
    def admin_panel():
        return render_template('admin_panel.html')

    # 🚨 ΝΕΟ: API Endpoint για έλεγχο login
    @app.route('/check_login')
    @login_required
    def check_login():
        current_user = get_current_user_from_session()
        return jsonify({
            'id': current_user.id,
            'role': current_user.role,
            'display_name': current_user.display_name
        }), 200

    # --- WEB RADIO PROXY (ΓΙΑ ΝΑ ΔΟΥΛΕΨΕΙ ΤΟ ΡΑΔΙΟ) ---
    @app.route('/radio_proxy')
    @login_required 
    def radio_proxy():
        """Proxy για το ραδιοφωνικό stream."""
        settings = get_settings()
        radio_url = settings.get('radio_stream_url')
        
        if not radio_url or settings.get('feature_radio') != 'True':
            return "", 204
            
        try:
            response = requests.get(radio_url, stream=True, timeout=10)
            
            # Χρησιμοποιούμε make_response για να χειριστούμε σωστά τη ροή
            res = make_response(response.iter_content(chunk_size=1024))
            res.status_code = response.status_code
            res.headers['Content-Type'] = response.headers.get('Content-Type', 'audio/mpeg')
            res.headers['Access-Control-Allow-Origin'] = '*' 
            return res
            
        except requests.exceptions.RequestException as e:
            print(f"Error in radio proxy: {e}")
            return "", 503

    # --- ADMIN PANEL API V1: SETTINGS, EMOTICONS, USERS (Μόνο για Admin/Owner) ---

    @app.route('/api/v1/settings', methods=['GET'])
    @role_required(['admin', 'owner'])
    def get_all_settings_api():
        settings = db.session.execute(select(Setting)).scalars().all()
        return jsonify([{'key': s.key, 'value': s.value, 'description': s.description} for s in settings]), 200

    @app.route('/api/v1/settings', methods=['POST'])
    @role_required(['admin', 'owner'])
    def update_settings_api():
        data = request.get_json()
        updates = data.get('settings', [])
        
        try:
            for item in updates:
                key = item.get('key')
                value = item.get('value')
                setting = db.session.get(Setting, key)
                if setting:
                    setting.value = value
            db.session.commit()
            # 🚨 ΕΚΠΟΜΠΗ SOCKETIO: Ενημέρωση όλων για τις αλλαγές
            socketio.emit('settings_update', get_settings(), room=GLOBAL_ROOM)
            return jsonify({"message": "Settings updated successfully."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": "Database error during update."}), 500
            
    # ... (Υλοποίηση /api/v1/emoticons GET/POST/DELETE και /api/v1/users GET/POST/DELETE εδώ) ...

    # --- SOCKETIO EVENT HANDLERS ---
    # ... (Τα υπάρχοντα handlers για 'connect', 'disconnect', 'join', 'send_message' μένουν ως έχουν) ...

    @socketio.on('connect')
    def handle_connect():
        # ... (Λογική σύνδεσης) ...
        pass
        
    @socketio.on('disconnect')
    def handle_disconnect():
        # ... (Λογική αποσύνδεσης) ...
        pass

    @socketio.on('send_message')
    def handle_send_message(data):
        # ... (Λογική αποστολής μηνύματος) ...
        pass

    return app

# --- Τερματικό Σημείο: Εκτέλεση του Server ---
if __name__ == '__main__':
    # ... (Eventlet setup) ...
    pass