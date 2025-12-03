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
from functools import wraps # 🚨 ΚΡΙΣΙΜΟ: ΑΠΑΡΑΙΤΗΤΟ ΓΙΑ ΤΟΥΣ DECORATORS
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

# --- Global Real-time State & DB Initialization ---
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'
db = SQLAlchemy()

# 🚨 MODELS (Πρέπει να είναι στο global scope για να λειτουργήσουν)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True) 
    email = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user') 
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default='#ffffff')
    
class Setting(db.Model):
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(255))
    
class Emoticon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), unique=True, nullable=False)
    url = db.Column(db.String(255), nullable=False)
    
# --- ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ & DECORATORS (ΠΡΕΠΕΙ ΝΑ ΕΙΝΑΙ GLOBAL) ---

def get_current_user_from_session():
    """Ανάκτηση χρήστη από το session."""
    # 🚨 ΣΗΜΕΙΩΣΗ: Απαιτείται app context για τη λειτουργία του db.session
    try:
        user_id = session.get('user_id')
        return db.session.get(User, user_id) if user_id else None
    except RuntimeError:
        # Μπορεί να καλεστεί εκτός app context (π.χ. στο socketio connect handler), οπότε επιστρέφουμε None
        return None

def login_required(f):
    """Decorator για έλεγχο σύνδεσης."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Ανακατεύθυνση στο login αν δεν υπάρχει session
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """Decorator για έλεγχο ρόλου (π.χ. admin, owner)."""
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user_from_session()
            if not user or user.role not in roles:
                # Χρησιμοποιούμε jsonify για API endpoints, redirect για HTML routes
                if request.blueprint in ['api']: # Υποθέτουμε ότι τα API έχουν blueprint 'api'
                    return jsonify({"error": "Forbidden. Insufficient role."}), 403
                return redirect(url_for('index')) # Ανακατεύθυνση στην αρχική σελίδα
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
    return {e.code: {'code': e.code, 'url': e.url} for e in emoticons}

def initialize_settings(app):
    """Αρχικοποιεί τις default ρυθμίσεις στη βάση δεδομένων."""
    with app.app_context(): 
        default_settings = {
            'feature_bold': 'True',
            'feature_italic': 'True',
            'feature_underline': 'True',
            'feature_color': 'True',
            'feature_img': 'True',
            'feature_emoticons': 'True',
            'feature_gif': 'True',
            'feature_radio': 'True', 
            'radio_stream_url': 'http://127.0.0.1:8000/stream.mp3', 
            'global_chat_enabled': 'True', 
            'welcome_message': 'Welcome to the chat!'
        }
        for key, value in default_settings.items():
            if not db.session.get(Setting, key):
                new_setting = Setting(key=key, value=value, description=f"Setting for {key}")
                db.session.add(new_setting)
        
        db.session.commit()
    

# --- Κύρια Συνάρτηση Εφαρμογής ---

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(16)),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", 'sqlite:///chat.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_TYPE='filesystem', 
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID", "default_client_id_if_missing"),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET", "default_client_secret_if_missing"),
    )

    db.init_app(app)
    Session(app) 
    oauth = OAuth(app)
    # 🚨 Κρίσιμο: manage_session=False λόγω της Flask-Session
    socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*") 

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
        redirect_to='auth_google' 
    )

    # --- ΒΑΣΙΚΗ ΛΟΓΙΚΗ ΕΚΚΙΝΗΣΗΣ ---

    with app.app_context():
        db.create_all()
        initialize_settings(app)

    # --- ROUTES ΓΙΑ AUTHENTICATION ---

    @app.route('/login')
    def login():
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        session.pop('google_token', None)
        return redirect(url_for('login'))
        
    @app.route('/login/google')
    def login_google():
        redirect_uri = url_for('auth_google', _external=True) 
        return oauth.google.authorize_redirect(redirect_uri)

    @app.route('/auth/google')
    def auth_google():
        # ... (Λογική Google Callback - Όπως πριν) ...
        try:
            token = oauth.google.authorize_access_token()
            userinfo = oauth.google.parse_id_token(token)

            user = db.session.execute(select(User).where(User.email == userinfo['email'])).scalar_one_or_none()
            if not user:
                user = User(
                    email=userinfo['email'],
                    display_name=userinfo.get('name', userinfo['email'].split('@')[0]),
                    avatar_url=userinfo.get('picture', '/static/default_avatar.png'),
                    username=None 
                )
                db.session.add(user)
                db.session.commit()
            
            session['user_id'] = user.id
            session['google_token'] = token
            
            return redirect(url_for('index'))

        except (MismatchingStateError, Exception) as e:
            print(f"OAuth Error: {e}")
            return redirect(url_for('login'))


    # --- ΒΑΣΙΚΑ APPLICATION ROUTES ---

    @app.route('/')
    @login_required # 🚨 ΤΩΡΑ ΕΙΝΑΙ ΟΡΑΤΟ
    def index():
        user = get_current_user_from_session()
        settings = get_settings()
        emoticons = get_emoticons()
        return render_template('chat.html', user=user, settings=settings, emoticons=emoticons)

    @app.route('/admin_panel')
    @login_required
    @role_required(['admin', 'owner']) # 🚨 ΤΩΡΑ ΕΙΝΑΙ ΟΡΑΤΟ
    def admin_panel():
        return render_template('admin_panel.html')

    # --- ADMIN PANEL & RADIO API ROUTES (Σημαντικά για τη λειτουργία) ---

    @app.route('/check_login')
    @login_required
    def check_login():
        # ... (Λογική) ...
        current_user = get_current_user_from_session()
        return jsonify({
            'id': current_user.id,
            'role': current_user.role,
            'display_name': current_user.display_name
        }), 200

    @app.route('/radio_proxy')
    @login_required 
    def radio_proxy():
        # ... (Λογική) ...
        settings = get_settings()
        radio_url = settings.get('radio_stream_url')
        
        if not radio_url or settings.get('feature_radio') != 'True':
            return "", 204
            
        try:
            # 🚨 Χρησιμοποιούμε requests για stream, όπως συζητήθηκε
            response = requests.get(radio_url, stream=True, timeout=10)
            res = make_response(response.iter_content(chunk_size=1024))
            res.status_code = response.status_code
            res.headers['Content-Type'] = response.headers.get('Content-Type', 'audio/mpeg')
            res.headers['Access-Control-Allow-Origin'] = '*' 
            return res
            
        except requests.exceptions.RequestException as e:
            print(f"Error in radio proxy: {e}")
            return "", 503
            
    # --- ADMIN API: SETTINGS ---

    @app.route('/api/v1/settings', methods=['GET'])
    @role_required(['admin', 'owner'])
    def get_all_settings_api():
        # ... (Λογική) ...
        settings = db.session.execute(select(Setting)).scalars().all()
        return jsonify([{'key': s.key, 'value': s.value, 'description': s.description} for s in settings]), 200

    @app.route('/api/v1/settings', methods=['POST'])
    @role_required(['admin', 'owner'])
    def update_settings_api():
        # ... (Λογική) ...
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
            socketio.emit('settings_update', get_settings(), room=GLOBAL_ROOM)
            return jsonify({"message": "Settings updated successfully."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": "Database error during update."}), 500


    # --- SOCKETIO EVENT HANDLERS ---
    # ... (Υποθέτουμε ότι τα handlers για 'connect', 'disconnect', 'send_message' υπάρχουν) ...
    # 🚨 ΣΗΜΕΙΩΣΗ: Πρέπει να διασφαλιστεί ότι τα handlers όπως το 'send_message' έχουν πρόσβαση
    # στον χρήστη μέσω του session/socket (όπως ορίστηκε στις βοηθητικές συναρτήσεις).

    return app

# --- Τερματικό Σημείο: Εκτέλεση του Server ---
if __name__ == '__main__':
    app = create_app()
    # ... (eventlet setup) ...
    print("Starting Flask-SocketIO server locally...")
    port = int(os.environ.get('PORT', 10000)) 
    try:
        import eventlet
        eventlet.monkey_patch() 
        from eventlet import wsgi
        wsgi.server(eventlet.listen(('', port)), app)
    except ImportError:
        # Fallback for local testing without eventlet
        app.run(debug=True, port=port)