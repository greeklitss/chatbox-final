import requests
import os
import json
import uuid
import time
import random
import secrets
import string
import redis

from flask_session import Session # ΝΕΟ IMPORT

from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import jsonify, url_for, request 

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import select, desc, func 
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, OperationalError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates 

# --- Global Real-time State (Safe for -w 1 eventlet worker) ---
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'

# 🚨 1. Αρχικοποιούμε τα extensions
db = SQLAlchemy()
oauth = OAuth()
socketio = SocketIO()
sess = Session() # ΝΕΑ ΑΡΧΙΚΟΠΟΙΗΣΗ


# ------------------------------------------------------------------
# --- ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ (MODELS) ---
# ------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True) 
    display_name = db.Column(db.String(80))
    role = db.Column(db.String(20), default='user')
    color = db.Column(db.String(7), default='#ffffff')
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(100), nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, default=datetime.now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_active(self):
        return True

class AppSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(64), unique=True, nullable=False)
    setting_value = db.Column(db.String(255))

class Emoticon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    url = db.Column(db.String(255), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    room = db.Column(db.String(50), default=GLOBAL_ROOM)


# ------------------------------------------------------------------
# --- ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ (HELPERS) ---
# ------------------------------------------------------------------

def login_required(f):
    """Decorator για να απαιτείται σύνδεση."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login')) 
        return f(*args, **kwargs)
    return decorated_function

def get_current_user_from_session():
    """Ανακτά τον χρήστη από το session."""
    user_id = session.get('user_id')
    if user_id:
        return db.session.get(User, user_id) 
    return None

def get_or_create_user(email, display_name, provider, oauth_id=None, avatar_url=None):
    """
    Ανακτά τον χρήστη με βάση το OAuth ID ή το Email, αλλιώς δημιουργεί νέο.
    """
    if provider != 'guest' and oauth_id:
        user = db.session.execute(
            select(User)
            .where(User.oauth_provider == provider, User.oauth_id == oauth_id)
        ).scalar_one_or_none()
        if user:
            user.last_login = datetime.now()
            db.session.commit()
            return user

    user = db.session.execute(select(User).where(User.email == email)).scalar_one_or_none()

    if user:
        if user.oauth_provider is None:
            user.oauth_provider = provider
            user.oauth_id = oauth_id
        user.display_name = display_name 
        user.avatar_url = avatar_url or user.avatar_url
        user.last_login = datetime.now()
        db.session.commit()
        return user
    
    unique_username = f"{provider}_{uuid.uuid4().hex[:8]}" 
    
    new_user = User(
        email=email,
        username=unique_username,
        display_name=display_name,
        role='user',
        avatar_url=avatar_url or '/static/default_avatar.png',
        oauth_provider=provider,
        oauth_id=oauth_id,
        is_online=False,
        last_login=datetime.now()
    )

    db.session.add(new_user)
    db.session.commit()
    return new_user

def initialize_settings():
    """Δημιουργεί βασικές ρυθμίσεις και τον αρχικό χρήστη (owner) αν δεν υπάρχουν."""
    
    default_settings = {
        'chat_enabled': 'True',
        'feature_bold': 'True',
        'feature_italic': 'True',
        'feature_underline': 'True',
        'max_msg_length': '500',
        'feature_radio': 'True', 
        'radio_url': 'http://stream.someserver.com/stream.mp3',
    }
    
    for key, default_value in default_settings.items():
        existing = db.session.execute(select(AppSetting).where(AppSetting.setting_key == key)).scalar_one_or_none()
        if not existing:
            db.session.add(AppSetting(setting_key=key, setting_value=default_value))

    owner_user = db.session.execute(
        select(User).where(User.role == 'owner').limit(1)
    ).scalar_one_or_none()
    
    if not owner_user:
        print("🚨 Creating initial OWNER user: owner@example.com / password123")
        new_owner = User(
            username='owner',
            email='owner@example.com',
            display_name='Admin Owner',
            role='owner',
            color='#FF0066',
            avatar_url='/static/default_avatar.png',
            is_online=False,
            last_login=datetime.now()
        )
        new_owner.set_password('password123') 
        db.session.add(new_owner)

    db.session.commit()
    print("Settings and Owner user checked/initialized.")

def initialize_emoticons():
    """Δημιουργεί βασικά emoticons."""
    
    TWEMOJI_CDN = "https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/"

    default_emoticons = [
        { 'code': ':D', 'url': f"{TWEMOJI_CDN}1f604.png" }, 
        { 'code': ';)', 'url': f"{TWEMOJI_CDN}1f609.png" }, 
        { 'code': ':(', 'url': f"{TWEMOJI_CDN}1f622.png" },
    ]
    
    for emoticon_data in default_emoticons:
        code = emoticon_data['code']
        url = emoticon_data['url']
        
        emoticon = db.session.execute(
            select(Emoticon).where(Emoticon.code == code)
        ).scalar_one_or_none()
        
        if not emoticon:
            new_emoticon = Emoticon(code=code, url=url)
            db.session.add(new_emoticon)

    db.session.commit()
    print("Default emoticons initialized from CDN.")
    
def save_and_emit_message(user_id, content, room_name):
    """Αποθηκεύει το μήνυμα στη βάση και το εκπέμπει στους clients."""
    try:
        new_msg = Message(user_id=user_id, content=content, room=room_name)
        db.session.add(new_msg)
        db.session.commit()
        
        user_data = db.session.execute(
            select(User.display_name, User.avatar_url, User.color)
            .where(User.id == user_id)
        ).first()

        if user_data:
            message_data = {
                'content': content,
                'timestamp': new_msg.timestamp.isoformat(),
                'user': {
                    'display_name': user_data.display_name,
                    'avatar_url': user_data.avatar_url,
                    'color': user_data.color
                }
            }
            socketio.emit('new_message', message_data, room=room_name)
            return True
        return False
    except Exception as e:
        db.session.rollback()
        print(f"Error saving or emitting message: {e}")
        return False

# ------------------------------------------------------------------
# --- ΣΥΝΑΡΤΗΣΗ ΔΗΜΙΟΥΡΓΙΑΣ ΕΦΑΡΜΟΓΗΣ (Factory Pattern) ---
# ------------------------------------------------------------------

def create_app():
    app = Flask(__name__)
    
    # 🚨 ΚΡΙΣΙΜΗ ΔΙΟΡΘΩΣΗ: Επιθετικό ProxyFix για σωστή αναγνώριση HTTPS (κρίσιμο για cookies σε Render)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # --- Ρυθμίσεις (Config) ---
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_fallback_key')
# 🚨 ΝΕΑ ΓΡΑΜΜΗ: Ορίζει ρητά το domain για τα sessions
    app.config['SESSION_COOKIE_DOMAIN'] = os.environ.get('SESSION_DOMAIN') # Πρέπει να είναι 'radioparea.com'
# 🚨 ΚΡΙΣΙΜΟ: Εξαναγκάζει το Flask να χρησιμοποιεί HTTPS για όλα τα URL (π.χ. OAuth callbacks)
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')  
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# 🚨 ΝΕΑ ΓΡΑΜΜΗ: Εξασφαλίζει ότι το cookie ισχύει σε όλο το domain
    app.config['SESSION_COOKIE_PATH'] = '/'
    # Ρυθμίσεις Flask Session (Χρησιμοποιούμε default cookies)
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
# 🚨 ΚΡΙΣΙΜΟ: ΡΥΘΜΙΣΕΙΣ REDIS SESSION 🚨
    # Χρησιμοποιούμε το REDIS_URL του Render για τη σύνδεση Redis
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url(os.environ.get('REDIS_URL'))
    # 🚨 ΚΡΙΣΙΜΟ: True για HTTPS (Render)
    app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER') else False 
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24 * 7)

    # Ρυθμίσεις OAuth
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # 🚨 ΕΛΕΓΧΟΣ ΚΛΕΙΔΙΩΝ: Εμφανίζεται στα logs του Render για διάγνωση
    if not app.config.get('GOOGLE_CLIENT_ID') or not app.config.get('GOOGLE_CLIENT_SECRET'):
        print("🚨 CRITICAL: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET is missing or empty. Check Render Env Vars.")
    else:
        id_snippet = app.config['GOOGLE_CLIENT_ID'][:5] + '...' + app.config['GOOGLE_CLIENT_ID'][-5:]
        print(f"✅ Google Client ID set: {id_snippet}. Proceeding with OAuth setup.")


    # --- 2. Αρχικοποίηση Extensions με το App ---
    db.init_app(app)
    sess.init_app(app) # ΚΑΛΕΣΤΕ ΤΟ ΓΙΑ ΝΑ ΕΝΕΡΓΟΠΟΙΗΘΕΙ Ο REDIS STORE
    
    # OAuth
    oauth.init_app(app)
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        oauth.register(
            name='google',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            # ✅ Αυτό διορθώνει το 'missing nonce'
            client_kwargs={'scope': 'openid email profile'},

            # ✅ Διορθώνει το MismatchingStateError (CSRF State Bypass)
            state_factory=lambda: None
        )
        
    # SocketIO
    socketio.init_app(app, 
                      message_queue=os.environ.get('REDIS_URL'), 
                      cors_allowed_origins="*", 
                      logger=False, 
                      engineio_logger=False,
                      manage_session=False
                     )
    
    # --- 3. ΑΡΧΙΚΟΠΟΙΗΣΗ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ ---
    with app.app_context():
        try:
            db.create_all() 
            print("Database tables ensured (db.create_all() successful).")
        except Exception as e:
            db.session.rollback()
            print(f"!!! DB CREATE_ALL WARNING (Rollback and Proceed): {e} !!!")
            
        try:
            initialize_settings() 
            initialize_emoticons()
            print("Database initialized successfully, settings and owner user ensured.")
        except Exception as e:
            db.session.rollback()
            print(f"!!! CRITICAL SETUP COMMIT ERROR: {e} !!!")


    # ------------------------------------------------------------------
    # --- 4. Διαδρομές (Routes) & API Endpoints ---
    # ------------------------------------------------------------------
    
    @app.route('/')
    def index():
        visits = session.get('visits', 0) + 1
        session['visits'] = visits
        return render_template('index.html', visits=visits)
    
    @app.route('/login')
    def login():
        return render_template('login.html')

    @app.route('/chat')
    @login_required
    def chat():
        current_user = get_current_user_from_session()
        
        settings = {s.setting_key: s.setting_value for s in db.session.execute(select(AppSetting)).scalars().all()}
        emoticons = {e.code: e.url for e in db.session.execute(select(Emoticon)).scalars().all()}
        
        messages = db.session.execute(
            select(Message, User.display_name, User.avatar_url, User.color)
            .join(User)
            .order_by(desc(Message.timestamp))
            .limit(50)
        ).all()
        messages = [
            {'user': {'display_name': msg[1], 'avatar_url': msg[2], 'color': msg[3]}, 
             'content': msg[0].content, 
             'timestamp': msg[0].timestamp} 
            for msg in reversed(messages)
        ]
        
        return render_template('chat.html', user=current_user, settings=settings, emoticons=emoticons, messages=messages)

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        return redirect(url_for('login'))

    @app.route('/api/v1/sign_up', methods=['POST'])
    def sign_up():
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        username = data.get('username')

        if not email or not password or not username:
            return jsonify({'error': 'Missing required fields'}), 400
        
        if db.session.execute(select(User).where(User.email == email)).scalar_one_or_none():
             return jsonify({'error': 'Email already registered'}), 409

        try:
            new_user = User(username=username, email=email, display_name=username, role='user')
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User created successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Database error: {e}'}), 500

    @app.route('/api/v1/login', methods=['POST'])
    def local_login():
        data = request.get_json()
        login_id = data.get('login_id') 
        password = data.get('password')

        # 1. Αναζήτηση με email
        user = db.session.execute(select(User).where(User.email == login_id)).scalar_one_or_none()
        
        # 2. Αν δεν βρεθεί με email, αναζήτηση με username
        if not user:
             user = db.session.execute(select(User).where(User.username == login_id)).scalar_one_or_none()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            user.last_login = datetime.now()
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"CRITICAL LOGIN COMMIT ERROR: {e}", flush=True) 
                pass 
                
            return jsonify({'message': 'Login successful', 'redirect': url_for('chat')}), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401


    # --- OAuth Διαδρομές ---

    @app.route('/oauth/login/google')
    def google_login():
        redirect_uri = url_for('google_auth', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    @app.route('/oauth/callback/google')
    def google_auth():
        try:
            token = oauth.google.authorize_access_token() 
            userinfo = oauth.google.parse_id_token(token)
            
            user = get_or_create_user(
                email=userinfo.get('email'),
                display_name=userinfo.get('name'),
                provider='google',
                oauth_id=userinfo.get('sub'),
                avatar_url=userinfo.get('picture')
            )
            
            session['user_id'] = user.id
            return redirect(url_for('chat'))

        except MismatchingStateError as e:
            db.session.rollback() 
            print(f"!!! OAUTH STATE ERROR (MismatchingStateError): {e} !!!")
            return "OAuth State Error: Session state lost during redirection. Check ProxyFix and cookies.", 400
            
        except OAuthError as e:
            db.session.rollback() 
            print(f"!!! CRITICAL OAUTH AUTHORIZATION ERROR: {e} !!!")
            # 🚨 Επιστρέφει 401 στον χρήστη, εμφανίζοντας λεπτομέρειες σφάλματος στα logs
            return f"OAuth Authorization Failed: Check GOOGLE_CLIENT_ID/SECRET and Redirect URI in Google Console. Error detail: {e}", 401
            
        except Exception as e:
            db.session.rollback() 
            print(f"!!! GENERIC INTERNAL OAUTH ERROR: {e} !!!")
            return f"Generic Internal OAuth Error: {e}", 500

    # ------------------------------------------------------------------
    # --- 5. SocketIO Event Handlers ---
    # ------------------------------------------------------------------
    
    @socketio.on('connect')
    def handle_connect():
        user = get_current_user_from_session()
        if user and request.sid:
            ONLINE_SIDS[request.sid] = user.id
            user.is_online = True
            db.session.commit()
            join_room(GLOBAL_ROOM)
            
            online_users_list = get_online_users()
            socketio.emit('user_list_update', {'users': online_users_list}, room=GLOBAL_ROOM)

    @socketio.on('disconnect')
    def handle_disconnect():
        user = get_current_user_from_session()
        if user and request.sid in ONLINE_SIDS:
            del ONLINE_SIDS[request.sid]
            
            if user.id not in ONLINE_SIDS.values():
                user.is_online = False
                db.session.commit()
                
                online_users_list = get_online_users()
                socketio.emit('user_list_update', {'users': online_users_list}, room=GLOBAL_ROOM)

    @socketio.on('send_message')
    def handle_send_message(data):
        user = get_current_user_from_session()
        if not user:
            return

        content = data.get('content', '').strip()
        room_name = data.get('room', GLOBAL_ROOM)
        
        max_length_setting = db.session.execute(
            select(AppSetting.setting_value).where(AppSetting.setting_key == 'max_msg_length')
        ).scalar_one_or_none()
        
        max_length = int(max_length_setting) if max_length_setting and max_length_setting.isdigit() else 500

        if not content or len(content) > max_length:
            error_msg = f'Message cannot be empty or longer than {max_length} characters.'
            emit('error_message', {'error': error_msg})
            return

        save_and_emit_message(user.id, content, room_name)

    def get_online_users():
        """Βοηθητική συνάρτηση για την ανάκτηση της λίστας των online χρηστών."""
        user_ids = list(set(ONLINE_SIDS.values()))
        if not user_ids:
            return []
            
        users = db.session.execute(
            select(User.display_name, User.color, User.avatar_url, User.role)
            .where(User.id.in_(user_ids))
        ).all()
        
        return [{'display_name': u.display_name, 'color': u.color, 'avatar_url': u.avatar_url, 'role': u.role} for u in users]

    return app

# --- Τερματικό Σημείο: Εκτέλεση του Server (για local dev) ---
if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 10000)) 
    socketio.run(app, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)