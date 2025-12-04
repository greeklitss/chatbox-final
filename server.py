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

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import select, desc, func 
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash # Χρησιμοποιούμε τη συνάρτηση hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, OperationalError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates 

# --- Global Real-time State (Safe for -w 1 eventlet worker) ---
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'

db = SQLAlchemy()
oauth = OAuth()

# --- Utility Functions ---

def get_default_color_by_role(role):
    """Επιστρέφει ένα default χρώμα με βάση τον ρόλο."""
    if role == 'owner':
        return '#FF3399' 
    elif role == 'admin':
        return '#00E6E6'
    else:
        return '#FFFFFF'

def login_required(f):
    """Decorator για προστατευμένα routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_admin_or_owner(f):
    """Decorator για προστασία admin panel."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
        user = db.session.get(User, user_id)
        if user and user.role in ['admin', 'owner']:
            return f(*args, **kwargs)
        
        return jsonify({'error': 'Forbidden access'}), 403
    return decorated_function

# --- Database Models ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # 🚨 ΚΡΙΣΙΜΗ ΑΛΛΑΓΗ: google_id πλέον nullable, καθώς θα υπάρχουν χρήστες με password
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=True) 
    display_name = db.Column(db.String(100), nullable=False)
    # 🚨 ΝΕΟ ΠΕΔΙΟ: password_hash για παραδοσιακό login
    password_hash = db.Column(db.String(255), nullable=True) 
    role = db.Column(db.String(50), default='user', nullable=False)
    color = db.Column(db.String(7), nullable=False)
    avatar_url = db.Column(db.String(500), nullable=False, default='static/default_avatar.png')
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(5000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    room = db.Column(db.String(100), default=GLOBAL_ROOM)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(500), nullable=False)

class Emoticon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    url = db.Column(db.String(500), nullable=False)

# --- Main App Factory ---

def create_app():
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1)

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_KEY_PREFIX'] = 'flask_session_'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

    db.init_app(app)
    sess = Session(app)
    
    oauth.init_app(app)
    
    oauth.register(
        name='google',
        client_id=os.environ.get('GOOGLE_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
        access_token_url='https://oauth2.googleapis.com/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'openid email profile'},
    )

    with app.app_context():
        try:
            db.create_all()
            print("Database initialized or already exists.")
        except Exception as e:
            print(f"Error initializing database: {e}")

        @app.before_request
        def load_user():
            user_id = session.get('user_id')
            if user_id:
                user = db.session.get(User, user_id)
                if user:
                    request.current_user = user
                else:
                    session.pop('user_id', None)
                    request.current_user = None
            else:
                request.current_user = None

    # ------------------ Flask Routes ------------------

    # 1. Main Index/Landing Page
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('chat_main'))
        return render_template('index.html')

    # 2. Login Page - Now renders the form (assumes it includes both traditional and Google options)
    @app.route('/login')
    def login():
        return render_template('login.html')

    # 🚨 ΝΕΟ ROUTE: Παραδοσιακό Login (Username/Password)
    @app.route('/login_submit', methods=['POST'])
    def login_submit():
        display_name = request.form.get('display_name')
        password = request.form.get('password')

        if not display_name or not password:
            return render_template('login.html', error='Please fill in both fields.')

        user = db.session.execute(select(User).where(User.display_name == display_name)).scalar_one_or_none()
        
        # Έλεγχος αν ο χρήστης υπάρχει, έχει hash κωδικό και ταιριάζει
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['display_name'] = user.display_name
            return redirect(url_for('chat_main'))
        else:
            return render_template('login.html', error='Invalid display name or password.')

    # 3. Google OAuth Start
    @app.route('/oauth_login')
    def oauth_login():
        redirect_uri = url_for('authorize', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    # 4. Logout
    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        session.pop('display_name', None)
        return redirect(url_for('index'))

    # 5. GOOGLE OAUTH CALLBACK (Με Manual Fetch)
    @app.route('/authorize')
    def authorize():
        try:
            # 1. Access Token Exchange
            token = oauth.google.authorize_access_token()
            user_info = token.get('userinfo')
            
            # 🚨 1.1. MANUAL FETCH: Αν το user_info λείπει από το token, το παίρνουμε χειροκίνητα
            if not user_info:
                print("User info missing from token. Manually fetching...")
                resp = oauth.google.get('userinfo', token=token)
                resp.raise_for_status() 
                user_info = resp.json()
            
            # 2. Safety check against missing ID
            if not user_info or 'id' not in user_info:
                print(f"CRITICAL ERROR: User info or ID missing after manual fetch. Received user_info: {user_info}")
                return redirect(url_for('login'))

            # Εύρεση χρήστη με Google ID (αν υπάρχει)
            user = db.session.execute(select(User).where(User.google_id == user_info['id'])).scalar_one_or_none()
            
            # Εάν δεν βρεθεί, ελέγχουμε αν υπάρχει χρήστης με το ίδιο email (για συγχώνευση)
            if user is None:
                user = db.session.execute(select(User).where(User.email == user_info.get('email'))).scalar_one_or_none()
                
                # Αν βρεθεί χρήστης με ίδιο email (παραδοσιακός login), ενημερώνουμε το google_id
                if user and not user.google_id:
                    user.google_id = user_info['id']
                    user.email = user_info.get('email', user.email)
                    print(f"User {user.display_name} merged with Google ID.")
                
                # Αν δεν βρεθεί καθόλου, δημιουργούμε ΝΕΟ χρήστη
                elif user is None:
                    default_role = 'user'
                    default_color = get_default_color_by_role(default_role)
                    
                    user = User(
                        google_id=user_info['id'], 
                        email=user_info.get('email', None),
                        display_name=user_info.get('name', 'NewUser'),
                        role=default_role,     
                        color=default_color,    
                        avatar_url=user_info.get('picture', 'static/default_avatar.png'),
                        # password_hash παραμένει Null
                    )
                    db.session.add(user)
            
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"Database Integrity/Commit Failed during user creation/merge: {e}") 
                return redirect(url_for('login')) 

            # Δημιουργία Session
            session['user_id'] = user.id
            session['display_name'] = user.display_name
            
            # ΤΕΛΙΚΗ ΑΝΑΚΑΤΕΥΘΥΝΣΗ
            return redirect(url_for('chat_main'))
            
        except MismatchingStateError:
            print("OAuth State Mismatch Error - Check session settings. This often means session is lost during redirect.")
            return redirect(url_for('login'))
        except OAuthError as e:
            print(f"OAuth Error: {e}")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"An unexpected error occurred during authorization: {e}") 
            return redirect(url_for('login'))

    # 6. Chat Main Page (Προστατευμένο)
    @app.route('/chat')
    @login_required
    def chat_main():
        current_user = request.current_user
        
        settings_list = db.session.execute(select(Settings)).scalars().all()
        settings = {s.key: s.value for s in settings_list}
        
        emoticons_list = db.session.execute(select(Emoticon)).scalars().all()
        emoticons = {e.code: e.url for e in emoticons_list}
        
        messages_query = select(Message).order_by(desc(Message.timestamp)).limit(50)
        messages_list = db.session.execute(messages_query).scalars().all()
        messages_list.reverse()
        
        online_user_ids = list(ONLINE_SIDS.values())
        online_users = db.session.execute(select(User).where(User.id.in_(online_user_ids))).scalars().all()

        return render_template(
            'chat.html', 
            user=current_user, 
            settings=settings, 
            emoticons=emoticons,
            initial_messages=messages_list,
            online_users=online_users
        )

    # 7. Admin Panel Route (Προστατευμένο)
    @app.route('/admin_panel')
    @check_admin_or_owner
    def admin_panel():
        return render_template('admin_panel.html')

    # 8. Check Login Status (για χρήση από admin_panel.html)
    @app.route('/check_login')
    @login_required
    def check_login():
        current_user = request.current_user
        return jsonify({
            'id': current_user.id,
            'role': current_user.role,
            'display_name': current_user.display_name
        })

    # ------------------ SocketIO Handlers ------------------
    # ... (SocketIO handlers παραμένουν ίδια)
    
    socketio = SocketIO(
        app, 
        manage_session=False, 
        cors_allowed_origins="*", 
        message_queue=os.environ.get('REDIS_URL')
    )

    @socketio.on('connect')
    def handle_connect():
        user_id = session.get('user_id')
        if not user_id:
            return False 
        
        sid = request.sid
        
        if user_id not in ONLINE_SIDS.values():
            user = db.session.get(User, user_id)
            if user:
                emit('user_status', {'user_id': user.id, 'display_name': user.display_name, 'status': 'online', 'role': user.role, 'color': user.color}, broadcast=True)

        ONLINE_SIDS[sid] = user_id
        join_room(GLOBAL_ROOM)
        print(f"User {user_id} connected with SID: {sid}. Total SIDs: {len(ONLINE_SIDS)}")
        
        online_user_ids = list(ONLINE_SIDS.values())
        online_users = db.session.execute(select(User).where(User.id.in_(online_user_ids))).scalars().all()
        online_data = [{'id': u.id, 'display_name': u.display_name, 'role': u.role, 'color': u.color, 'avatar_url': u.avatar_url} for u in online_users]
        emit('online_users_list', online_data)
        
    @socketio.on('disconnect')
    def handle_disconnect():
        sid = request.sid
        user_id = ONLINE_SIDS.pop(sid, None)
        
        if user_id is None:
            return

        is_user_still_online = user_id in ONLINE_SIDS.values()

        if not is_user_still_online:
            user = db.session.get(User, user_id)
            if user:
                emit('user_status', {'user_id': user.id, 'display_name': user.display_name, 'status': 'offline'}, broadcast=True)

        print(f"User {user_id} disconnected. Total SIDs: {len(ONLINE_SIDS)}")

    @socketio.on('send_message')
    def handle_send_message(data):
        user_id = session.get('user_id')
        sid = request.sid
        
        if not user_id or sid not in ONLINE_SIDS:
            return

        current_user = db.session.get(User, user_id)
        content = data.get('content', '').strip()
        room_name = data.get('room', GLOBAL_ROOM)
        
        if not current_user or not content or current_user.is_banned:
            return

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
                'display_name': current_user.display_name,
                'avatar_url': current_user.avatar_url,
                'role': current_user.role,
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

if __name__ == '__main__':
    app = create_app()
    print("Starting Flask-SocketIO server locally...")
    port = int(os.environ.get('PORT', 10000)) 
    
    try:
        import eventlet
        eventlet.monkey_patch()
        SocketIO(app, manage_session=False, message_queue=os.environ.get('REDIS_URL')).run(app, host='0.0.0.0', port=port, debug=True)
    except ImportError:
        print("Warning: eventlet not installed. Falling back to default Flask server.")
        SocketIO(app, manage_session=False).run(app, host='0.0.0.0', port=port, debug=True)