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
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, OperationalError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates 


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

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    display_name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False) # user, admin, owner
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')
    color = db.Column(db.String(7), default='#ffffff')
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Σχέσεις: Ένας χρήστης έχει πολλά μηνύματα
    messages = db.relationship('Message', backref='author', lazy='dynamic', cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username cannot be empty")
        return username

class Message(db.Model):
    """Μοντέλο Μηνύματος."""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    room = db.Column(db.String(50), default='general') # For multi-room support

    # Σχέσεις: Ένα μήνυμα ανήκει σε έναν χρήστη
    # author (User) - ορίστηκε στο User.messages backref    


class Settings(db.Model):
    """Μοντέλο Ρυθμίσεων για το Chat."""
    __tablename__ = 'settings'
    
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    type = db.Column(db.String(10), default='boolean') # boolean, string, number

class Emoticon(db.Model):
    """Μοντέλο Emoticon."""
    __tablename__ = 'emoticons'
    
    code = db.Column(db.String(20), primary_key=True) # π.χ. :smile:
    url = db.Column(db.String(255), nullable=False) # π.χ. /static/emotes/smile.gif
    is_active = db.Column(db.Boolean, default=True)



# --- Βοηθητικές Συναρτήσεις ---

def initialize_settings():
    """Αρχικοποιεί τις default ρυθμίσεις του chat."""
    # Χρησιμοποιούμε τη μέθοδο merge για να κάνουμε update αν υπάρχει
    default_settings = [
        {'key': 'chat_enabled', 'value': 'True', 'description': 'Ενεργοποίηση/Απενεργοποίηση αποστολής μηνυμάτων.', 'type': 'boolean'},
        {'key': 'profanity_filter_enabled', 'value': 'True', 'description': 'Ενεργοποίηση φίλτρου ακατάλληλων λέξεων.', 'type': 'boolean'},
        {'key': 'max_message_length', 'value': '500', 'description': 'Μέγιστο μήκος μηνύματος σε χαρακτήρες.', 'type': 'number'},
        {'key': 'feature_bold', 'value': 'True', 'description': 'Ενεργοποίηση BBCode [b].', 'type': 'boolean'},
        {'key': 'feature_italic', 'value': 'True', 'description': 'Ενεργοποίηση BBCode [i].', 'type': 'boolean'},
        {'key': 'feature_gif', 'value': 'True', 'description': 'Ενεργοποίηση ενσωμάτωσης [img] URLs.', 'type': 'boolean'},
        {'key': 'feature_radio', 'value': 'True', 'description': 'Ενεργοποίηση/Απενεργοποίηση του ραδιοφώνου.', 'type': 'boolean'},
    ]
    
    for setting in default_settings:
        # Χρησιμοποιούμε db.session.merge για Upsert (UPDATE ή INSERT)
        existing = db.session.get(Settings, setting['key'])
        if existing:
            # Κάνουμε update μόνο την περιγραφή και τον τύπο, όχι την τιμή αν υπάρχει
            existing.description = setting['description']
            existing.type = setting['type']
            db.session.merge(existing)
        else:
            db.session.add(Settings(**setting))
            
    db.session.commit()

def initialize_emoticons():
    """Αρχικοποιεί τα default emoticons."""
    default_emoticons = [
        { 'code': ':smile:', 'url': '/static/emotes/smile.gif', 'is_active': True },
        { 'code': ':wink:', 'url': '/static/emotes/wink.gif', 'is_active': True },
        { 'code': ':happy:', 'url': '/static/emotes/happy.gif', 'is_active': True },
        { 'code': ':lol:', 'url': '/static/emotes/lol.gif', 'is_active': True },
        { 'code': ':sad:', 'url': '/static/emotes/sad.gif', 'is_active': True },
        { 'code': ':cool:', 'url': '/static/emotes/cool.gif', 'is_active': True },
        { 'code': ':cry:', 'url': '/static/emotes/cry.gif', 'is_active': True },
        { 'code': ':kiss:', 'url': '/static/emotes/kiss.gif', 'is_active': True },
        { 'code': ':oops:', 'url': '/static/emotes/oops.gif', 'is_active': True },
    ]
    
    for emoticon in default_emoticons:
        # Χρησιμοποιούμε db.session.merge για Upsert (UPDATE ή INSERT)
        existing = db.session.get(Emoticon, emoticon['code'])
        if not existing:
             db.session.add(Emoticon(**emoticon))
            
    db.session.commit()

# --- Flask Application Factory ---

def create_app():
    """Δημιουργεί και ρυθμίζει την Flask εφαρμογή."""
    app = Flask(__name__)

    # 🚨 ΚΡΙΣΙΜΗ ΠΡΟΣΘΗΚΗ: Χρησιμοποιούμε ProxyFix για να διασφαλίσουμε τη σωστή λειτουργία του SocketIO
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_port=1, x_prefix=1, x_proto=1)

    # Γενικές Ρυθμίσεις
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_change_me_in_prod')
    app.config['SESSION_TYPE'] = 'sqlalchemy' 
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

    # Ρυθμίσεις Uploads
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
    app.config['UPLOAD_FOLDER'] = 'static/uploads'

    # Ρυθμίσεις Βάσης Δεδομένων
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///chatbox.db')

    # Προσαρμόζουμε το URL του PostgreSQL
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Ρυθμίσεις OAuth Google
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    # --- ΑΡΧΙΚΟΠΟΙΗΣΗ ΤΩΝ EXTENSIONS ΜΕ ΤΟ app ---
    db.init_app(app)
    sess.init_app(app)
    socketio.init_app(app, manage_session=False, async_mode='threading', cors_allowed_origins="*")
    oauth.init_app(app)

    # 2.3. FIX ΓΙΑ Flask-Session & Flask-SQLAlchemy Conflict
    # Το Flask-Session, όταν χρησιμοποιεί το 'sqlalchemy' ως τύπο, προσπαθεί να δημιουργήσει
    # μια νέα επέκταση SQLAlchemy αν δεν του δοθεί ρητά η υπάρχουσα, οδηγώντας στο RuntimeError.
    if app.config.get('SESSION_TYPE') == 'sqlalchemy':
        # 🚨 ΚΡΙΣΙΜΗ ΔΙΟΡΘΩΣΗ: Δίνουμε την υπάρχουσα επέκταση `db` στο Session configuration.
        app.config['SESSION_SQLALCHEMY'] = db 
        
    # Προσθήκη Google OAuth Provider

    global google
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://oauth2.googleapis.com/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params={'scope': 'openid email profile'},
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'openid email profile'},
        jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    )
    
    # 🚨 Εκτελούμε το setup ΜΟΝΟ μια φορά όταν η εφαρμογή είναι έτοιμη
    with app.app_context():
        setup_app_on_startup(app, db)
        
    # --- Flask Routes ---

    @app.route('/')
    def index():
        """Η κύρια σελίδα του chat. Απαιτεί σύνδεση."""
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        
        try:
            current_user = get_user_by_session()
            if not current_user:
                session.pop('user_id', None)
                return redirect(url_for('login_page'))
                
            settings = get_current_settings()
            default_room = settings.get('default_room', 'general')
            
            # Λήψη των τελευταίων 50 μηνυμάτων
            stmt = select(Message).order_by(desc(Message.timestamp)).limit(50).options(db.joinedload(Message.user))
            messages = db.session.execute(stmt).scalars().all()
            messages.reverse() 
            
            # 🚨 ΔΙΟΡΘΩΣΗ: Χρησιμοποιούμε 'chat.html' αντί για 'index.html'
            return render_template('chat.html', 
                                 user=current_user, 
                                 settings=settings, 
                                 messages=messages,
                                 default_room=default_room)
        except OperationalError as e:
            # Ειδικός χειρισμός αν η DB είναι offline
            print(f"🚨 OperationalError in index route: {e}")
            return "Database connection failed during chat load. Please check server logs.", 500
        except Exception as e:
            print(f"🚨 CRITICAL ERROR in index route: {e}")
            return "Internal Server Error during chat loading. Check database connection logs.", 500

    @app.route('/admin_panel')
    @admin_required
    def admin_panel():
        """Σελίδα διαχείρισης."""
        return render_template('admin_panel.html')

    @app.route('/check_login')
    @login_required
    def check_login():
        """Ελέγχει αν ο χρήστης είναι συνδεδεμένος και επιστρέφει βασικά δεδομένα."""
        user = get_user_by_session()
        if user:
            return jsonify({
                'id': user.id, 
                'username': user.username,
                'display_name': user.display_name,
                'role': user.role,
                'avatar_url': user.avatar_url
            }), 200
        return jsonify({'error': 'Not logged in'}), 401
    

    @app.route('/login')
    def login_page():
        """Σελίδα σύνδεσης/εγγραφής."""
        if 'user_id' in session:
            return redirect(url_for('index'))
        # Εμφανίζουμε τυχόν OAuth errors
        error_message = request.args.get('error')
        return render_template('login.html', error_message=error_message)

    # --- API Routes για Admin Panel ---
    
    @app.route('/api/v1/admin/settings', methods=['GET', 'POST'])
    @admin_required
    def handle_settings():
        """Διαχείριση ρυθμίσεων συστήματος."""
        if request.method == 'GET':
            settings = get_current_settings()
            return jsonify(settings), 200
        
        elif request.method == 'POST':
            data = request.json
            try:
                for key, value in data.items():
                    stmt = select(Setting).where(Setting.key == key)
                    setting = db.session.execute(stmt).scalar_one_or_none()
                    
                    if setting:
                        setting.value = value
                    else:
                        db.session.add(Setting(key=key, value=value))
                        
                db.session.commit()
                return jsonify({'message': 'Settings updated successfully'}), 200
            except Exception as e:
                db.session.rollback()
                print(f"Error updating settings: {e}")
                return jsonify({'error': 'Failed to update settings'}), 500

    @app.route('/api/v1/admin/emoticons', methods=['GET', 'POST', 'DELETE'])
    @admin_required
    def handle_emoticons():
        """Διαχείριση emoticons."""
        if request.method == 'GET':
            emoticons = db.session.execute(select(Emoticon)).scalars().all()
            return jsonify([{'id': e.id, 'code': e.code, 'url': e.url} for e in emoticons]), 200
        
        elif request.method == 'POST':
            data = request.json
            code = data.get('code')
            url = data.get('url')
            
            if not code or not url:
                return jsonify({'error': 'Missing emoticon code or URL'}), 400
                
            try:
                new_emoticon = Emoticon(code=code, url=url)
                db.session.add(new_emoticon)
                db.session.commit()
                return jsonify({'message': 'Emoticon added successfully', 'id': new_emoticon.id}), 201
            except IntegrityError:
                db.session.rollback()
                return jsonify({'error': 'Emoticon code already exists'}), 409
            except Exception as e:
                db.session.rollback()
                print(f"Error adding emoticon: {e}")
                return jsonify({'error': 'Failed to add emoticon'}), 500

        elif request.method == 'DELETE':
            emoticon_id = request.args.get('id')
            try:
                stmt = select(Emoticon).where(Emoticon.id == emoticon_id)
                emoticon = db.session.execute(stmt).scalar_one_or_none()
                if emoticon:
                    db.session.delete(emoticon)
                    db.session.commit()
                    return jsonify({'message': f'Emoticon {emoticon_id} deleted successfully'}), 200
                return jsonify({'error': 'Emoticon not found'}), 404
            except Exception as e:
                db.session.rollback()
                print(f"Error deleting emoticon: {e}")
                return jsonify({'error': 'Failed to delete emoticon'}), 500
    
    @app.route('/api/v1/admin/users', methods=['GET'])
    @admin_required
    def list_users():
        """Επιστρέφει τη λίστα χρηστών."""
        try:
            users = db.session.execute(select(User).order_by(User.id)).scalars().all()
            user_list = [{
                'id': u.id, 
                'username': u.username, 
                'display_name': u.display_name,
                'email': u.email,
                'role': u.role,
                'color': u.color,
                'is_google_user': u.is_google_user,
                'last_seen': u.last_seen.strftime('%Y-%m-%d %H:%M:%S') if u.last_seen else 'N/A'
            } for u in users]
            return jsonify(user_list), 200
        except Exception as e:
            print(f"Error listing users: {e}")
            return jsonify({'error': 'Failed to retrieve user list'}), 500

    @app.route('/api/v1/admin/users/<int:user_id>/role', methods=['POST'])
    @admin_required
    def update_user_role(user_id):
        """Ανανέωση ρόλου χρήστη."""
        data = request.json
        new_role = data.get('role')
        
        if new_role not in ['user', 'admin', 'owner']:
            return jsonify({'error': 'Invalid role specified'}), 400

        user = db.session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        current_user = get_user_by_session()
        
        # Προστασία από υποβάθμιση του Owner
        if user.role == 'owner' and new_role != 'owner' and current_user.role != 'owner':
            return jsonify({'error': 'Only the Owner can manage other Owners or remove the Owner role.'}), 403
            
        # Ο Admin δεν μπορεί να αλλάξει τον ρόλο του Owner
        if user.role == 'owner' and current_user.role == 'admin':
             return jsonify({'error': 'Admin cannot modify Owner role.'}), 403
             
        # Ο Owner δεν μπορεί να υποβαθμίσει τον εαυτό του αν είναι ο μόνος Owner
        if user.id == current_user.id and user.role == 'owner' and new_role != 'owner':
             stmt_owner_count = select(func.count(User.id)).where(User.role == 'owner')
             owner_count = db.session.execute(stmt_owner_count).scalar_one()
             if owner_count <= 1:
                return jsonify({'error': 'Cannot remove Owner role if you are the only one.'}), 403

        try:
            user.role = new_role
            db.session.commit()
            return jsonify({'message': f'User {user.username} role updated to {new_role}'}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error updating user role: {e}")
            return jsonify({'error': 'Failed to update user role'}), 500


    # --- Login & Sign Up API Routes (Local) ---

    @app.route('/api/v1/sign_up', methods=['POST'])
    def sign_up():
        """Εγγραφή νέου χρήστη."""
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not password or len(username) < 3 or len(password) < 6:
            return jsonify({'error': 'Username must be at least 3 chars, password 6 chars.'}), 400

        try:
            stmt_username = select(User).where(User.username == username)
            if db.session.execute(stmt_username).scalar_one_or_none():
                return jsonify({'error': 'Username already taken.'}), 409
            
            if email:
                stmt_email = select(User).where(User.email == email)
                if db.session.execute(stmt_email).scalar_one_or_none():
                    return jsonify({'error': 'Email already registered.'}), 409

            new_user = User(username=username, display_name=username, email=email, color=generate_random_color())
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            return jsonify({'message': 'Registration successful! Please log in.'}), 201

        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Registration failed due to data conflict (e.g. duplicate username/email).'}), 409
        except Exception as e:
            db.session.rollback()
            print(f"Sign up error: {e}")
            return jsonify({'error': 'An unexpected error occurred during registration.'}), 500

    @app.route('/api/v1/login', methods=['POST'])
    def login():
        """Σύνδεση χρήστη."""
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Missing username or password.'}), 400

        try:
            stmt = select(User).where(User.username == username)
            user = db.session.execute(stmt).scalar_one_or_none()

            if user and user.password_hash and user.check_password(password):
                # Επιτυχής σύνδεση
                session['user_id'] = user.id
                session.permanent = True
                return jsonify({'message': 'Login successful!', 'redirect': url_for('index')}), 200
            elif user and user.is_google_user:
                return jsonify({'error': 'This username is registered via Google. Please use the Google sign-in button.'}), 401
            else:
                return jsonify({'error': 'Invalid username or password.'}), 401

        except Exception as e:
            print(f"Login error: {e}")
            return jsonify({'error': 'An unexpected error occurred during login.'}), 500

    @app.route('/logout')
    def logout():
        """Αποσύνδεση χρήστη."""
        session.pop('user_id', None)
        return redirect(url_for('login_page'))

    # --- Google OAuth Routes ---

    @app.route('/login/google')
    def login_google():
        """Ξεκινά τη διαδικασία σύνδεσης με Google."""
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)

    @app.route('/login/google/authorize')
    def authorize_google():
        """Callback μετά την επιτυχή σύνδεση με Google."""
        try:
            token = google.authorize_access_token()
            userinfo = google.get('userinfo').json()
            
            google_email = userinfo.get('email')
            google_username = google_email.split('@')[0] if google_email else userinfo.get('id')
            google_avatar = userinfo.get('picture')
            google_display_name = userinfo.get('name') or google_username
            
            if not google_email:
                return redirect(url_for('login_page', error='Google sign-in failed: No email provided.'))

            stmt = select(User).where(User.email == google_email)
            user = db.session.execute(stmt).scalar_one_or_none()

            if user:
                if not user.is_google_user and user.password_hash:
                    return redirect(url_for('login_page', error='Email registered locally. Please log in with password.'))
                
                user.avatar_url = google_avatar
                user.display_name = google_display_name
                db.session.commit()
                
                session['user_id'] = user.id
                session.permanent = True
                return redirect(url_for('index'))
            else:
                new_user = User(
                    username=google_username,
                    display_name=google_display_name,
                    email=google_email,
                    is_google_user=True,
                    avatar_url=google_avatar,
                    color=generate_random_color(),
                )
                db.session.add(new_user)
                db.session.commit()
                session['user_id'] = new_user.id
                session.permanent = True
                return redirect(url_for('index'))

        except MismatchingStateError:
            return redirect(url_for('login_page', error='OAuth state mismatch. Please try again.'))
        except OAuthError as e:
            print(f"OAuth Error: {e}")
            return redirect(url_for('login_page', error=f'Google authorization failed: {e}'))
        except Exception as e:
            db.session.rollback()
            print(f"Google Authorize General Error: {e}")
            return redirect(url_for('login_page', error='An unexpected error occurred during Google login.'))
            
    # --- SocketIO Events ---

    @socketio.on('connect')
    def handle_connect():
        current_user = get_user_by_session()
        if current_user:
            settings = get_current_settings()
            default_room = settings.get('default_room', 'general')
            
            join_room(default_room)
            join_room(f"user_{current_user.id}")
            
            # Ενημέρωση last_seen
            current_user.last_seen = datetime.now(timezone.utc)
            db.session.commit()

            print(f"User {current_user.username} (ID: {current_user.id}) connected and joined {default_room}.")
            
            emit('user_joined', {'username': current_user.display_name, 'room': default_room}, room=default_room)
        else:
            print("Unauthenticated user connected.")
            
    @socketio.on('disconnect')
    def handle_disconnect():
        current_user = get_user_by_session()
        if current_user:
            settings = get_current_settings()
            default_room = settings.get('default_room', 'general')
            
            emit('user_left', {'username': current_user.display_name, 'room': default_room}, room=default_room)
            
            leave_room(default_room)
            leave_room(f"user_{current_user.id}")
            print(f"User {current_user.username} (ID: {current_user.id}) disconnected.")

    @socketio.on('send_message')
    @login_required
    def handle_send_message(data):
        content = data.get('content', '').strip()
        room_name = data.get('room', 'general')
        
        if not content:
            return

        current_user = get_user_by_session()
        
        if current_user:
            try:
                new_message = Message(
                    user_id=current_user.id,
                    room_name=room_name,
                    content=content,
                    timestamp=datetime.now(timezone.utc)
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


# --- Τερματικό Σημείο: Εκτέλεση & Deployment ---

# Δημιουργία του instance της εφαρμογής για το Gunicorn (ή άλλο WSGI server).
# Η μεταβλητή `app` πρέπει να είναι διαθέσιμη στο module level, 
# γι' αυτό καλούμε το create_app() εδώ.
app = create_app()

# Αυτό το block είναι μόνο για τοπική εκτέλεση (π.χ. python server.py)
if __name__ == '__main__':
    print("Starting Flask-SocketIO server locally...")
    # 🚨 ΟΡΙΖΟΥΜΕ ΤΟ PORT ΝΑ ΠΡΟΕΡΧΕΤΑΙ ΑΠΟ ΤΟ ΠΕΡΙΒΑΛΛΟΝ, με fallback στο 10000
    port = int(os.environ.get('PORT', 10000)) 
    # Χρησιμοποιούμε το ήδη δημιουργημένο instance `app`
    socketio.run(app, debug=True, port=port)