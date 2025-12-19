import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
from authlib.integrations.flask_client import OAuth, OAuthError as AuthlibOAuthError
from flask_socketio import SocketIO, emit
import eventlet
import secrets
import random

# --------------------------------------------------------------------------
# 1. ΕΚΤΑΣΕΙΣ (Extensions)
# --------------------------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth()
socketio = SocketIO()

ONLINE_USERS = {} 
CHAT_COLORS = ['#D4AF37', '#E57373', '#81C784', '#64B5F6', '#FFD54F', '#BA68C8', '#4DB6AC', '#FF8A65']

# --------------------------------------------------------------------------
# 2. ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ
# --------------------------------------------------------------------------
def get_online_users_list():
    users_data = []
    unique_users = {}
    # Φιλτράρισμα για να μην φαίνονται διπλά ονόματα αν κάποιος μπει από 2 συσκευές
    for sid, data in ONLINE_USERS.items():
        unique_users[data['id']] = data
    
    for user_data in unique_users.values():
        users_data.append({
            'id': user_data['id'],
            'display_name': user_data['display_name'],
            'role': user_data['role'],
            'color': user_data['color'],
            'avatar_url': user_data.get('avatar_url') or f"https://ui-avatars.com/api/?name={user_data['display_name']}&background=random"
        })
    return users_data

# --------------------------------------------------------------------------
# 3. ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ
# --------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True) 
    password_hash = db.Column(db.String(256), nullable=True) 
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), default='user')
    color = db.Column(db.String(20), default='#008000')
    avatar_url = db.Column(db.String(256), nullable=True) 
    has_changed_name = db.Column(db.Boolean, default=False) # Για την αλλαγή nickname μόνο 1 φορά
    messages = db.relationship('Message', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password) if self.password_hash else False

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

# --------------------------------------------------------------------------
# 4. ΕΡΓΟΣΤΑΣΙΟ ΕΦΑΡΜΟΓΗΣ (create_app)
# --------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1, x_prefix=1)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db').replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
   
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'
    oauth.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
        issuer='https://accounts.google.com'
    )

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))
        return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(display_name=username).first()
            if user and user.check_password(password):
                login_user(user, remember=True)
                return redirect(url_for('chat_page'))
            flash('Λάθος στοιχεία σύνδεσης.', 'error')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login_page'))

    @app.route('/google_login')
    def google_login():
        nonce = secrets.token_urlsafe(16)
        session['nonce'] = nonce
        redirect_uri = url_for('google_auth', _external=True)
        return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

    @app.route('/google_auth')
    def google_auth():
        try:
            token = oauth.google.authorize_access_token()
            nonce = session.pop('nonce', None)
            user_info = oauth.google.parse_id_token(token, nonce=nonce)
            if not user_info:
                return redirect(url_for('login_page'))

            email = user_info.get('email')
            user = User.query.filter_by(email=email).first()

            if not user:
                user = User(
                    email=email,
                    display_name=user_info.get('name', email),
                    role='user',
                    color=random.choice(CHAT_COLORS),
                    avatar_url=user_info.get('picture')
                )
                db.session.add(user)
                db.session.commit()

            login_user(user, remember=True)
            return redirect(url_for('chat_page'))
        except Exception:
            return redirect(url_for('login_page'))

    @app.route('/chat')
    @login_required
    def chat_page():
        return render_template('chat.html', 
                             display_name=current_user.display_name, 
                             role=current_user.role, 
                             color=current_user.color,
                             avatar_url=current_user.avatar_url,
                             has_changed_name=current_user.has_changed_name)

    # --- SOCKETIO EVENTS ---
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            ONLINE_USERS[request.sid] = {
                'id': current_user.id, 
                'display_name': current_user.display_name, 
                'role': current_user.role, 
                'color': current_user.color, 
                'avatar_url': current_user.avatar_url
            }
            emit('users_update', get_online_users_list(), broadcast=True)

    @socketio.on('disconnect')
    def handle_disconnect():
        if request.sid in ONLINE_USERS:
            del ONLINE_USERS[request.sid]
            emit('users_update', get_online_users_list(), broadcast=True)

    @socketio.on('message')
    def handle_message(data):
        if current_user.is_authenticated:
            new_msg = Message(user_id=current_user.id, content=data['content'])
            db.session.add(new_msg)
            db.session.commit()
            emit('message', {
                'display_name': current_user.display_name, 
                'content': data['content'], 
                'color': current_user.color,
                'avatar_url': current_user.avatar_url or f"https://ui-avatars.com/api/?name={current_user.display_name}&background=random"
            }, broadcast=True)

    @socketio.on('update_profile')
    def update_profile(data):
        if current_user.is_authenticated:
            user = User.query.get(current_user.id)
            if 'new_nickname' in data and not user.has_changed_name:
                user.display_name = data['new_nickname']
                user.has_changed_name = True
            if 'new_avatar' in data:
                user.avatar_url = data['new_avatar']
            db.session.commit()
            emit('profile_updated', broadcast=True)

    @socketio.on('clear_chat_request')
    def clear_chat():
        if current_user.is_authenticated and current_user.role == 'owner':
            Message.query.delete()
            db.session.commit()
            emit('clear_chat_client', broadcast=True)

    return app

app = create_app()

if __name__ == '__main__':
    socketio.run(app, debug=True)