import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import select
from datetime import datetime
from authlib.integrations.flask_client import OAuth, OAuthError as AuthlibOAuthError
from flask_socketio import SocketIO, emit
import eventlet

# --------------------------------------------------------------------------
# 1. ΕΚΤΑΣΕΙΣ (Extensions)
# --------------------------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth()
socketio = SocketIO()

ONLINE_USERS = {} 

# --------------------------------------------------------------------------
# 2. ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ
# --------------------------------------------------------------------------
def get_default_color_by_role(role):
    colors = {'owner': '#FF0000', 'admin': '#0000FF', 'user': '#008000', 'guest': '#808080'}
    return colors.get(role.lower(), '#000000')

def get_online_users_list():
    users_data = []
    unique_users = {}
    for user_data in ONLINE_USERS.values():
        unique_users[user_data['id']] = user_data
    for user_data in unique_users.values():
        users_data.append({
            'id': user_data['id'],
            'display_name': user_data['display_name'],
            'role': user_data['role'],
            'color': user_data['color'],
            'avatar_url': user_data.get('avatar_url')
        })
    role_order = {'owner': 1, 'admin': 2, 'user': 3, 'guest': 4}
    users_data.sort(key=lambda x: role_order.get(x['role'].lower(), 5))
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
    color = db.Column(db.String(7), default='#008000')
    avatar_url = db.Column(db.String(256), nullable=True) 
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

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(256), nullable=False)

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
    
    # HTTPS FIXES FOR RENDER
    app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['PREFERRED_URL_SCHEME'] = 'https'

    # GOOGLE OAUTH
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

    # ROUTES
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

    # --- Η ΔΙΟΡΘΩΣΗ: Προσθήκη του Register Route ---
    @app.route('/register')
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))
        return render_template('login.html') # Χρησιμοποιούμε την ίδια σελίδα
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/google_login')
    def google_login():
        return oauth.google.authorize_redirect(url_for('google_auth', _external=True))

    @app.route('/google_auth')
    def google_auth():
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token)
        google_id = user_info['sub']
        user = User.query.filter_by(google_id=google_id).first()
        if not user:
            user = User(display_name=user_info['name'], email=user_info['email'], google_id=google_id, role='user', color=get_default_color_by_role('user'), avatar_url=user_info.get('picture'))
            db.session.add(user)
            db.session.commit()
        login_user(user)
        return redirect(url_for('chat_page'))

    @app.route('/chat')
    @login_required
    def chat_page():
        return render_template('chat.html', user_id=current_user.id, display_name=current_user.display_name, role=current_user.role, color=current_user.color, avatar_url=current_user.avatar_url)

    @app.route('/api/v1/sign_up', methods=['POST'])
    def api_sign_up():
        data = request.get_json()
        if User.query.filter_by(display_name=data.get('username')).first():
            return jsonify({'error': 'Το όνομα χρήστη υπάρχει ήδη.'}), 409
        user = User(display_name=data.get('username'), role='user', color=get_default_color_by_role('user'))
        user.set_password(data.get('password'))
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'Επιτυχής εγγραφή'}), 201

    # SOCKETIO EVENTS
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            ONLINE_USERS[request.sid] = {'id': current_user.id, 'display_name': current_user.display_name, 'role': current_user.role, 'color': current_user.color, 'avatar_url': current_user.avatar_url}
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
            emit('message', {'display_name': current_user.display_name, 'content': data['content'], 'timestamp': datetime.utcnow().isoformat(), 'role': current_user.role, 'color': current_user.color}, broadcast=True)

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)