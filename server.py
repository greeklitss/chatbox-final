import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timezone
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO, emit
import secrets

# --- ΕΚΤΑΣΕΙΣ ---
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth()
socketio = SocketIO()

ONLINE_USERS = {} 

# --- ΜΟΝΤΕΛΑ ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True) 
    password_hash = db.Column(db.String(256), nullable=True) 
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
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- CREATE APP ---
def create_app():
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1, x_prefix=1)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key-123')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db').replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # HTTPS & COOKIES FIX
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
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

    # --- ROUTES ---
    @app.route('/')
    def index():
        if current_user.is_authenticated: return redirect(url_for('chat_page'))
        return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        if current_user.is_authenticated: return redirect(url_for('chat_page'))
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(display_name=username).first()
            if user and user.check_password(password):
                login_user(user, remember=True)
                return redirect(url_for('chat_page'))
            flash('Λάθος στοιχεία σύνδεσης.', 'error')
        return render_template('login.html')

    @app.route('/google_login')
    def google_login():
        nonce = secrets.token_urlsafe(16)
        session['nonce'] = nonce
        return oauth.google.authorize_redirect(url_for('google_auth', _external=True), nonce=nonce)

    @app.route('/google_auth')
    def google_auth():
        try:
            token = oauth.google.authorize_access_token()
            user_info = oauth.google.parse_id_token(token, nonce=session.pop('nonce', None))
            email = user_info.get('email')
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(email=email, display_name=user_info.get('name', email), role='user', color='#00FFC0', avatar_url=user_info.get('picture'))
                db.session.add(user); db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('chat_page'))
        except Exception as e:
            print(f"Auth Error: {e}"); return redirect(url_for('login_page'))

    @app.route('/chat')
    @login_required
    def chat_page():
        history = Message.query.order_by(Message.timestamp.asc()).limit(100).all()
        return render_template('chat.html', messages=history)

    @app.route('/logout')
    def logout():
        logout_user(); return redirect(url_for('index'))

    # --- SOCKETIO ---
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            ONLINE_USERS[request.sid] = {'id': current_user.id, 'display_name': current_user.display_name, 'role': current_user.role, 'color': current_user.color, 'avatar_url': current_user.avatar_url}
            emit('users_update', list(ONLINE_USERS.values()), broadcast=True)

    @socketio.on('disconnect')
    def handle_disconnect():
        ONLINE_USERS.pop(request.sid, None)
        emit('users_update', list(ONLINE_USERS.values()), broadcast=True)

    @socketio.on('message')
    def handle_message(data):
        if current_user.is_authenticated:
            msg = Message(user_id=current_user.id, content=data['content'])
            db.session.add(msg); db.session.commit()
            emit('message', {'display_name': current_user.display_name, 'content': data['content'], 'timestamp': datetime.now().isoformat(), 'color': current_user.color, 'avatar_url': current_user.avatar_url}, broadcast=True)

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app)