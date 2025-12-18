import eventlet
eventlet.monkey_patch()

import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO, emit

# 1. Extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth()
socketio = SocketIO()

ONLINE_USERS = {} 

# 2. Models
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
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

# 3. Helpers
def get_online_users_list():
    users_data = []
    unique_ids = set()
    for user_data in ONLINE_USERS.values():
        if user_data['id'] not in unique_ids:
            users_data.append(user_data)
            unique_ids.add(user_data['id'])
    return users_data

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 4. Factory
def create_app():
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')
    
    # Database Fix
    db_uri = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    if db_uri.startswith("postgres://"):
        db_uri = db_uri.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet')

    # ROUTES
    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        if request.method == 'POST':
            # Η λογική σου για το login
            pass
        return render_template('login.html')

    @app.route('/register')
    def register_page():
        return render_template('login.html') # Ή register.html αν έχεις

    @app.route('/chat')
    @login_required
    def chat_page():
        return render_template('chat.html')

    # SOCKETS
    @socketio.on('message')
    def handle_message(data):
        if current_user.is_authenticated:
            emit('message', {'display_name': current_user.display_name, 'content': data['content']}, broadcast=True)

    # Δημιουργία πινάκων αν δεν υπάρχουν
    with app.app_context():
        db.create_all()

    return app
app = create_app()

if __name__ == '__main__':
    # Αυτό τρέχει μόνο τοπικά για δοκιμές
    socketio.run(app, debug=True)
