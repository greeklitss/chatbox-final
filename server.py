import eventlet
eventlet.monkey_patch()

import os
import random
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
socketio = SocketIO()

ONLINE_USERS = {}

# --- ΜΟΝΤΕΛΑ ΒΑΣΗΣ ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), default='user')
    color = db.Column(db.String(20), default='#D4AF37')
    avatar_url = db.Column(db.String(256), nullable=True)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password) if self.password_hash else False

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    text_color = db.Column(db.String(20), default='#ffffff')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', backref='messages_list')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Μνήμη για το φόντο (Global)
bg_storage = {"url": None, "size": "100", "position": "55"}

def create_app():
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1, x_prefix=1)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'radioparea_secret_2025')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db').replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet')

    @app.route('/')
    @login_required
    def chat_page():
        history = Message.query.order_by(Message.timestamp.desc()).limit(50).all()[::-1]
        return render_template('chat.html', history=history)

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        if request.method == 'POST':
            user = User.query.filter_by(display_name=request.form.get('username')).first()
            if user and user.check_password(request.form.get('password')):
                login_user(user, remember=True)
                return redirect(url_for('chat_page'))
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect(url_for('login_page'))

    # --- SOCKET EVENTS ---
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            ONLINE_USERS[request.sid] = {
                'id': current_user.id, 'display_name': current_user.display_name,
                'role': current_user.role, 'color': current_user.color,
                'avatar_url': current_user.avatar_url or f"https://ui-avatars.com/api/?name={current_user.display_name}"
            }
            emit('user_list', list(ONLINE_USERS.values()), broadcast=True)
            if bg_storage["url"]: emit('init_background', bg_storage)

    @socketio.on('disconnect')
    def handle_disconnect():
        if request.sid in ONLINE_USERS:
            del ONLINE_USERS[request.sid]
            emit('user_list', list(ONLINE_USERS.values()), broadcast=True)

    @socketio.on('message')
    def handle_message(data):
        if current_user.is_authenticated:
            msg = Message(content=data['content'], user_id=current_user.id, text_color=data.get('text_color', '#fff'))
            db.session.add(msg)
            db.session.commit()
            emit('message', {
                'display_name': current_user.display_name, 'content': data['content'],
                'color': current_user.color, 'text_color': data.get('text_color', '#fff')
            }, broadcast=True)

    @socketio.on('admin_change_bg')
    def handle_bg(data):
        if current_user.role == 'owner':
            bg_storage["url"] = data['url']
            emit('update_bg', bg_storage, broadcast=True)

    @socketio.on('admin_bg_transform')
    def handle_transform(data):
        if current_user.role == 'owner':
            bg_storage["size"] = data.get('size', bg_storage["size"])
            bg_storage["position"] = data.get('position', bg_storage["position"])
            emit('update_bg_transform', bg_storage, broadcast=True)

    @socketio.on('update_profile')
    def handle_profile(data):
        if current_user.is_authenticated:
            current_user.color = data.get('color', current_user.color)
            current_user.avatar_url = data.get('avatar_url', current_user.avatar_url)
            db.session.commit()
            if request.sid in ONLINE_USERS:
                ONLINE_USERS[request.sid].update({'color': current_user.color, 'avatar_url': current_user.avatar_url})
            emit('user_list', list(ONLINE_USERS.values()), broadcast=True)

    @socketio.on('clear_chat_request')
    def handle_clear():
        if current_user.role == 'owner':
            Message.query.delete()
            db.session.commit()
            emit('message', {'content': 'CLEAN_EVENT'}, broadcast=True)

    with app.app_context(): db.create_all()
    return app

if __name__ == '__main__':
    socketio.run(create_app())