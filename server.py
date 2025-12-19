import eventlet
eventlet.monkey_patch()

import os
import random
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'radioparea_premium_key_2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///radioparea.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
# Σημαντικό: async_mode='eventlet'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user') 
    color = db.Column(db.String(20), default='#D4AF37')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

ONLINE_USERS = {}

# --- ROUTES ---
@app.route('/')
def health_check():
    if current_user.is_authenticated:
        return redirect(url_for('chat_page'))
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('chat_page'))
        flash('Λάθος στοιχεία πρόσβασης!')
    return render_template('login.html')

@app.route('/chat')
@login_required
def chat_page():
    return render_template('chat.html', 
                         display_name=current_user.display_name, 
                         role=current_user.role, 
                         color=current_user.color)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- SOCKETIO EVENTS ---
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        ONLINE_USERS[request.sid] = {
            'display_name': current_user.display_name,
            'color': current_user.color,
            'role': current_user.role
        }
        emit('users_update', list(ONLINE_USERS.values()), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in ONLINE_USERS:
        del ONLINE_USERS[request.sid]
        emit('users_update', list(ONLINE_USERS.values()), broadcast=True)

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
            'role': current_user.role
        }, broadcast=True)

@socketio.on('clear_chat_request')
def handle_clear():
    if current_user.is_authenticated and current_user.role == 'owner':
        Message.query.delete()
        db.session.commit()
        emit('clear_chat_client', broadcast=True)

# --- INIT ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
            owner = User(username='admin', password=hashed_pw, display_name='Admin', role='owner', color='#D4AF37')
            db.session.add(owner)
            db.session.commit()
    socketio.run(app, host='0.0.0.0', port=10000)