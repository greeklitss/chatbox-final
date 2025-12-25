import eventlet
eventlet.monkey_patch()

import os
import random
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_socketio import SocketIO, emit
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash

# --- ΡΥΘΜΙΣΕΙΣ ΕΦΑΡΜΟΓΗΣ ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'radio-parea-secret-2025')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///radio.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- ΡΥΘΜΙΣΕΙΣ GOOGLE OAUTH ---
# Αντικατάστησε αυτά με τα πραγματικά σου κλειδιά
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'
socketio = SocketIO(app, cors_allowed_origins="*")
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='user') # user, admin, owner
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref=db.backref('messages', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ΔΙΑΔΡΟΜΕΣ (ROUTES) ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(display_name=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('chat_page'))
        flash('Λάθος όνομα χρήστη ή κωδικός πρόσβασης.')
    return render_template('login.html')

# GOOGLE LOGIN ROUTES
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
    except Exception as e:
        flash(f"Σφάλμα κατά τη σύνδεση με Google: {str(e)}")
        return redirect(url_for('login_page'))

    if user_info:
        user = User.query.filter_by(email=user_info['email']).first()
        if not user:
            user = User(
                display_name=user_info.get('name', user_info['email']),
                email=user_info['email'],
                avatar_url=user_info.get('picture', '/static/default_avatar.png'),
                role='user'
            )
            db.session.add(user)
            db.session.commit()
        login_user(user)
        return redirect(url_for('chat_page'))
    return redirect(url_for('login_page'))

@app.route('/chat')
@login_required
def chat_page():
    return render_template('chat.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- SOCKET.IO EVENTS ---
@socketio.on('send_message')
def handle_send_message(data):
    if current_user.is_authenticated:
        new_msg = Message(content=data['message'], author=current_user)
        db.session.add(new_msg)
        db.session.commit()
        emit('receive_message', {
            'message': data['message'],
            'user': current_user.display_name,
            'avatar': current_user.avatar_url,
            'timestamp': new_msg.timestamp.strftime('%H:%M')
        }, broadcast=True)


def create_app():
    return app
# --- ΕΚΚΙΝΗΣΗ ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Στο Koyeb/Heroku χρησιμοποιούμε τη θύρα από το περιβάλλον
    port = int(os.environ.get('PORT', 8000))
    socketio.run(app, host='0.0.0.0', port=port)