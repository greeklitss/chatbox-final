import eventlet
eventlet.monkey_patch()  # ΑΠΑΡΑΙΤΗΤΟ: Πρέπει να είναι στην αρχή

import os
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO, emit
import random

# --- INITIALIZATION ---
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1, x_prefix=1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- EXTENSIONS ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'
oauth = OAuth(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

ONLINE_USERS = {}

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        # Προσθήκη του χρήστη στη λίστα των online
        ONLINE_USERS[request.sid] = {
            'id': current_user.id, 
            'display_name': current_user.display_name, 
            'role': current_user.role, 
            'color': current_user.color, 
            'avatar_url': current_user.avatar_url
        }
        # Ενημέρωση όλων για τη νέα λίστα
        emit('users_update', list(ONLINE_USERS.values()), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in ONLINE_USERS:
        del ONLINE_USERS[request.sid]
        emit('users_update', list(ONLINE_USERS.values()), broadcast=True)

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), default='user')
    color = db.Column(db.String(7), default='#008000')
    avatar_url = db.Column(db.String(256), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password) if self.password_hash else False

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- GOOGLE OAUTH ---
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- ROUTES ---
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

@app.route('/google_login')
def google_login():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google_auth')
def google_auth():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token, nonce=session.pop('nonce', None))
    email = user_info.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, display_name=user_info.get('name', email),role='user', color=generate_random_color(), avatar_url=user_info.get('picture'))
        db.session.add(user)
        db.session.commit()
    login_user(user, remember=True)
    return redirect(url_for('chat_page'))

def generate_random_color():
    # Παράγει ένα τυχαίο φωτεινό χρώμα σε HEX
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

def get_online_users_list():
    users_data = []
    # Χρησιμοποιούμε set για να μην εμφανίζεται ο ίδιος χρήστης πολλές φορές
    seen_ids = set()
    for user_data in ONLINE_USERS.values():
        if user_data['id'] not in seen_ids:
            users_data.append({
                'id': user_data['id'],
                'display_name': user_data['display_name'],
                'color': user_data['color'], # Το τυχαίο χρώμα του
                'avatar_url': user_data.get('avatar_url')
            })
            seen_ids.add(user_data['id'])
    # Τυχαία σειρά στη λίστα για να μην προδίδεται ο Owner από τη θέση
    random.shuffle(users_data)
    return users_data
@app.route('/chat')
@login_required
def chat_page():
    # Επιβολή τυχαίου χρώματος αν δεν έχει (Mystery Mode)
    if not current_user.color or current_user.color == '#008000':
        current_user.color = generate_random_color()
        db.session.commit()
    
    # ΠΡΟΣΟΧΗ: Εδώ στέλνουμε το role και το id για να ξεκλειδώσουν τα κουμπιά
    return render_template('chat.html', 
                           user_id=current_user.id, 
                           display_name=current_user.display_name, 
                           role=current_user.role, 
                           color=current_user.color, 
                           avatar_url=current_user.avatar_url)# --- SOCKETIO ---
@socketio.on('message')
def handle_message(data):
    if current_user.is_authenticated:
        # Εδώ αποθηκεύουμε το μήνυμα
        new_msg = Message(user_id=current_user.id, content=data['content'])
        db.session.add(new_msg)
        db.session.commit()

# Εδώ στέλνουμε το μήνυμα σε όλους με τα στοιχεία που χρειάζονται για τα εικονίδια
        emit('message', {
            'id': new_msg.id,
            'user_id': current_user.id,
            'display_name': current_user.display_name, 
            'content': data['content'], 
            'role': current_user.role, 
            'color': current_user.color,
            'avatar_url': current_user.avatar_url
        }, broadcast=True)

# --- START ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    socketio.run(app, debug=True)