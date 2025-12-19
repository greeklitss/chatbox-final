import os
import random
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'radioparea_secret_123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///radioparea.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'owner', 'admin', 'user'
    color = db.Column(db.String(20), default='#D4AF37')
    avatar_url = db.Column(db.String(200), default='/static/default_avatar.png')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- UTILS ---
def generate_random_color():
    colors = ['#ff4d4d', '#4dff4d', '#4da6ff', '#ffff4d', '#ff4dff', '#4dffff', '#D4AF37', '#ffffff']
    return random.choice(colors)

def get_online_users_list():
    return [user for user in ONLINE_USERS.values()]

ONLINE_USERS = {}

# --- ROUTES ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('chat_page'))
        flash('Λάθος στοιχεία!')
    return render_template('login.html')

@app.route('/chat')
@login_required
def chat_page():
    # Αν ο χρήστης δεν έχει χρώμα, του δίνουμε ένα τυχαίο (Mystery Mode)
    if not current_user.color or current_user.color == '#008000':
        current_user.color = generate_random_color()
        db.session.commit()
    
    return render_template('chat.html', 
                         user_id=current_user.id, 
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
            'id': current_user.id,
            'display_name': current_user.display_name,
            'color': current_user.color,
            'role': current_user.role
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
        # Αποθήκευση στη βάση
        new_msg = Message(user_id=current_user.id, content=data['content'])
        db.session.add(new_msg)
        db.session.commit()
        
        # Εκπομπή σε όλους
        emit('message', {
            'id': new_msg.id,
            'display_name': current_user.display_name,
            'content': data['content'],
            'color': current_user.color,
            'role': current_user.role
        }, broadcast=True)

@socketio.on('clear_chat_request')
def handle_clear_chat():
    # Μόνο ο Owner μπορεί να καθαρίσει το chat
    if current_user.is_authenticated and current_user.role == 'owner':
        Message.query.delete()
        db.session.commit()
        emit('clear_chat_client', broadcast=True)

# --- INITIALIZE DATABASE ---
def init_db():
    with app.app_context():
        db.create_all()
        # Έλεγχος αν υπάρχει ήδη owner, αλλιώς δημιουργία
        if not User.query.filter_by(role='owner').first():
            hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
            owner = User(username='admin', 
                         password=hashed_pw, 
                         display_name='Admin', 
                         role='owner', 
                         color='#D4AF37')
            db.session.add(owner)
            db.session.commit()
            print("Owner created: admin / admin123")

if __name__ == '__main__':
    init_db()
    # Χρήση eventlet για το Render
    socketio.run(app, host='0.0.0.0', port=10000)