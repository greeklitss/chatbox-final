import os
import json
import uuid
import time
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from functools import wraps

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix 
from sqlalchemy import select, desc # 🚨 Προσθήκη desc
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash 
from flask_session import Session 
from sqlalchemy.sql import text 
from sqlalchemy.exc import IntegrityError, ProgrammingError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError 


# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app
db = SQLAlchemy()
sess = Session()
oauth = OAuth()


# --- Ρυθμίσεις Εφαρμογής & Flask App ---
app = Flask(__name__) 
# 🚨 ΚΡΙΣΙΜΗ ΠΡΟΣΘΗΚΗ: ΕΦΑΡΜΟΓΗ PROXYFIX για το Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1) 
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key')

# --- DB Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Session Configuration (Χρήση SQLAlchemy για συνεδρίες) ---
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_COOKIE_NAME'] = 'flask_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# --- Initializations ---
db.init_app(app)
sess.init_app(app)
socketio = SocketIO(app, manage_session=False, cors_allowed_origins='*', path='/socket.io') # 🚨 ΚΡΙΣΙΜΟ path='/socket.io' για Render
oauth.init_app(app)


# --- DATABASE MODELS (ΚΡΙΣΙΜΟ ΓΙΑ ΙΣΤΟΡΙΚΟ) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user') # user, admin, owner, guest
    avatar_url = db.Column(db.String(255), default='/static/default_avatar.png')
    
    messages = db.relationship('Message', backref='author', lazy='dynamic')
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.id} by {self.user_id}>'
    
# --- GLOBAL CHAT DATA (ΚΡΙΣΙΜΟ ΓΙΑ ONLINE USERS) ---
# Λεξικό για τη διαχείριση ενεργών χρηστών {user_id: {'username': str, 'role': str, 'sids': set, 'avatar_url': str}}
active_users = {}


# --- AUTH DECORATOR ---
# Υποθέτω ότι υπάρχει, αλλιώς πρέπει να το προσθέσετε
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- HELPER FUNCTION ΓΙΑ ΕΝΕΡΓΟΥΣ ΧΡΗΣΤΕΣ ---
def get_online_users():
    """Επιστρέφει μια λίστα με τους ενεργούς χρήστες για μετάδοση (με avatar)."""
    with app.app_context():
        users_list = []
        for user_id, data in active_users.items():
            user_data_from_db = db.session.get(User, user_id)
            avatar = user_data_from_db.avatar_url if user_data_from_db else '/static/default_avatar.png'
            users_list.append({
                'id': user_id, 
                'username': data['username'], 
                'role': data['role'],
                'avatar_url': avatar
            })
        return users_list


# --- FLASK ROUTES (Chat & Ιστορικό) ---

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return render_template('login.html')

@app.route('/chat')
@login_required
def chat_page():
    # Εδώ θα περάσετε τα δεδομένα του χρήστη στο template
    user_data = {
        'username': session.get('username'),
        'role': session.get('role'),
        'id': session.get('user_id'),
    }
    return render_template('chat.html', user=user_data)


# 🚨 ΝΕΟ: ROUTE ΓΙΑ ΙΣΤΟΡΙΚΟ ΜΗΝΥΜΑΤΩΝ (ΚΡΙΣΙΜΟ ΓΙΑ ΤΗ ΜΝΗΜΗ)
@app.route('/api/v1/messages', methods=['GET'])
@login_required 
def get_message_history():
    try:
        with app.app_context():
            # Φόρτωση των τελευταίων 50 μηνυμάτων
            messages = db.session.execute(
                select(Message)
                .order_by(desc(Message.timestamp))
                .limit(50)
            ).scalars().all()
            
            messages.reverse() # Αντιστροφή της λίστας για χρονολογική σειρά
            
            history = []
            for msg in messages:
                user = db.session.get(User, msg.user_id)
                
                username = user.username if user else 'Unknown'
                role = user.role if user else 'guest' 
                avatar = user.avatar_url if user else '/static/default_avatar.png' 

                history.append({
                    'username': username,
                    'role': role,
                    'msg': msg.content,
                    'timestamp': msg.timestamp.isoformat(), 
                    'user_id': msg.user_id,
                    'avatar_url': avatar
                })

            return jsonify(history), 200
    except Exception as e:
        print(f"Error loading message history: {e}")
        return jsonify([]), 500

# --- SOCKETIO EVENTS (ΚΡΙΣΙΜΟ ΓΙΑ CHAT & ONLINE USERS) ---

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        role = session['role']
        sid = request.sid

        join_room('chat')

        if user_id not in active_users:
            # Ο χρήστης συνδέεται για πρώτη φορά
            active_users[user_id] = {'username': username, 'role': role, 'sids': {sid}}
            
            # Ενημέρωση όλων για τον νέο χρήστη (στέλνουμε την πλήρη λίστα)
            emit('update_active_users', get_online_users(), broadcast=True)
            
        else:
            # Ο χρήστης επανασυνδέεται (π.χ. ανανέωση)
            active_users[user_id]['sids'].add(sid)
            # Στέλνουμε μόνο σε αυτόν την τρέχουσα λίστα
            emit('update_active_users', get_online_users(), room=sid)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user_id = session['user_id']
        sid = request.sid
        
        if user_id in active_users:
            active_users[user_id]['sids'].discard(sid)
            
            if not active_users[user_id]['sids']:
                # Τελευταία συνεδρία αποσυνδέθηκε
                del active_users[user_id]
                
                # Ενημέρωση όλων για την αποσύνδεση
                emit('update_active_users', get_online_users(), broadcast=True)

@socketio.on('message')
def handle_message(data):
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    username = session['username']
    role = session['role']
    msg_content = data.get('msg')
    
    if not msg_content:
        return

    timestamp = datetime.now(timezone.utc)
    
    # 1. Αποθήκευση στη Βάση Δεδομένων
    try:
        with app.app_context():
            new_message = Message(user_id=user_id, content=msg_content, timestamp=timestamp)
            db.session.add(new_message)
            db.session.commit()
    except Exception as e:
        print(f"Database error saving message: {e}")
        # Δεν επιστρέφουμε, ώστε να ενημερωθεί τουλάχιστον ο χρήστης
        
    # 2. Αποστολή σε όλους
    message_data = {
        'username': username,
        'role': role,
        'msg': msg_content,
        'timestamp': timestamp.isoformat(),
        'user_id': user_id
    }
    emit('new_message', message_data, room='chat', include_self=True)
    
# (Ο υπόλοιπος κώδικας για Admin, Avatars, κλπ. παραμένει ίδιος)
# ...
# ...

# --- ΠΡΟΣΘΗΚΗ: ΚΡΙΣΙΜΟΣ ΕΛΕΓΧΟΣ ΔΗΜΙΟΥΡΓΙΑΣ ΒΑΣΗΣ ---
with app.app_context():
    # Δημιουργεί όλους τους πίνακες (User, Message, Setting κ.λπ.) αν δεν υπάρχουν
    db.create_all() 
    
    # initialize_settings()
    # initialize_emoticons() 

if __name__ == '__main__':
    # Χρησιμοποιήστε το socketio.run για να διαχειριστεί τις συνδέσεις
    socketio.run(app, debug=True, port=os.environ.get('PORT', 5000))