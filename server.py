import os
import json
import uuid
import time
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix # 🚨 ΝΕΟ IMPORT: Προσθέστε αυτή τη γραμμή


# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash 
from flask_session import Session 
from sqlalchemy.sql import text 
from sqlalchemy.exc import IntegrityError, ProgrammingError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError 


# 🚨 1. Αρχικοποιούμε τα extensions χωρίς το app (Application Factory Pattern)
db = SQLAlchemy()
sess = Session()
oauth = OAuth()


# --- Ρυθμίσεις Εφαρμογής & Flask App ---
# Χρησιμοποιούμε τη default ρύθμιση για templates/static folders.
app = Flask(__name__) 
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1) 
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", 'a_default_secret_key_for_local_dev')

# --- Ρυθμίσεις Βάσης Δεδομένων ---
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'postgresql://user:password@localhost/chatboxdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Ρυθμίσεις Google OAuth ---
app.config['GOOGLE_CLIENT_ID'] = os.environ.get("GOOGLE_CLIENT_ID", "YOUR_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get("GOOGLE_CLIENT_SECRET", "YOUR_CLIENT_SECRET")
# Η διαδρομή αυτή πρέπει να είναι καταχωρημένη στο Google Cloud Console
GOOGLE_REDIRECT_URI = 'https://chatbox-final.onrender.com/login/google/authorize'

# --- Ρυθμίσεις Session ---
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "sqlalchemy"
app.config["SESSION_SQLALCHEMY"] = db
app.config["SESSION_SQLALCHEMY_TABLE"] = "sessions"
app.config['SESSION_COOKIE_SECURE'] = True # Απαραίτητο για https/Render
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # 🚨 ΠΡΟΣΘΗΚΗ: Αυτό διορθώνει το OAuth redirect issue


# --- Αρχικοποίηση Extensions ---
db.init_app(app)
sess.init_app(app)
oauth.init_app(app)

# --- Ρυθμίσεις SocketIO ---
socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*") 

# --- Ρυθμίσεις OAuth Clients ---
oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False) # Roles: 'user', 'admin', 'owner'
    avatar_url = db.Column(db.String(255), nullable=True)
    # last_seen = db.Column(db.DateTime, default=datetime.utcnow) # Για online list

class Setting(db.Model):
    __tablename__ = 'setting'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=False)

class Emoticon(db.Model):
    __tablename__ = 'emoticon'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)

# 🚨 ΝΕΟ: Μοντέλο για το Ιστορικό Μηνυμάτων
class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(2000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to get user details easily
    user = db.relationship('User', backref='messages')


# --- Utility Functions ---
def requires_role(*roles):
    """Decorator για έλεγχο ρόλου."""
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in roles:
                return jsonify({'message': 'Access denied.'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

def login_required(f):
    """Decorator για έλεγχο σύνδεσης."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user_or_guest():
    """Επιστρέφει το αντικείμενο User ή ένα ψεύτικο Guest object."""
    user_id = session.get('user_id')
    user_role = session.get('role', 'guest')
    
    if user_role == 'guest' or not user_id:
        class GuestUser:
            id = session.get('user_id', 'GUEST-' + str(uuid.uuid4()))
            display_name = session.get('display_name', 'Guest')
            role = 'guest'
            avatar_url = url_for('static', filename='default_avatar.png')
        session['user_id'] = GuestUser.id
        session['role'] = GuestUser.role
        session['display_name'] = GuestUser.display_name
        return GuestUser
    
    with app.app_context():
        return db.session.get(User, user_id)

# --- Routes ---
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    # Εάν ο χρήστης είναι ήδη συνδεδεμένος, πήγαινε στο chat
    if 'user_id' in session and session.get('role') != 'guest':
        return redirect(url_for('chat'))
    
    # Επιτρέπει τη σύνδεση ως guest
    guest_user = get_current_user_or_guest()
    
    return render_template('login.html', guest_user=guest_user)

# --- Google OAuth Handlers ---
@app.route('/login/google')
def login_google():
    """Ξεκινά τη διαδικασία Google OAuth."""
    # Κρίσιμο: Περνάμε το σωστό redirect_uri (πρέπει να ταιριάζει με το Google Cloud Console)
    return oauth.google.authorize_redirect(GOOGLE_REDIRECT_URI) 

@app.route('/login/google/authorize')
def authorize_google():
    """Λαμβάνει τον κωδικό εξουσιοδότησης από το Google."""
    try:
        token = oauth.google.authorize_access_token()
    except MismatchingStateError as e:
        print(f"Mismatching State Error: {e}")
        return redirect(url_for('login'))
    except OAuthError as e:
        print(f"OAuth Error during token retrieval: {e}")
        return redirect(url_for('login'))
    except Exception as e:
        print(f"An unexpected error occurred during authorization: {e}")
        return redirect(url_for('login'))


    if token:
        user_info = oauth.google.parse_id_token(token)
        google_id = user_info['sub']
        email = user_info['email']
        display_name = user_info.get('name', email.split('@')[0])
        username = email.split('@')[0]
        
        with app.app_context():
            user = db.session.execute(db.select(User).filter_by(google_id=google_id)).scalar_one_or_none()
            
            if user is None:
                # Δημιουργία νέου χρήστη
                user = User(
                    google_id=google_id,
                    username=username,
                    display_name=display_name,
                    email=email,
                    role='user',
                    avatar_url=user_info.get('picture')
                )
                db.session.add(user)
                try:
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    # Εάν το email υπάρχει ήδη, συνδέουμε τον google_id
                    user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one()
                    user.google_id = google_id
                    db.session.commit()
            
            # Ενημέρωση Session
            session['user_id'] = user.id
            session['display_name'] = user.display_name
            session['role'] = user.role
            session['is_google_user'] = True

        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login/guest', methods=['GET', 'POST']) # 🚨 ΔΙΟΡΘΩΣΗ: Προσθέτουμε POST
def login_guest():
    """Δημιουργεί ένα guest session."""
    guest_id = 'GUEST-' + str(uuid.uuid4())
    session['user_id'] = guest_id
    session['display_name'] = f'Guest-{guest_id[:4]}'
    session['role'] = 'guest'
    return redirect(url_for('chat'))
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('display_name', None)
    session.pop('role', None)
    session.pop('is_google_user', None)
    return redirect(url_for('login'))


# --- Chat & Core Routes ---
@app.route('/chat')
@login_required
def chat():
    """Φορτώνει τη σελίδα chat και το ιστορικό μηνυμάτων."""
    
    user = None
    messages = []
    
    with app.app_context():
        # Παίρνουμε τον χρήστη/guest
        user = get_current_user_or_guest() 
        current_settings = {s.key: s.value for s in Setting.query.all()}
        
        # 🚨 ΚΡΙΣΙΜΟ: Φόρτωση των τελευταίων 100 μηνυμάτων (μόνο για registered users)
        if user and user.role != 'guest':
            messages = db.session.query(Message)\
                         .join(User, Message.user_id == User.id)\
                         .order_by(Message.timestamp.desc())\
                         .limit(100).all()
            messages.reverse() # Αντιστρέφουμε για να είναι σωστή η σειρά

    if user:
        return render_template('chat.html', user=user, messages=messages, current_settings=current_settings)
    
    return redirect(url_for('login')) 


# --- Admin Routes ---
@app.route('/admin_panel')
@requires_role('owner', 'admin')
def admin_panel():
    with app.app_context():
        # Παίρνουμε όλους τους χρήστες 
        users = User.query.all()
        return render_template('admin_panel.html', users=users)

@app.route('/admin/set_role', methods=['POST'])
@requires_role('owner', 'admin')
def set_user_role():
    """Επιτρέπει στον admin να αλλάξει τον ρόλο ενός άλλου χρήστη (μέσω AJAX)."""
    data = request.get_json()
    user_id = data.get('user_id')
    new_role = data.get('role')
    
    if not user_id or new_role not in ['user', 'admin', 'owner']:
        return jsonify({'success': False, 'message': 'Invalid data.'}), 400

    with app.app_context():
        user = db.session.get(User, user_id)
        if user:
            # Απαγόρευση αλλαγής του ρόλου του ίδιου του χρήστη μέσω αυτής της διαδρομής
            if user.id == session['user_id']:
                 return jsonify({'success': False, 'message': 'Cannot change your own role.'}), 403
            
            user.role = new_role
            db.session.commit()
            return jsonify({'success': True, 'message': f'User {user.display_name} role set to {new_role}.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404

# --- Settings Routes (ΟΜΑΔΑ 3 - ΑΣΠΡΟ) ---
@app.route('/settings/set_avatar_url', methods=['POST'])
def set_avatar_url():
    """Επιτρέπει στον χρήστη να αλλάξει το avatar του μέσω URL (μέσω AJAX)."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401
    
    data = request.get_json()
    new_url = data.get('avatar_url')
    
    if not new_url:
        return jsonify({'success': False, 'message': 'Missing URL.'}), 400

    user_id = session['user_id']
    with app.app_context():
        if session.get('role') == 'guest':
             return jsonify({'success': True, 'message': 'Avatar URL set for this session.'})
             
        user = db.session.get(User, user_id)
        if user:
            user.avatar_url = new_url
            db.session.commit()
            
            # Ενημερώνουμε όλους μέσω SocketIO για την αλλαγή avatar
            socketio.emit('user_avatar_updated', {
                'user_id': user.id,
                'avatar_url': new_url
            }, room='chat')
            
            return jsonify({'success': True, 'message': 'Avatar URL updated.'})
        else:
            return jsonify({'success': False, 'message': 'User not found.'}), 404
            

# --- SocketIO Events ---
@socketio.on('join')
def handle_join(data):
    """Χειρίζεται το join ενός χρήστη στο chat room."""
    user = get_current_user_or_guest()
    # join_room('chat')
    # print(f"{user.display_name} has joined the chat.")
    # emit('status', {'msg': f'{user.display_name} has entered the room.'}, room='chat')

@socketio.on('send_message')
def handle_message(data):
    """Λαμβάνει ένα μήνυμα από έναν χρήστη, το αποθηκεύει και το στέλνει σε όλους τους άλλους."""
    if 'user_id' not in session or 'message' not in data:
        return
        
    user_id = session['user_id']
    user_role = session.get('role', 'guest')
    display_name = session.get('display_name', 'Guest')
    message_text = data['message']
    
    # 🚨 1. Αποθήκευση του μηνύματος (μόνο για registered users)
    if user_role != 'guest':
        try:
            with app.app_context():
                user_instance = db.session.get(User, user_id)
                if not user_instance:
                    return # Μην σώζεις αν δεν υπάρχει χρήστης
                
                new_message = Message(
                    user_id=user_id, 
                    text=message_text,
                    timestamp=datetime.now()
                )
                db.session.add(new_message)
                db.session.commit()
        except Exception as e:
            print(f"Error saving message: {e}") 
            
    # 🚨 2. Εκπομπή του μηνύματος στους clients (για εμφάνιση και ήχο)
    emit('new_message', {
        'message': message_text,
        'username': display_name,
        'role': user_role, # ΚΡΙΣΙΜΟ: Στέλνουμε το ρόλο για χρωματισμό
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }, broadcast=True)
    
    print(f"Message from {display_name} ({user_role}): {message_text}")


# --- MAIN EXECUTION ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Χρησιμοποιήστε socketio.run(app) αντί για app.run() όταν χρησιμοποιείτε SocketIO
    socketio.run(app, debug=True)