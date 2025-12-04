import os
import secrets
import json
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlunparse

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select, and_
from sqlalchemy.exc import IntegrityError
import requests

# ----------------------------------------------------
# 1. ΒΑΣΙΚΕΣ ΡΥΘΜΙΣΕΙΣ FLASK & DB
# ----------------------------------------------------

# Σταθερές
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(16))
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*") # Απαραίτητο για το Render

# Google OAuth 2.0 Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
google_config = requests.get(GOOGLE_DISCOVERY_URL).json()
GOOGLE_AUTH_URL = google_config["authorization_endpoint"]
GOOGLE_TOKEN_URL = google_config["token_endpoint"]
GOOGLE_USERINFO_URL = google_config["userinfo_endpoint"]

# ----------------------------------------------------
# 2. ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ
# ----------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(120), unique=True, nullable=True) # Τροποποιήθηκε σε nullable=True
    password_hash = db.Column(db.String(255), nullable=True) # Νέο πεδίο
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False) # 'owner', 'admin', 'user'
    color = db.Column(db.String(7), default='#008cff', nullable=False) # Χρώμα κειμένου
    avatar_url = db.Column(db.String(255), nullable=True)
    
    # Σχέσεις
    messages = db.relationship('Message', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.display_name} | Role: {self.role}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

# ----------------------------------------------------
# 3. HELPER FUNCTIONS & DECORATORS
# ----------------------------------------------------

def get_default_color_by_role(role):
    """Επιστρέφει το προεπιλεγμένο χρώμα με βάση τον ρόλο."""
    if role == 'owner':
        return '#FF3399' # Έντονο Ροζ
    elif role == 'admin':
        return '#00CC00' # Πράσινο
    else:
        return '#FFFFFF' # Λευκό

@app.before_request
def load_user_from_session():
    """Φορτώνει τον χρήστη από το session σε κάθε request."""
    user = None
    if 'user_id' in session:
        user = db.session.execute(select(User).where(User.id == session['user_id'])).scalar_one_or_none()
    request.current_user = user

def login_required(f):
    """Decorator: Απαιτεί σύνδεση."""
    def decorated_function(*args, **kwargs):
        if request.current_user is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ # Fix for Flask routing
    return decorated_function

def check_admin_or_owner(f):
    """Decorator: Απαιτεί ρόλο 'admin' ή 'owner'."""
    @login_required
    def decorated_function(*args, **kwargs):
        user = request.current_user
        if user and user.role in ['admin', 'owner']:
            return f(*args, **kwargs)
        # Αποστολή 403 Forbidden ή ανακατεύθυνση
        return abort(403)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ----------------------------------------------------
# 4. ROUTES
# ----------------------------------------------------

# 4.1 Index
@app.route('/')
def index():
    return render_template('index.html')

# 4.2 Login / Logout / OAuth

@app.route('/login')
def login():
    if request.current_user:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/oauth_login')
def oauth_login():
    """Εκκίνηση της διαδικασίας Google OAuth."""
    # ... (ο κώδικας για το Google OAuth) ...

@app.route('/oauth_callback/google')
def oauth_callback():
    """Callback μετά την εξουσιοδότηση της Google."""
    # ... (ο κώδικας για το Google OAuth) ...

@app.route('/check_login')
@login_required
def check_login():
    """Επιστρέφει τα βασικά στοιχεία χρήστη για έλεγχο από το frontend."""
    user = request.current_user
    return jsonify({
        'id': user.id,
        'display_name': user.display_name,
        'role': user.role
    })

@app.route('/login_submit', methods=['POST'])
def login_submit():
    """Διαδικασία Traditional Login."""
    display_name = request.form.get('display_name')
    password = request.form.get('password')

    if not display_name or not password:
        # Δεν πρέπει να αποκαλύψουμε αν έφταιγε το username ή το password
        return render_template('login.html', error='Invalid display name or password.')
    
    # Βρες τον χρήστη με βάση το display name
    user = db.session.execute(select(User).where(User.display_name == display_name)).scalar_one_or_none()

   # Έλεγχος: Ο χρήστης υπάρχει ΚΑΙ έχει password_hash
    if user and user.password_hash and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        print(f"--- SUCCESS LOGIN: User {user.display_name} (ID: {user.id}) logged in and ID saved to session.") # 🚨 Νέα γραμμή
        return redirect(url_for('chat'))
    else:
        print("--- FAILED LOGIN: Invalid credentials or hash mismatch.") # 🚨 Νέα γραμμή
        return render_template('login.html', error='Invalid display name or password.')


# 4.3 Chat Route
@app.route('/chat')
@login_required
def chat():
    # Προετοιμασία δεδομένων χρήστη για το chat.html
    user = request.current_user
    return render_template('chat.html', user_id=user.id, display_name=user.display_name, role=user.role, color=user.color, avatar_url=user.avatar_url)


# 4.4 Admin Panel & Creation Routes

@app.route('/admin_panel')
@check_admin_or_owner
def admin_panel():
    return render_template('admin_panel.html')

@app.route('/admin_create_user', methods=['POST'])
@check_admin_or_owner
def admin_create_user():
    """Δημιουργία νέου χρήστη με κωδικό μέσω Admin Panel (AJAX)."""
    try:
        data = request.get_json() 
    except:
        return jsonify({'error': 'Invalid JSON format'}), 400
        
    display_name = data.get('display_name')
    password = data.get('password')
    role = data.get('role', 'user') 

    if not display_name or not password:
        return jsonify({'error': 'Display name and password are required'}), 400

    hashed_password = generate_password_hash(password)
    default_color = get_default_color_by_role(role)

    try:
        new_user = User(
            display_name=display_name,
            password_hash=hashed_password,
            role=role,
            color=default_color,
            avatar_url=None # Μηδενικό avatar
        )
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'message': f'User {display_name} created successfully with role {role}.'}), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'User with this display name already exists.'}), 409
    except Exception as e:
        db.session.rollback()
        print(f"Error creating user via admin panel: {e}")
        return jsonify({'error': 'An unexpected error occurred.'}), 500


# 4.5 API Routes (User Settings & Admin Management)

@app.route('/api/v1/user/settings', methods=['POST'])
@login_required
def update_user_settings():
    """Ενημέρωση ρυθμίσεων του ίδιου του χρήστη (Nickname, Avatar, Password)."""
    user = request.current_user
    data = request.get_json()
    
    # 1. Αλλαγή Display Name (Nickname)
    new_display_name = data.get('display_name')
    if new_display_name and user.display_name != new_display_name:
        existing_user = db.session.execute(select(User).where(User.display_name == new_display_name)).scalar_one_or_none()
        if existing_user:
            return jsonify({'error': 'Nickname already in use.'}), 409
        user.display_name = new_display_name

    # 2. Αλλαγή Avatar URL
    new_avatar_url = data.get('avatar_url')
    if new_avatar_url is not None:
        user.avatar_url = new_avatar_url if new_avatar_url.strip() else None

    # 3. Αλλαγή Κωδικού
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if old_password and new_password:
        if user.password_hash and check_password_hash(user.password_hash, old_password):
            user.password_hash = generate_password_hash(new_password)
        elif not user.password_hash:
            return jsonify({'error': 'Cannot change password on Google-linked account.'}), 400
        else:
            return jsonify({'error': 'Invalid old password.'}), 403
        
    try:
        db.session.commit()
        return jsonify({'message': 'Settings updated successfully.', 'new_display_name': user.display_name, 'new_avatar_url': user.avatar_url})
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user settings: {e}")
        return jsonify({'error': 'An unexpected error occurred during save.'}), 500

@app.route('/api/v1/admin/user/<int:user_id>/update', methods=['POST'])
@check_admin_or_owner
def admin_update_user_settings(user_id):
    """Ενημέρωση ρυθμίσεων άλλου χρήστη από Admin/Owner (Nickname, Password, Role)."""
    target_user = db.session.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not target_user:
        return jsonify({'error': 'Target user not found.'}), 404
        
    current_user = request.current_user
    data = request.get_json()

    # 1. Αλλαγή Display Name (Nickname)
    new_display_name = data.get('display_name')
    if new_display_name and target_user.display_name != new_display_name:
        target_user.display_name = new_display_name

    # 2. Αλλαγή Κωδικού (Admin/Owner)
    new_password = data.get('new_password')
    if new_password:
        target_user.password_hash = generate_password_hash(new_password)

    # 3. Αλλαγή Ρόλου
    new_role = data.get('role')
    if new_role and new_role in ['user', 'admin', 'owner']:
        # Επέτρεψε αλλαγή ρόλου. Κανόνας: Ο Owner μπορεί να αλλάξει τα πάντα, ο Admin όχι τον δικό του ρόλο
        if target_user.id != current_user.id or current_user.role == 'owner':
             target_user.role = new_role
             target_user.color = get_default_color_by_role(new_role)
        else:
             return jsonify({'error': 'Admins cannot change their own role.'}), 403

    try:
        db.session.commit()
        return jsonify({'message': f'User {target_user.display_name} updated successfully.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user via admin panel: {e}")
        return jsonify({'error': 'An unexpected error occurred.'}), 500


# ----------------------------------------------------
# 5. SocketIO Events (Σε Αναμονή για Επεξεργασία/Διαγραφή Μηνυμάτων)
# ----------------------------------------------------

@socketio.on('connect')
def handle_connect():
    user = request.current_user
    if user:
        print(f'User {user.display_name} connected.')
        join_room('global_chat')
    else:
        # Αποσύνδεση αν δεν είναι συνδεδεμένος (για ασφάλεια)
        return False

# ... (Υπάρχοντα events όπως message, disconnect) ...

# 🚨 ΝΕΟ: Επεξεργασία Μηνύματος (User)
@socketio.on('edit_message')
@login_required
def handle_edit_message(data):
    # Εδώ θα ελέγχεται αν ο χρήστης είναι ο συγγραφέας του μηνύματος.
    # Αν είναι, ενημερώνεται το μήνυμα στη βάση και εκπέμπεται το 'message_edited'
    pass

# 🚨 ΝΕΟ: Επεξεργασία/Διαγραφή Μηνύματος (Admin/Owner)
@socketio.on('admin_message_action')
@login_required
def handle_admin_message_action(data):
    user = request.current_user
    if user.role in ['admin', 'owner']:
        # Εδώ θα χειρίζεται η επεξεργασία/διαγραφή οποιουδήποτε μηνύματος
        pass
    else:
        return False # Απορρίπτουμε την ενέργεια


# ----------------------------------------------------
# 6. Εκκίνηση (Πρέπει να γίνει μετά τον ορισμό των μοντέλων)
# ----------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        # Δημιουργία πινάκων αν δεν υπάρχουν
        # Προσοχή: Επειδή χρησιμοποιείτε Migrate, βεβαιωθείτε ότι έχετε κάνει 'flask db upgrade'
        # db.create_all() 
        pass
    socketio.run(app, debug=True)