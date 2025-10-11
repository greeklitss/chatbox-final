import os 
import json
import uuid 
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from datetime import datetime

# --- ΝΕΕΣ ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash # Για κωδικούς

# --- Ρυθμίσεις Εφαρμογής & Session ---
app = Flask(__name__, static_folder='.') 
app.config['SECRET_KEY'] = 'a_very_secure_secret_key_for_sessions' 
app.config['SESSION_TYPE'] = 'filesystem' 
app.config['SESSION_PERMANENT'] = True

# --- FLASK-SQLALCHEMY & DATABASE CONFIG ---
# Για postgresql/dbeer θα έπρεπε να είναι: 
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@host:port/dbname'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat_users.db' # Χρησιμοποιούμε SQLite για ευκολία
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- GOOGLE OAUTH CONFIG (Authlib) ---
app.config['GOOGLE_CLIENT_ID'] = os.environ.get("GOOGLE_CLIENT_ID", "YOUR_GOOGLE_CLIENT_ID_HERE")
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get("GOOGLE_CLIENT_SECRET", "YOUR_GOOGLE_CLIENT_SECRET_HERE")
app.config['GOOGLE_CONF_URL'] = 'https://accounts.google.com/.well-known/openid-configuration'

oauth = OAuth(app)
oauth.register(
    name='google',
    server_metadata_url=app.config['GOOGLE_CONF_URL'],
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    client_kwargs={'scope': 'openid email profile'},
)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Ρύθμιση φακέλου upload
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(os.path.join(os.getcwd(), UPLOAD_FOLDER)):
    os.makedirs(os.path.join(os.getcwd(), UPLOAD_FOLDER))

# --- ΚΑΘΟΛΙΚΕΣ ΔΟΜΕΣ ΔΕΔΟΜΕΝΩΝ ---
connected_users = {} 
app_settings = {'allow_gif_searches': 'true', 'default_font_color': '#F0F0F0'}

# --- DATABASE MODEL ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), default='user')
    password_hash = db.Column(db.String(128), nullable=True) # Για τον πρώτο Admin
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email} ({self.role})>'

# --- ROUTES & VIEWS ---

@app.before_request
def check_for_admin_signup():
    """Ελέγχει αν πρέπει να γίνει redirect στη σελίδα εγγραφής του πρώτου admin"""
    with app.app_context():
        # Ελέγχουμε αν υπάρχει ήδη Admin
        admin_exists = db.session.query(User).filter_by(role='admin').first()
        
    if not admin_exists and request.path not in ['/signup', '/api/signup']:
        # Αν δεν υπάρχει κανένας Admin, αναγκάζουμε εγγραφή
        return redirect(url_for('signup_page'))

@app.route('/signup')
def signup_page():
    """Σελίδα εγγραφής του πρώτου Admin"""
    with app.app_context():
        admin_exists = db.session.query(User).filter_by(role='admin').first()
        
    if admin_exists:
        # Αν υπάρχει ήδη Admin, στέλνουμε στο login
        return redirect(url_for('login_page'))
        
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Admin Signup</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style> /* ... (Styles from previous turn) ... */
        body { font-family: 'Roboto', sans-serif; background-color: #121212; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .box { background: #1f1f1f; padding: 30px; border-radius: 8px; box-shadow: 0 0 20px #FF0066; width: 300px; }
        h2 { color: #FF0066; text-align: center; }
        input[type="text"], input[type="password"], input[type="email"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #39FF14; background: #333; color: white; border-radius: 4px; box-sizing: border-box; }
        button { background: #39FF14; color: black; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-weight: bold; transition: background 0.3s; margin-top: 10px; }
        button:hover { background: #FF0066; color: white; }
    </style>
    </head>
    <body>
        <div class="box">
            <h2><i class="fas fa-user-shield"></i> Initial Admin Registration</h2>
            <form action="/api/signup" method="POST">
                <label for="email">Email (Username):</label>
                <input type="email" id="email" name="email" required>
                <label for="display_name">Display Name:</label>
                <input type="text" id="display_name" name="display_name" required>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                <button type="submit">Register Admin</button>
            </form>
        </div>
        <p style="position: fixed; bottom: 10px; color: #aaa;">This page is shown only when no Admin exists.</p>
    </body>
    </html>
    """
    return html_content

@app.route('/api/signup', methods=['POST'])
def handle_signup():
    email = request.form.get('email')
    password = request.form.get('password')
    display_name = request.form.get('display_name')
    
    if not email or not password or not display_name:
        return jsonify({'error': 'Missing fields'}), 400

    with app.app_context():
        admin_exists = db.session.query(User).filter_by(role='admin').first()
        if admin_exists:
             return jsonify({'error': 'Admin already registered. Please use Google Login.'}), 403

        # Δημιουργία του πρώτου Admin
        new_admin = User(email=email, display_name=display_name, role='admin')
        new_admin.set_password(password)
        
        db.session.add(new_admin)
        db.session.commit()

        # Αυτόματη σύνδεση του πρώτου Admin
        session['logged_in'] = True
        session['display_name'] = display_name
        session['role'] = 'admin'
        
        return redirect(url_for('index'))


@app.route('/login')
def login_page():
    """Σελίδα σύνδεσης"""
    if session.get('logged_in'):
        return redirect(url_for('index'))
        
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style> /* ... (Styles from previous turn) ... */
        body { font-family: 'Roboto', sans-serif; background-color: #121212; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #1f1f1f; padding: 30px; border-radius: 8px; box-shadow: 0 0 20px #FF0066; width: 300px; text-align: center; }
        h2 { color: #39FF14; }
        .google-btn {
            background: #4285F4; 
            color: white; 
            padding: 10px 15px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            width: 100%; 
            font-weight: bold; 
            transition: background 0.3s; 
            margin-top: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
        }
        .google-btn:hover { background: #3367d6; }
        .google-btn i { margin-right: 10px; font-size: 1.2em; }
    </style>
    </head>
    <body>
        <div class="login-box">
            <h2><i class="fas fa-music"></i> Welcome Back!</h2>
            <a href="/google_login" class="google-btn">
                <i class="fab fa-google"></i> Sign in with Google
            </a>
            <p style="margin-top: 20px; color: #aaa;">Admin accounts only via registered Google emails.</p>
        </div>
    </body>
    </html>
    """
    return html_content

@app.route('/google_login')
def google_login():
    """
    Ξεκινάει τη ροή Google OAuth.
    """
    # Το Authlib ξεκινάει τη ροή και ανακατευθύνει τον χρήστη στην Google
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def authorize_google():
    """
    Callback από την Google. Επεξεργάζεται την απάντηση.
    """
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    
    google_id = user_info['sub']
    email = user_info['email']
    display_name = user_info['name'] or email

    with app.app_context():
        # 1. Βρες τον χρήστη στη βάση (για Admin ή ήδη συνδεδεμένο Guest)
        user = db.session.query(User).filter_by(google_id=google_id).first()
        
        if not user:
            # 2. Αν δεν υπάρχει, έλεγξε αν το email αντιστοιχεί σε εγγεγραμμένο Admin
            user = db.session.query(User).filter_by(email=email, role='admin').first()
            if user:
                # 3. Αν είναι Admin, ενημέρωσε το google_id για μελλοντικές συνδέσεις
                user.google_id = google_id
                db.session.commit()
            else:
                # 4. Αν δεν είναι Admin, είναι ένας νέος απλός Guest
                user = User(google_id=google_id, email=email, display_name=display_name, role='user')
                db.session.add(user)
                db.session.commit()

        # Καταγραφή του session
        session['logged_in'] = True
        session['display_name'] = user.display_name
        session['role'] = user.role
        
        return redirect(url_for('index'))

@app.route('/check_login', methods=['GET'])
def check_login():
    """Ελέγχει αν ο χρήστης είναι συνδεδεμένος μέσω Session"""
    if session.get('logged_in'):
        return jsonify({
            'display_name': session['display_name'],
            'role': session['role']
        }), 200
    else:
        return jsonify({'error': 'Not logged in'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """Διαγράφει το session και αποσυνδέει τον χρήστη"""
    if 'logged_in' in session:
        session.clear() # Καθαρίζουμε όλο το session
        
    return jsonify({'message': 'Logged out', 'redirect': url_for('login_page')}), 200

@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify(app_settings), 200

@app.route('/')
def index():
    """Σερβίρει το chat.html, αλλά πρώτα ελέγχει τη σύνδεση"""
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
        
    return send_from_directory(app.static_folder, 'chat.html')

# --- FILE UPLOAD (No Change) ---
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file:
        filename = secure_filename(file.filename)
        timestamp_prefix = datetime.now().strftime('%Y%m%d%H%M%S_')
        unique_filename = timestamp_prefix + filename
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(save_path)
        
        file_url = url_for('static', filename=f'uploads/{unique_filename}', _external=True)
        
        return jsonify({'url': file_url}), 200
        
    return jsonify({'error': 'Upload failed'}), 500


# --- WEBSOCKET EVENT HANDLERS (No Change in logic, uses passed query args) ---
@socketio.on('connect')
def handle_connect():
    sid = request.sid
    
    display_name = request.args.get('display_name', 'System')
    user_role = request.args.get('role', 'user')

    connected_users[sid] = {'display_name': display_name, 'role': user_role}
    print(f'Client connected: {display_name} ({sid})')
    
    if user_role != 'System': 
        emit('userStatus', {'displayName': display_name, 'status': 'connected'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in connected_users:
        user = connected_users.pop(sid)
        print(f'Client disconnected: {user["display_name"]} ({sid})')
        emit('userStatus', {'displayName': user['display_name'], 'status': 'disconnected'}, broadcast=True)

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    user = connected_users.get(sid, {'display_name': 'Unknown', 'role': 'user'})

    try:
        message_format = json.loads(data)
        text_or_url = message_format.get('text') or message_format.get('url')

        message_data = {
            'messageId': str(datetime.now().timestamp()), 
            'displayName': user['display_name'],
            'role': user['role'],
            'message': text_or_url,
            'timestamp': datetime.now().isoformat(),
            'isBold': message_format.get('isBold', False),
            'isItalic': message_format.get('isItalic', False),
            'color': message_format.get('color', app_settings['default_font_color'])
        }

        print(f"[{user['role']}] {user['display_name']}: {text_or_url}")
        emit('message', message_data, broadcast=True)

    except json.JSONDecodeError:
        print(f"Received invalid JSON message from {user['display_name']}: {data}")

# --- ΕΚΚΙΝΗΣΗ ΤΟΥ SERVER ---
if __name__ == '__main__':
    from flask_session import Session
    Session(app) 

    # Δημιουργία των πινάκων της βάσης δεδομένων
    with app.app_context():
        db.create_all()
        print("Database tables created.")
        
    socketio.run(app, debug=True, port=os.environ.get("PORT", 5000), host='0.0.0.0')