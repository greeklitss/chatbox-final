import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select
from datetime import datetime
from authlib.integrations.flask_client import OAuth, OAuthError as AuthlibOAuthError
from flask_socketio import SocketIO, emit, join_room, leave_room # Νέα εισαγωγή
import eventlet # Απαραίτητο για το gunicorn eventlet worker

# --------------------------------------------------------------------------
# 1. ΕΚΤΑΣΕΙΣ (Extensions)
# --------------------------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth() 
socketio = SocketIO() # Νέα αρχικοποίηση

# --- Λίστα ενεργών χρηστών (Global/Memory Store) ---
# Στην παραγωγή, αυτό θα ήταν Redis/DB. Εδώ το κρατάμε στη μνήμη του Master Process.
ONLINE_USERS = {} 

# --------------------------------------------------------------------------
# 2. ΒΟΗΘΗΤΙΚΗ ΣΥΝΑΡΤΗΣΗ (Helper Function)
# --------------------------------------------------------------------------
def get_default_color_by_role(role):
    colors = {
        'owner': '#FF0000', # Κόκκινο
        'admin': '#00CC00', # Πράσινο (Άλλαξε από Μπλε για να ξεχωρίζει από το user)
        'user': '#00bfff', # Light Blue
        'guest': '#808080' # Γκρι
    }
    return colors.get(role.lower(), '#000000') 

def get_online_users_list():
    """Επιστρέφει τη λίστα των online χρηστών για το frontend."""
    # Απαιτείται κλείδωμα αν είχαμε πολλούς workers, αλλά με eventlet worker=1 είναι εντάξει
    return list(ONLINE_USERS.values())


# --------------------------------------------------------------------------
# 3. ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ (Database Models)
# (Διατηρούνται ως έχουν)
# --------------------------------------------------------------------------
class User(UserMixin, db.Model):
    # ... (ο κώδικας User παραμένει ως έχει) ...
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True) 
    oauth_provider = db.Column(db.String(50), nullable=True) 
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(7), nullable=False)
    avatar_url = db.Column(db.String(255), nullable=True)

    messages = db.relationship('Message', backref='author', lazy='dynamic') 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    # ... (ο κώδικας Message παραμένει ως έχει) ...
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class Settings(db.Model):
    # ... (ο κώδικας Settings παραμένει ως έχει) ...
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)


# --------------------------------------------------------------------------
# 4. ΕΡΓΟΣΤΑΣΙΟ ΕΦΑΡΜΟΓΗΣ (Application Factory)
# --------------------------------------------------------------------------
def create_app(test_config=None):
    # --- 1. Αρχικοποίηση Flask App & Ρυθμίσεις ---
    app = Flask(__name__)
    # ... (οι ρυθμίσεις παραμένουν ως έχουν) ...
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_needs_to_be_long')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['REMEMBER_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # 🚨 Ρυθμίσεις SocketIO
    app.config['SOCKETIO_MESSAGE_QUEUE'] = os.environ.get('REDIS_URL') or None
    # Χρησιμοποιούμε eventlet/gevent αν υπάρχει, αλλιώς Flask default.
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet') 

    # --- 2. Αρχικοποίηση Extensions ---
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'
    login_manager.session_protection = 'strong'

    # ... (Ο κώδικας OAuth παραμένει ως έχει) ...
    oauth.init_app(app)
    oauth.register(
        'google',
        client_id=app.config.get('GOOGLE_CLIENT_ID'),
        client_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
        redirect_uri='/oauth/authorize' 
    )

    # Flask-Login: Συνάρτηση φόρτωσης χρήστη
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))


    # --------------------------------------------------------------------------
    # 5. ΡΟΥΤΙΝΕΣ FLASK (ROUTES)
    # --------------------------------------------------------------------------
    
    @app.route('/', endpoint='index_page')
    def index():
        return render_template('index.html')

    @app.route('/admin_panel')
    @login_required
    def admin_panel():
        if current_user.role not in ['admin', 'owner']:
            flash('Δεν έχετε δικαίωμα πρόσβασης.', 'error')
            return redirect(url_for('chat_page')) 
        return render_template('admin_panel.html')

    # ΡΟΥΤΙΝΑ CHAT (Η διορθωμένη ρουτίνα σας)
    @app.route('/chat', endpoint='chat_page') 
    @login_required
    def chat():
        """Προστατευμένη ρουτίνα για τη σελίδα συνομιλίας."""
        return render_template(
            'chat.html',
            role=current_user.role,
            color=current_user.color,
            # Περνάμε τις μεταβλητές για το JS
            user_id=current_user.id,
            display_name=current_user.display_name,
            password_hash_status=current_user.password_hash is not None 
        )

    # Ρουτίνα Σύνδεσης (Endpoint: login_page)
    @app.route('/login', methods=['GET', 'POST'], endpoint='login_page')
    def login():
        # ... (ο κώδικας login παραμένει ως έχει) ...
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))
        
        if request.method == 'POST':
            display_name = request.form.get('display_name')
            password = request.form.get('password')
            
            user = db.session.scalar(select(User).filter_by(display_name=display_name))
            
            if user is None or not user.check_password(password):
                flash('Λάθος όνομα χρήστη ή κωδικός.', 'error')
                return redirect(url_for('login_page'))
            
            login_user(user)
            return redirect(url_for('chat_page'))
            
        return render_template('login.html')

    @app.route('/logout', endpoint='logout_page')
    @login_required
    def logout():
        # ... (ο κώδικας logout παραμένει ως έχει) ...
        logout_user()
        flash('Έχετε αποσυνδεθεί επιτυχώς.', 'success')
        return redirect(url_for('login_page')) 
    
    # ... (Οι ρουτίνες OAuth και API παραμένουν ως έχουν) ...
    # --------------------------------------------------------------------------
    # 6. SOCKET.IO EVENTS
    # --------------------------------------------------------------------------

    @socketio.on('connect')
    def handle_connect():
        """Χειρίζεται τη σύνδεση ενός νέου χρήστη."""
        if current_user.is_authenticated:
            # Προσθήκη του χρήστη στη λίστα ONLINE_USERS
            ONLINE_USERS[request.sid] = {
                'id': current_user.id,
                'display_name': current_user.display_name,
                'role': current_user.role,
                'color': current_user.color
            }
            # Ενημέρωση όλων των χρηστών για τη νέα λίστα
            socketio.emit('users_update', get_online_users_list(), broadcast=True)
            print(f'User connected: {current_user.display_name}. Total: {len(ONLINE_USERS)}')
        else:
            # Για χρήστες που δεν έχουν συνδεθεί
            pass 

    @socketio.on('disconnect')
    def handle_disconnect():
        """Χειρίζεται την αποσύνδεση ενός χρήστη."""
        if request.sid in ONLINE_USERS:
            del ONLINE_USERS[request.sid]
            # Ενημέρωση όλων των χρηστών για την αλλαγή
            socketio.emit('users_update', get_online_users_list(), broadcast=True)
            print(f'User disconnected. Remaining: {len(ONLINE_USERS)}')

    @socketio.on('message')
    def handle_message(data):
        """Χειρίζεται την αποστολή ενός νέου μηνύματος."""
        if not current_user.is_authenticated:
            return # Αγνοούμε μηνύματα από μη συνδεδεμένους χρήστες

        # 1. Αποθήκευση στη βάση δεδομένων
        new_message = Message(
            user_id=current_user.id,
            content=data['content']
        )
        db.session.add(new_message)
        db.session.commit()
        
        # 2. Εκπομπή σε όλους τους συνδεδεμένους χρήστες
        emit('message', {
            'display_name': current_user.display_name,
            'content': data['content'],
            'timestamp': datetime.utcnow().isoformat(),
            'role': current_user.role,
            'color': current_user.color
        }, broadcast=True)


    # --- 7. Επιστροφή του αντικειμένου app ---
    return app

# # Εάν θέλετε να τρέχετε τοπικά, αφαιρέστε τα σχόλια από τις παρακάτω γραμμές:
# if __name__ == '__main__':
#     app = create_app()
#     # Χρησιμοποιούμε το socketio.run() αντί για app.run()
#     socketio.run(app, debug=True)