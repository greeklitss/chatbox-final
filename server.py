import requests
import os
import json
import uuid
import time
import random
import secrets
import string

# Εισαγωγές Flask και SocketIO
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect, session, render_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import jsonify, url_for, request 

# --- ΒΙΒΛΙΟΘΗΚΕΣ ΓΙΑ DB & AUTH ---
from werkzeug.middleware.proxy_fix import ProxyFix # ΚΡΙΣΙΜΟ ΓΙΑ RENDER/PROXY
from sqlalchemy import select, desc, func 
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session
from sqlalchemy.sql import text
from sqlalchemy.exc import IntegrityError, ProgrammingError, OperationalError
from authlib.integrations.base_client.errors import MismatchingStateError, OAuthError
from sqlalchemy.orm import validates 


# --- Global Real-time State (Safe for -w 1 eventlet worker) ---
ONLINE_SIDS = {} 
GLOBAL_ROOM = 'main'

# --- ΧΑΡΤΟΓΡΑΦΗΣΗ ΡΟΛΩΝ / ΧΡΩΜΑΤΩΝ (ΚΡΙΣΙΜΟ ΓΙΑ ΤΟ LOGIN) ---
USER_ROLE_COLORS = {
    # Χρησιμοποιούμε τα χρώματα από το style.css
    'owner': '#ff3399',      
    'admin': '#00e6e6',      
    'user': '#ffffff',       # Default χρώμα για απλό χρήστη
}

def get_default_color_by_role(role):
    """Επιστρέφει το hex color με βάση τον ρόλο."""
    # Επιστρέφει το χρώμα του ρόλου, αλλιώς επιστρέφει το default χρώμα χρήστη
    return USER_ROLE_COLORS.get(role, USER_ROLE_COLORS['user'])


# --- Αρχικοποίηση Εξαρτήσεων ---
db = SQLAlchemy()
oauth = OAuth()
socketio = SocketIO()

# --- ΥΠΟΘΕΤΙΚΑ ΜΟΝΤΕΛΑ DB ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    display_name = db.Column(db.String(120), nullable=False)
    # 🚨 ΚΡΙΣΙΜΟ: Αυτά τα πεδία πρέπει να είναι NOT NULL αν τα ορίζουμε ρητά
    role = db.Column(db.String(50), default='user', nullable=False) 
    color = db.Column(db.String(7), default='#ffffff', nullable=False)
    # ... άλλα πεδία (π.χ. avatar)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # ... άλλα πεδία

# --- ΥΠΟΘΕΤΙΚΕΣ ΒΟΗΘΗΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ ---
def get_global_settings():
    # Επιστρέφει τις ρυθμίσεις για το chat.html
    return {"feature_bold": "True", "feature_italic": "True"}

def get_emoticons():
    # Επιστρέφει τα emoticons για το chat.html
    return {":smile:": "/static/emoticons/smile.gif"}


# --- DECORATOR ΠΡΟΣΤΑΣΙΑΣ ΣΕΛΙΔΩΝ ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Ανακατεύθυνση στη σελίδα login αν δεν είναι συνδεδεμένος
            return redirect(url_for('login')) 
        return f(*args, **kwargs)
    return decorated_function


# --- APP FACTORY ---
def create_app():
    # 🚨 ΚΡΙΣΙΜΟ: Προσθήκη ProxyFix για σωστό χειρισμό HTTPS/Header από τον Render
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_prefix=1)
    
    # --- Ρυθμίσεις App ---
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key-for-dev')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Ρυθμίσεις Flask Session
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_PERMANENT'] = True
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_COOKIE_NAME'] = 'flask_session_id'
    
    # 🚨 ΚΡΙΣΙΜΟ: Ρυθμίσεις Session για Render/HTTPS (Αποφυγή CSRF/MismatchingStateError)
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

    # Ρυθμίσεις Google OAuth
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # --- Αρχικοποίηση Εξαρτήσεων ---
    db.init_app(app)
    Session(app)
    socketio.init_app(app, manage_session=False, async_mode='eventlet', cors_allowed_origins="*")

    # Αρχικοποίηση OAuth
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://oauth2.googleapis.com/token',
        access_token_params=None,
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        client_kwargs={'scope': 'openid email profile'},
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
    )
    
    # --- ΔΗΜΙΟΥΡΓΙΑ DB (Χρειάζεται μόνο την πρώτη φορά) ---
    with app.app_context():
        try:
            db.create_all()
            print("Database initialized or already exists.")
        except (ProgrammingError, OperationalError) as e:
            print(f"Database creation failed (may not be necessary if already exists): {e}")

    # =========================================================================
    # 🚨 ΡΟΥΤΕΣ ΕΦΑΡΜΟΓΗΣ (ΔΙΟΡΘΩΜΕΝΕΣ ΡΟΕΣ)
    # =========================================================================

    # 1. ROOT (Αρχική Σελίδα)
    @app.route('/')
    def index():
        # Αν ο χρήστης είναι ήδη συνδεδεμένος, τον στέλνουμε κατευθείαν στο chat (/chat)
        if session.get('user_id'):
            return redirect(url_for('chat_main')) 
        
        # Αν δεν είναι συνδεδεμένος, εμφανίζουμε την προσωρινή σελίδα splash (index.html)
        return render_template('index.html')


    # 2. ΣΕΛΙΔΑ CHAT (Προστατευμένη)
    @app.route('/chat')
    @login_required # <-- Προστατεύουμε τη σελίδα chat
    def chat_main():
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)
        
        # Φορτώνουμε τις ρυθμίσεις και τα emoticons
        settings = get_global_settings() 
        emoticons = get_emoticons()       
        
        return render_template('chat.html', user=user, settings=settings, emoticons=emoticons)


    # 3. ΣΕΛΙΔΑ LOGIN
    @app.route('/login')
    def login():
        if session.get('user_id'):
            return redirect(url_for('chat_main'))
        return render_template('login.html')

    
    # 4. GOOGLE LOGIN (Redirect to Google)
    @app.route('/login/google')
    def login_google(): # 🚨 ΣΩΣΤΟ ENDPOINT NAME: 'login_google'
        redirect_uri = url_for('authorize', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    
    # 5. GOOGLE OAUTH CALLBACK (ΠΛΗΡΩΣ ΔΙΟΡΘΩΜΕΝΟ)
    @app.route('/authorize')
    def authorize():
        try:
            token = oauth.google.authorize_access_token()
            user_info = token.get('userinfo')
            
            # Εύρεση ή δημιουργία χρήστη
            user = db.session.execute(select(User).where(User.google_id == user_info['id'])).scalar_one_or_none()
            
            if user is None:
                # 1. Ορίζουμε τον default ρόλο
                default_role = 'user'
                
                # 2. Βρίσκουμε το χρώμα με βάση τον default ρόλο
                default_color = get_default_color_by_role(default_role)
                
                # 3. Δημιουργία νέου χρήστη με ΟΛΑ τα υποχρεωτικά πεδία
                user = User(
                    google_id=user_info['id'], 
                    display_name=user_info.get('name', 'NewUser'),
                    role=default_role,     
                    color=default_color    
                    # 🚨 ΠΡΟΣΘΕΣΤΕ ΕΔΩ ΟΠΟΙΑ ΑΛΛΑ NOT NULL πεδία λείπουν από το μοντέλο User
                )
                db.session.add(user)
                
                # 4. ΧΕΙΡΙΣΜΟΣ ΣΦΑΛΜΑΤΟΣ DB ΑΜΕΣΩΣ ΜΕΤΑ ΤΟ COMMIT
                try:
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    # Εκτύπωση του σφάλματος για debugging στον Render
                    print(f"Database Integrity/Commit Failed during user creation: {e}") 
                    return redirect(url_for('login')) 

            # Δημιουργία Session (Εκτελείται μόνο αν το commit ήταν επιτυχημένο)
            session['user_id'] = user.id
            session['display_name'] = user.display_name
            
            # ΤΕΛΙΚΗ ΑΝΑΚΑΤΕΥΘΥΝΣΗ: Προς το προστατευμένο chat (/chat)
            return redirect(url_for('chat_main'))
            
        except MismatchingStateError:
            print("OAuth State Mismatch Error - Check session settings.")
            return redirect(url_for('login'))
        except OAuthError as e:
            print(f"OAuth Error: {e}")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"An unexpected error occurred during authorization: {e}")
            return redirect(url_for('login'))


    # 6. LOGOUT
    @app.route('/logout')
    @login_required
    def logout():
        # ... (Λογική αποσύνδεσης χρήστη) ...
        if 'user_id' in session:
            user_id_to_remove = session['user_id']
            sids_to_disconnect = [sid for sid, uid in ONLINE_SIDS.items() if uid == user_id_to_remove]
            for sid in sids_to_disconnect:
                socketio.emit('disconnect_user', {'user_id': user_id_to_remove}, room=sid) 
                
        session.pop('user_id', None)
        session.clear()
        
        # Ανακατεύθυνση στην αρχική σελίδα (η οποία θα δείξει το index.html)
        return redirect(url_for('index'))


    # 7. ADMIN PANEL
    @app.route('/admin_panel')
    @login_required
    def admin_panel():
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)
        
        # Έλεγχος ρόλου 
        if user and user.role in ['admin', 'owner']:
            return render_template('admin_panel.html', user=user)
        else:
            return redirect(url_for('chat_main')) 


    # 8. CHECK LOGIN (Για AJAX κλήσεις από client)
    @app.route('/check_login')
    def check_login():
        if 'user_id' in session:
            user = db.session.get(User, session['user_id'])
            if user:
                return jsonify({
                    'id': user.id,
                    'display_name': user.display_name,
                    'role': user.role,
                    'color': user.color
                }), 200
        return jsonify({'error': 'Not logged in'}), 401


    # =========================================================================
    # 🚨 SOCKETIO LOGIC (Πρέπει να περιληφθεί εδώ)
    # =========================================================================
    
    # ... (Υποθέτουμε ότι η λογική SocketIO βρίσκεται εδώ) ...
    
    
    return app


# --- Τερματικό Σημείο: Εκτέλεση του Server ---

if __name__ == '__main__':
    app = create_app()
    # ... (Τοπική εκτέλεση με eventlet)
    try:
        import eventlet
        eventlet.monkey_patch()
        port = int(os.environ.get('PORT', 10000))
        socketio.run(app, host='0.0.0.0', port=port, debug=True)
    except ImportError:
        print("Eventlet not found. Running with default Flask server. NOT suitable for production.")
        app.run(host='0.0.0.0', port=10000, debug=True)