# server.py

import os
import json
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select, or_

# Βιβλιοθήκες για Google OAuth
from authlib.integrations.flask_client import OAuth as AuthlibOAuth
# ΔΙΟΡΘΩΣΗ: Σωστή εισαγωγή για το OAuthError
from authlib.integrations.base_client.errors import OAuthError as AuthlibOAuthError


# --- 1. Αρχικοποίηση Εξωτερικών Αντικειμένων ---
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = AuthlibOAuth()

# --- 2. Βοηθητικές Συναρτήσεις ---

def get_default_color_by_role(role):
    """Επιστρέφει ένα default χρώμα με βάση τον ρόλο του χρήστη."""
    colors = {
        'owner': '#FF3399',  # Φούξια
        'admin': '#00BFFF',  # Deep Sky Blue
        'user': '#3CB371'   # Medium Sea Green
    }
    return colors.get(role, '#808080') # Γκρι αν δεν βρεθεί

# --- 3. Μοντέλα Βάσης Δεδομένων (UserMixin για Flask-Login) ---

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    color = db.Column(db.String(7), default='#808080', nullable=False)
    avatar_url = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Χρησιμοποιεί το password_hash για να ελέγξει τον κωδικό.
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Settings(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

# --- 4. Login Manager Loader ---

@login_manager.user_loader
def load_user(user_id):
    """Φορτώνει τον χρήστη από το ID του για το Flask-Login."""
    return db.session.execute(select(User).where(User.id == int(user_id))).scalar_one_or_none()

# --- 5. Εργοστάσιο Εφαρμογής (Application Factory) ---

def create_app():
    app = Flask(__name__)
    
    # --- Ρυθμίσεις (Configuration) ---
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_needs_to_be_long')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['REMEMBER_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # --- Αρχικοποίηση Επεκτάσεων ---
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    
    # Ρυθμίσεις Flask-Login
    login_manager.login_view = 'login'
    login_manager.session_protection = 'strong'

    # Ρυθμίσεις Google OAuth (Authlib)
    oauth.init_app(app)
    oauth.register(
        'google',
        client_id=app.config.get('GOOGLE_CLIENT_ID'),
        client_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
        # ΔΙΟΡΘΩΣΗ: Χρησιμοποιούμε τη στατική διαδρομή /oauth/authorize για να αποφύγουμε το RuntimeError κατά την εκκίνηση
        redirect_uri='/oauth/authorize' 
    )

    # --- Routes της Εφαρμογής ---

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/chat')
    @login_required # Βεβαιώνει ότι μόνο συνδεδεμένοι χρήστες έχουν πρόσβαση
    def chat():
        """Η κεντρική σελίδα Chat."""
        return render_template('chat.html')

    @app.route('/admin_panel')
    @login_required
    def admin_panel():
        """Προστατευμένη ρουτίνα για το admin panel."""
        if current_user.role not in ['admin', 'owner']:
            flash('Δεν έχετε δικαίωμα πρόσβασης.', 'error')
            return redirect(url_for('chat'))
        return render_template('admin_panel.html')
    
    # --- Routes Σύνδεσης/Αποσύνδεσης ---

    # Ρουτίνα GET: Απλώς εμφανίζει το login template
    @app.route('/login', methods=['GET'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('chat.html'))
        return render_template('index.html')

    # Ρουτίνα POST API: Χειρίζεται τη σύνδεση username/password (AJAX)
    @app.route('/api/v1/login', methods=['POST'])
    def api_login():
        """Διαχειρίζεται τη σύνδεση μέσω AJAX/API και επιστρέφει JSON."""
        if current_user.is_authenticated:
            return jsonify({'success': True, 'redirect': url_for('index')}), 200

        data = request.get_json()
        if not data:
            # 400 Bad Request
            return jsonify({'error': 'Δεν παρασχέθηκαν δεδομένα.'}), 400
            
        display_name = data.get('display_name')
        password = data.get('password')
        
        user = db.session.execute(select(User).where(User.display_name == display_name)).scalar_one_or_none()
        
        if user and user.check_password(password):
            login_user(user)
            redirect_url = url_for('chat')            
            # Επιστρέφουμε JSON με το URL ανακατεύθυνσης
            return jsonify({'success': True, 'redirect': redirect_url}), 200
        
        # 401 Unauthorized
        return jsonify({'error': 'Λάθος Όνομα Χρήστη ή Κωδικός.'}), 401


    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Έχετε αποσυνδεθεί επιτυχώς.', 'success')
        return redirect(url_for('index.html'))

    # --- Routes Google OAuth ---

    @app.route('/oauth/login', methods=['GET'])
    def oauth_login():
        """Ανακατευθύνει τον χρήστη στη σελίδα σύνδεσης της Google."""
        # Χρησιμοποιούμε url_for('authorize', _external=True) εδώ, καθώς εκτελείται εντός του request context
        return oauth.google.authorize_redirect(
            redirect_uri=url_for('authorize', _external=True)
        )

    @app.route('/oauth/authorize')
    def authorize():
        """Google OAuth callback route."""
        try:
            token = oauth.google.authorize_access_token()
        except AuthlibOAuthError as e:
            flash(f'Authentication failed: {e.description}', 'error')
            return redirect(url_for('chat.html')) 

        userinfo = oauth.google.parse_id_token(token, nonce=session.get('nonce'))
        user_google_id = userinfo.get('sub')
        
        user = db.session.execute(
            select(User).where(User.google_id == user_google_id)
        ).scalar_one_or_none()

        if not user:
            # Δημιουργία ΝΕΟΥ Χρήστη
            new_user = User(
                google_id=user_google_id,
                display_name=userinfo.get('name', 'New User'),
                avatar_url=userinfo.get('picture'),
                role='user',
                # Ορίζουμε έναν τυχαίο password_hash
                password_hash=generate_password_hash(str(os.urandom(24))),
                color=get_default_color_by_role('user')
            )
            db.session.add(new_user)
            db.session.commit()
            user_to_login = new_user
        else:
            user_to_login = user

        login_user(user_to_login)
        flash(f"Επιτυχής σύνδεση ως {user_to_login.display_name} (Google).", 'success')
        
        return redirect(url_for('chat.html'))
    
    # --- API Routes ---

    @app.route('/api/v1/user', methods=['GET'])
    @login_required
    def api_get_current_user():
        """
        Επιστρέφει τα δεδομένα του συνδεδεμένου χρήστη.
        Χρησιμοποιείται από το admin_panel.html.
        """
        return jsonify({
            'id': current_user.id,
            'display_name': current_user.display_name,
            'role': current_user.role,
            'color': current_user.color,
            'avatar_url': current_user.avatar_url,
            'google_id': current_user.google_id
        })

    # --- Error Handlers ---

    @app.errorhandler(401)
    def unauthorized(error):
        # Αν η αίτηση είναι AJAX/API, επιστρέφουμε JSON
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401
            
        flash("Πρέπει να συνδεθείτε για να δείτε αυτή τη σελίδα.", 'warning')
        return redirect(url_for('login.html'))

    return app

# if __name__ == '__main__':
#     app = create_app()
#     # app.run(debug=True)