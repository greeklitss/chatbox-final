# server.py

import os
import json
from datetime import datetime
from urllib.parse import urlparse
import random # Χρησιμοποιείται για τυχαία χρώματα αν χρειαστεί

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select, or_

# Βιβλιοθήκες για Google OAuth
from authlib.integrations.flask_client import OAuth as AuthlibOAuth
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
    return colors.get(role, '#FFFFFF')

# --- 3. User Model ---

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(128), unique=True, nullable=True)
    
    # Τοπική σύνδεση (αν χρησιμοποιείται)
    email = db.Column(db.String(120), unique=True, nullable=True)
    username = db.Column(db.String(64), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False) # Απαραίτητο για το login_required
    
    display_name = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(20), default='user') # 'user', 'admin', 'owner'
    color = db.Column(db.String(10), nullable=False) # Χρώμα για το chat
    avatar_url = db.Column(db.String(256), nullable=True)

    def __repr__(self):
        return f'<User {self.display_name}>'

# --- 4. Login Manager Configuration ---

@login_manager.user_loader
def load_user(user_id):
    """Καθορίζει πώς ο LoginManager φορτώνει έναν χρήστη από την ID του."""
    return db.session.get(User, int(user_id))

# --- 5. Application Factory ---

def create_app():
    app = Flask(__name__)
    
    # --- Ρυθμίσεις (Configuration) ---
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_needs_to_be_long')
    # 🚨 ΔΙΟΡΘΩΣΗ: Διαβάζει DATABASE_URL, όπως περιμένει ο κώδικάς σας
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Ρυθμίσεις Cookies για HTTPS deployment (Render)
    app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['REMEMBER_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    
    # Ρυθμίσεις Google OAuth
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # --- Αρχικοποίηση Επεκτάσεων ---
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login' # Route για ανακατεύθυνση αν δεν είναι συνδεδεμένος
    
    # Αρχικοποίηση OAuth (Authlib)
    oauth.init_app(app)
    oauth.register(
        'google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )

    # --- Βασικά Routes Εφαρμογής ---

    @app.route('/')
    def index():
        """Αρχική σελίδα (Landing Page)."""
        if current_user.is_authenticated:
             # Αν είναι συνδεδεμένος, τον στέλνουμε στο chat
             return redirect(url_for('chat'))
        return render_template('index.html')

    @app.route('/login', methods=['GET']) # Απλό GET για εμφάνιση φόρμας
    def login():
        """Σελίδα σύνδεσης και εγγραφής."""
        if current_user.is_authenticated:
            # ✅ ΔΙΟΡΘΩΣΗ: Ανακατεύθυνση στο chat
            return redirect(url_for('chat'))
            
        return render_template('login.html')

    @app.route('/chat')
    @login_required # 🔒 Απαιτείται σύνδεση για το chat
    def chat():
        """Η κεντρική σελίδα Chat."""
        return render_template('chat.html')

    @app.route('/logout')
    @login_required
    def logout():
        """Αποσύνδεση χρήστη."""
        logout_user()
        flash('Αποσυνδεθήκατε με επιτυχία.', 'info')
        return redirect(url_for('index'))

    @app.route('/admin_panel')
    @login_required
    def admin_panel():
        """Πίνακας διαχείρισης (για admin/owner)."""
        # 🚨 Server-side προστασία: Ανακατεύθυνση αν ο ρόλος δεν είναι εξουσιοδοτημένος
        if current_user.role not in ['owner', 'admin']:
            flash('Δεν έχετε δικαίωμα πρόσβασης στον πίνακα διαχείρισης.', 'error')
            # Ανακατεύθυνση στο chat αν δεν έχει δικαίωμα, όπως ζητήθηκε
            return redirect(url_for('chat')) 
        
        return render_template('admin_panel.html')

    # --- Google OAuth Routes ---

    @app.route('/oauth/login')
    def oauth_login():
        """Εκκίνηση της διαδικασίας Google OAuth."""
        redirect_uri = url_for('authorize', _external=True)
        return oauth.google.authorize_redirect(redirect_uri)

    @app.route('/oauth/authorize')
    def authorize():
        """Google OAuth callback route."""
    
        redirect_uri = url_for('authorize', _external=True) 

        try:
            token = oauth.google.authorize_access_token(redirect_uri=redirect_uri)        
        except AuthlibOAuthError as e:
            flash(f'Authentication failed: {e.description}', 'error') 
            return redirect(url_for('login'))

        # Λήψη πληροφοριών χρήστη
        userinfo = oauth.google.parse_id_token(token)
        user_google_id = userinfo.get('sub')
        
        # Αναζήτηση χρήστη στη βάση
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
                # Ορίζουμε έναν τυχαίο password_hash (απαραίτητο για το UserMixin)
                password_hash=generate_password_hash(str(os.urandom(24))),
                color=get_default_color_by_role('user'),
                email=userinfo.get('email') # Προσθήκη email
            )
            db.session.add(new_user)
            db.session.commit()
            user_to_login = new_user
        else:
            # Ενημέρωση πληροφοριών αν χρειαστεί (π.χ. avatar, όνομα)
            user.display_name = userinfo.get('name', user.display_name)
            user.avatar_url = userinfo.get('picture', user.avatar_url)
            db.session.commit()
            user_to_login = user

        login_user(user_to_login)
        flash(f"Επιτυχής σύνδεση ως {user_to_login.display_name} (Google).", 'success')
        
        # ✅ ΤΕΛΙΚΗ ΔΙΟΡΘΩΣΗ: Ανακατεύθυνση ΟΛΩΝ στο chat
        return redirect(url_for('chat'))
    
    # --- API Routes ---

    @app.route('/api/v1/user', methods=['GET'])
    @login_required
    def api_get_current_user():
        """
        Επιστρέφει τα δεδομένα του συνδεδεμένου χρήστη.
        Χρησιμοποιείται από το admin_panel.html.
        """
        # Αυτό το route μπορεί να χρησιμοποιηθεί και για το chat.html
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
             return jsonify({'error': 'Unauthorized', 'message': 'You must be logged in to access this resource.'}), 401
        # Διαφορετικά, ανακατευθύνουμε στη σελίδα σύνδεσης
        flash('Πρέπει να συνδεθείτε για να συνεχίσετε.', 'warning')
        return redirect(url_for('login'))
        
    @app.errorhandler(404)
    def not_found(error):
        # Εδώ μπορείτε να εμφανίσετε μια προσαρμοσμένη σελίδα 404
        return render_template('404.html'), 404

    return app

# --- 6. Main Run Block (προαιρετικό, για τοπική εκτέλεση) ---
if __name__ == '__main__':
    # Αυτό το block τρέχει μόνο αν εκτελέσετε 'python server.py' τοπικά
    # Στο deployment (π.χ. Gunicorn/Render), εκτελείται το 'server:create_app()'
    app = create_app()
    app.run(debug=True)