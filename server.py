import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select
from datetime import datetime
from authlib.integrations.flask_client import OAuth, OAuthError as AuthlibOAuthError # Προστέθηκε

# --------------------------------------------------------------------------
# 1. ΕΚΤΑΣΕΙΣ (Extensions)
# --------------------------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth() # Ορισμός του OAuth extension

# --------------------------------------------------------------------------
# 2. ΒΟΗΘΗΤΙΚΗ ΣΥΝΑΡΤΗΣΗ (Helper Function)
# --------------------------------------------------------------------------
def get_default_color_by_role(role):
    colors = {
        'owner': '#FF0000', # Κόκκινο
        'admin': '#0000FF', # Μπλε
        'user': '#008000', # Πράσινο
        'guest': '#808080' # Γκρι
    }
    return colors.get(role.lower(), '#000000') # Προεπιλογή: Μαύρο

# --------------------------------------------------------------------------
# 3. ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ (Database Models)
# --------------------------------------------------------------------------

class User(UserMixin, db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)

# --------------------------------------------------------------------------
# 4. ΕΡΓΟΣΤΑΣΙΟ ΕΦΑΡΜΟΓΗΣ (Application Factory)
# --------------------------------------------------------------------------
def create_app(test_config=None):
    # --- 1. Αρχικοποίηση Flask App & Ρυθμίσεις ---
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_needs_to_be_long')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['REMEMBER_COOKIE_SECURE'] = True if os.environ.get('RENDER_EXTERNAL_URL') else False
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

    # --- 2. Αρχικοποίηση Extensions ---
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'
    login_manager.session_protection = 'strong'

    # Ρυθμίσεις Google OAuth (Authlib)
    oauth.init_app(app)
    oauth.register(
        'google',
        client_id=app.config.get('GOOGLE_CLIENT_ID'),
        client_secret=app.config.get('GOOGLE_CLIENT_SECRET'),
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
        redirect_uri='/oauth/authorize' 
    )

    # Flask-Login: Συνάρτηση φόρτωσης χρήστη (ΠΡΕΠΕΙ ΝΑ ΕΙΝΑΙ ΜΕΣΑ!)
    @login_manager.user_loader
    def load_user(user_id):
        """Φορτώνει τον χρήστη από το ID του για το Flask-Login."""
        # Χρησιμοποιούμε db.session.get() για άμεση φόρτωση από το ID
        return db.session.get(User, int(user_id))

    # --------------------------------------------------------------------------
    # 5. ΡΟΥΤΙΝΕΣ (ROUTES) - ΟΛΕΣ ΕΙΝΑΙ ΣΩΣΤΑ ΜΕΣΑ
    # --------------------------------------------------------------------------
    
    @app.route('/', endpoint='index_page')
    def index():
        return render_template('index.html')

    @app.route('/admin_panel')
    @login_required
    def admin_panel():
        """Προστατευμένη ρουτίνα για το admin panel."""
        if current_user.role not in ['admin', 'owner']:
            flash('Δεν έχετε δικαίωμα πρόσβασης.', 'error')
            return redirect(url_for('chat_page')) 
        return render_template('admin_panel.html')

    @app.route('/chat', endpoint='chat_page') 
    @login_required
    def chat():
        """Προστατευμένη ρουτίνα για τη σελίδα συνομιλίας."""
        return render_template(
            'chat.html',
            role=current_user.role,
            color=current_user.color
        ) 

    # Ρουτίνα Σύνδεσης (Endpoint: login_page)
    @app.route('/login', methods=['GET', 'POST'], endpoint='login_page')
    def login():
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

    # Ρουτίνα POST API: Χειρίζεται τη σύνδεση username/password (AJAX)
    @app.route('/api/v1/login', methods=['POST'])
    def api_login():
        """Διαχειρίζεται τη σύνδεση μέσω AJAX/API και επιστρέφει JSON."""
        if current_user.is_authenticated:
            return jsonify({'success': True, 'redirect': url_for('chat_page')}), 200

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Δεν παρασχέθηκαν δεδομένα.'}), 400
            
        display_name = data.get('display_name')
        password = data.get('password')
        
        user = db.session.scalar(select(User).filter_by(display_name=display_name))
        
        if user and user.check_password(password):
            login_user(user)
            redirect_url = url_for('admin_panel') if user.role in ['owner', 'admin'] else url_for('chat_page')
            return jsonify({'success': True, 'redirect': redirect_url}), 200
            
        return jsonify({'error': 'Λάθος Όνομα Χρήστη ή Κωδικός.'}), 401

    @app.route('/logout', endpoint='logout_page')
    @login_required
    def logout():
        logout_user()
        flash('Έχετε αποσυνδεθεί επιτυχώς.', 'success')
        # Χρήση του σωστού endpoint name
        return redirect(url_for('login_page')) 

    # --- Routes Google OAuth ---

    @app.route('/oauth/login', methods=['GET'])
    def oauth_login():
        """Ανακατευθύνει τον χρήστη στη σελίδα σύνδεσης της Google."""
        return oauth.google.authorize_redirect(
            redirect_uri=url_for('authorize', _external=True)
        )

    @app.route('/oauth/authorize')
    def authorize():
        """Google OAuth callback route (Endpoint: authorize)."""
        try:
            token = oauth.google.authorize_access_token()
        except AuthlibOAuthError as e:
            flash(f'Authentication failed: {e.description}', 'error')
            # Χρήση του σωστού endpoint name
            return redirect(url_for('login_page')) 

        userinfo = oauth.google.parse_id_token(token, nonce=session.get('nonce'))
        user_google_id = userinfo.get('sub')
        
        user = db.session.execute(
            select(User).where(User.google_id == user_google_id)
        ).scalar_one_or_none()

        if not user:
            new_user = User(
                google_id=user_google_id,
                display_name=userinfo.get('name', 'New User'),
                avatar_url=userinfo.get('picture'),
                role='user',
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
        
        return redirect(url_for('admin_panel') if user_to_login.role in ['owner', 'admin'] else url_for('chat_page'))
    
    # --- API Routes ---

    @app.route('/api/v1/user', methods=['GET'])
    @login_required
    def api_get_current_user():
        """Επιστρέφει τα δεδομένα του συνδεδεμένου χρήστη."""
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
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401
            
        flash("Πρέπει να συνδεθείτε για να δείτε αυτή τη σελίδα.", 'warning')
        # Χρήση του σωστού endpoint name
        return redirect(url_for('login_page')) 

    # --- 6. Επιστροφή του αντικειμένου app ---
    return app

# # Εάν θέλετε να τρέχετε τοπικά, αφαιρέστε τα σχόλια από τις παρακάτω γραμμές:
# if __name__ == '__main__':
#     app = create_app()
#     app.run(debug=True)