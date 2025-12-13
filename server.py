import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select
from datetime import datetime

# --------------------------------------------------------------------------
# 1. ΕΚΤΑΣΕΙΣ (Extensions)
# Ορίζονται εδώ για να είναι διαθέσιμες σε όλα τα scripts (π.χ. db_init.py, migration)
# --------------------------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

# --------------------------------------------------------------------------
# 2. ΒΟΗΘΗΤΙΚΗ ΣΥΝΑΡΤΗΣΗ (Helper Function)
# Χρησιμοποιείται για την αρχική δημιουργία χρήστη (π.χ. στο db_init.py)
# --------------------------------------------------------------------------
def get_default_color_by_role(role):
    # Εδώ μπορείτε να ορίσετε τα χρώματα βάσει ρόλου
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
    
    # Οι στήλες που προστέθηκαν με το migration script
    email = db.Column(db.String(120), unique=True, nullable=True) 
    oauth_provider = db.Column(db.String(50), nullable=True) 
    
    # Οι υπάρχουσες στήλες
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(7), nullable=False)
    avatar_url = db.Column(db.String(255), nullable=True)

    # Σχέση με μηνύματα (Υποθέτουμε ότι υπάρχει μοντέλο Message)
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
    # Πίνακας για τις καθολικές ρυθμίσεις
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False) # MUST NOT BE NULL
    value = db.Column(db.String(255), nullable=False)          # MUST NOT BE NULL

# server.py (Συνέχεια)

# --------------------------------------------------------------------------
# 4. ΕΡΓΟΣΤΑΣΙΟ ΕΦΑΡΜΟΓΗΣ (Application Factory)
# --------------------------------------------------------------------------
def create_app(test_config=None):
    # --- 1. Αρχικοποίηση Flask App ---
    app = Flask(__name__)
    
    # Φόρτωση ρυθμίσεων
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_dev_key')
    # Η DATABASE_URL ορίζεται από το Render (ή από εσάς στο PowerShell)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///db.sqlite'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # --- 2. Αρχικοποίηση Extensions ---
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'
    
    # Flask-Login: Συνάρτηση φόρτωσης χρήστη
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))


    # --------------------------------------------------------------------------
    # 5. ΡΟΥΤΙΝΕΣ (ROUTES)
    # 🚨 ΚΡΙΣΙΜΗ ΔΙΟΡΘΩΣΗ: ΟΛΕΣ ΟΙ ΡΟΥΤΙΝΕΣ ΠΡΕΠΕΙ ΝΑ ΕΙΝΑΙ ΕΔΩ ΜΕΣΑ
    # --------------------------------------------------------------------------
    
    # Ρουτίνα Αρχικής Σελίδας
    @app.route('/', endpoint='index_page')
    def index():
        return render_template('index.html')

    # Ρουτίνα Σύνδεσης
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

    # Ρουτίνα Αποσύνδεσης
    @app.route('/logout', endpoint='logout_page')
    @login_required
    def logout():
        logout_user()
        flash('Έχετε αποσυνδεθεί επιτυχώς.', 'success')
        return redirect(url_for('index_page'))

    # ΡΟΥΤΙΝΑ CHAT (Η διορθωμένη ρουτίνα σας)
    @app.route('/chat', endpoint='chat_page') 
    @login_required
    def chat():
        """Προστατευμένη ρουτίνα για τη σελίδα συνομιλίας."""
        # 🚨 ΔΙΟΡΘΩΣΗ: Περνάμε τις μεταβλητές role και color στο template
        return render_template(
            'chat.html',
            role=current_user.role,
            color=current_user.color
        )

    # --- 6. Επιστροφή του αντικειμένου app ---
    return app

# # Εάν θέλετε να τρέχετε τοπικά, αφαιρέστε τα σχόλια από τις παρακάτω γραμμές:
# if __name__ == '__main__':
#     app = create_app()
#     app.run(debug=True)

# Τέλος Αρχείου server.py