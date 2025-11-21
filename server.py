import os
from flask import Flask, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import timedelta

# --- 1. Αρχικοποίηση Extensions (Global Scope) ---
db = SQLAlchemy()
sess = Session()
socketio = SocketIO()

# --- 2. Μοντέλα Βάσης Δεδομένων (Κρίσιμο: __tablename__) ---
# Πρέπει να ορίσετε τα μοντέλα με τα σωστά ονόματα πινάκων 
# και τουλάχιστον τα βασικά πεδία, ώστε το SQLAlchemy να κάνει mapping.

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    # Προσθέστε άλλα πεδία όπως 'password_hash' αργότερα

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer) 
    content = db.Column(db.Text)

    
class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(100), nullable=False)


# 🚨 ΝΕΟ: ΠΡΟΣΘΕΤΟΥΜΕ ΤΟ EMOTICON ΜΕ ΤΟ ΠΕΔΙΟ IMAGE_URL ΠΟΥ ΖΗΤΑΕΙ Η ΒΑΣΗ
class Emoticon(db.Model):
    __tablename__ = 'emoticons'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
# --- 3. Flask Application Factory ---

def create_app():
    app = Flask(__name__)
    
    # --- CONFIGURATION ---
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_prefix=1, x_port=1, x_proto=1)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_fallback_key')
    
    database_url = os.environ.get('DATABASE_URL')
    
    # Χειρισμός DATABASE_URL για Render (Postgres)
    if not database_url:
        database_url = 'sqlite:///temp.db'
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
        
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # 🚨 ΚΡΙΣΙΜΟ FIX ΓΙΑ FLASK-SESSION & GUNICORN
    app.config['SQLALCHEMY_SESSION_TABLE_ARGS'] = {'extend_existing': True}
    
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    app.config['SESSION_SQLALCHEMY_TABLE'] = 'flask_sessions'
    
    # --- INITIALIZE EXTENSIONS ---
    db.init_app(app) 
    app.config['SESSION_SQLALCHEMY'] = db 
    sess.init_app(app)
    socketio.init_app(app, manage_session=False, cors_allowed_origins="*")

    # --- ROUTES (Ελάχιστη Δοκιμή) ---
    @app.route('/')
    def index():
        # Έλεγχος Session
        if 'visits' not in session:
            session['visits'] = 1
        else:
            session['visits'] += 1
            
        # Έλεγχος DB Connection
        with app.app_context():
            try:
                user_count = db.session.scalar(db.select(db.func.count(User.id)))
                db_status = f"✅ Success! Found {user_count} users in DB."
            except Exception as e:
                db_status = f"❌ DB Error: {e}"

        # Render ενός ελάχιστου template
        return render_template('index.html', visits=session['visits'], db_status=db_status)

    return app

# --- 4. Τερματικό Σημείο (Eventlet/SocketIO Server) ---
# Το Gunicorn θα καλέσει το create_app()
if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 10000)) 
    print(f"Starting Flask-SocketIO server locally on port {port}...")
    socketio.run(app, host='0.0.0.0', port=port, debug=True)