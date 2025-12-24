import eventlet
eventlet.monkey_patch()

import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash

# 1. Αρχικοποίηση
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
socketio = SocketIO()

ONLINE_USERS = {}

# 2. Μοντέλο Χρήστη
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), default='user') # owner, admin, user
    color = db.Column(db.String(20), default='#D4AF37')
    avatar_url = db.Column(db.String(256), nullable=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 3. Routes (Οι "γέφυρες" για τις σελίδες σου)
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key_here'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///radio.db'
    
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        if request.method == 'POST':
            user = User.query.filter_by(display_name=request.form.get('username')).first()
            if user and user.check_password(request.form.get('password')):
                login_user(user)
                return redirect(url_for('chat_page'))
            flash('Λάθος στοιχεία!')
        return render_template('login.html')

    @app.route('/chat')
    @login_required
    def chat_page():
        return render_template('chat.html')

    @app.route('/admin')
    @login_required
    def admin_panel():
        if current_user.role not in ['admin', 'owner']:
            return redirect(url_for('chat_page'))
        return render_template('admin_panel.html')

    # API για να δουλεύει το admin_panel.html
    @app.route('/check_login')
    def check_login():
        if current_user.is_authenticated:
            return jsonify({'id': current_user.id, 'role': current_user.role})
        return jsonify({'error': 'unauthorized'}), 401

    @app.route('/api/v1/admin/users')
    @login_required
    def get_users():
        users = User.query.all()
        return jsonify([{'id': u.id, 'display_name': u.display_name, 'role': u.role} for u in users])

    # 4. Socket Events (Για το Chat και την "Σκούπα")
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            ONLINE_USERS[request.sid] = {
                'display_name': current_user.display_name,
                'avatar_url': current_user.avatar_url,
                'color': current_user.color
            }
            emit('user_list', list(ONLINE_USERS.values()), broadcast=True)

    @socketio.on('clear_chat_request')
    def handle_clear():
        if current_user.role == 'owner':
            # Στέλνει το σήμα που περιμένει το chat.html σου
            emit('message', {'content': 'CLEAN_EVENT'}, broadcast=True)

    with app.app_context():
        db.create_all()
        # Δημιουργία πρώτου Admin αν δεν υπάρχει
        if not User.query.filter_by(display_name="Admin").first():
            admin = User(display_name="Admin", role="owner", 
                         password_hash=generate_password_hash("admin123"))
            db.session.add(admin)
            db.session.commit()

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True)