import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select
from datetime import datetime
# Νέα εισαγωγή για το Google Login
from authlib.integrations.flask_client import OAuth, OAuthError as AuthlibOAuthError
from flask_socketio import SocketIO, emit, join_room, leave_room
import eventlet # Απαραίτητο για το gunicorn eventlet worker

# --------------------------------------------------------------------------
# 1. ΕΚΤΑΣΕΙΣ (Extensions)
# --------------------------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth() # Ορισμός του OAuth extension
socketio = SocketIO()

# --- Λίστα ενεργών χρηστών (Global/Memory Store) ---
ONLINE_USERS = {} 

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

def get_online_users_list():
    """Επιστρέφει τη λίστα των συνδεδεμένων χρηστών για το SocketIO."""
    users_data = []
    # Χρησιμοποιούμε set για να αφαιρέσουμε τους διπλούς χρήστες
    seen_users = set() 
    
    # Το request.sid είναι η session ID του SocketIO, το οποίο αλλάζει ανά σύνδεση.
    # Πρέπει να ομαδοποιήσουμε ανά User ID.
    unique_users = {}
    for user_data in ONLINE_USERS.values():
        unique_users[user_data['id']] = user_data

    for user_data in unique_users.values():
        users_data.append({
            'id': user_data['id'],
            'display_name': user_data['display_name'],
            'role': user_data['role'],
            'color': user_data['color'],
            'avatar_url': user_data.get('avatar_url')
        })

    # Ταξινόμηση για να εμφανίζονται πρώτα οι owners/admins
    role_order = {'owner': 1, 'admin': 2, 'user': 3, 'guest': 4}
    users_data.sort(key=lambda x: role_order.get(x['role'].lower(), 5))
    
    return users_data


# --------------------------------------------------------------------------
# 3. ΜΟΝΤΕΛΑ ΒΑΣΗΣ ΔΕΔΟΜΕΝΩΝ (Database Models)
# --------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True) 
    password_hash = db.Column(db.String(256), nullable=True) 
    google_id = db.Column(db.String(120), unique=True, nullable=True) # Για Google Login
    role = db.Column(db.String(20), default='user')
    color = db.Column(db.String(7), default='#008000')
    avatar_url = db.Column(db.String(256), nullable=True) 

    messages = db.relationship('Message', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False 
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.display_name}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.content[:20]}>'

# --------------------------------------------------------------------------
# 4. ΕΡΓΟΣΤΑΣΙΟ ΕΦΑΡΜΟΓΗΣ (Application Factory)
# --------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login callback για φόρτωση χρήστη από το ID."""
    return User.query.get(int(user_id))

def create_app():
    # --- 1. Αρχικοποίηση Εφαρμογής ---
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_must_be_strong')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ΡΥΘΜΙΣΕΙΣ GOOGLE OAUTH
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID_HERE')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET_HERE')
    
    # --- 2. Αρχικοποίηση Extensions ---
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'login_page'

    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        client_kwargs={'scope': 'openid email profile'},
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
    )
    
    # ----------------------------------------------------
    # 5. ΟΡΙΣΜΟΣ ΡΟΥΤΙΝΩΝ (Routes) - ΟΛΕΣ ΜΕΣΑ ΣΤΟ create_app()
    # ----------------------------------------------------

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))
        return redirect(url_for('login_page'))

    @app.route('/login', methods=['GET', 'POST'])
    def login_page():
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            user = User.query.filter_by(display_name=username).first()

            if user and user.check_password(password):
                login_user(user, remember=True)
                flash(f'Συνδεθήκατε ως {user.display_name}.', 'success')
                
                next_page = request.args.get('next')
                return redirect(next_page or url_for('chat_page'))
            else:
                flash('Λάθος Όνομα Χρήστη ή Κωδικός.', 'error')

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Αποσυνδεθήκατε επιτυχώς.', 'success')
        return redirect(url_for('login_page'))


    # --- ΡΟΥΤΙΝΕΣ GOOGLE OAUTH ---
    @app.route('/google_login')
    def google_login():
        """Ξεκινάει τη διαδικασία σύνδεσης μέσω Google."""
        if current_user.is_authenticated:
            return redirect(url_for('chat_page'))
        
        return oauth.google.authorize_redirect(url_for('google_auth', _external=True))


    @app.route('/google_auth')
    def google_auth():
        """Χειρίζεται την απάντηση (callback) από τον Google Auth Server."""
        try:
            token = oauth.google.authorize_access_token()
            user_info = oauth.google.get('userinfo').json()
            
            google_id = user_info['id']
            email = user_info.get('email')
            display_name = user_info.get('name', email.split('@')[0] if email else f"User{google_id[:5]}")
            avatar_url = user_info.get('picture')
            
            user = User.query.filter_by(google_id=google_id).first()

            if user is None:
                # Δημιουργία μοναδικού display_name
                unique_name = display_name
                counter = 1
                while User.query.filter_by(display_name=unique_name).first():
                    unique_name = f"{display_name}_{counter}"
                    counter += 1

                new_user = User(
                    display_name=unique_name,
                    email=email,
                    google_id=google_id,
                    password_hash=None, 
                    role='user',
                    color=get_default_color_by_role('user'),
                    avatar_url=avatar_url
                )
                db.session.add(new_user)
                db.session.commit()
                user_to_login = new_user
                flash('Καλώς ήρθες! Ο λογαριασμός σου μέσω Google δημιουργήθηκε.', 'success')
            else:
                user_to_login = user
                
            login_user(user_to_login)
            flash(f"Επιτυχής σύνδεση ως {user_to_login.display_name} (Google).", 'success')
            
            return redirect(url_for('admin_panel') if user_to_login.role in ['owner', 'admin'] else url_for('chat_page'))

        except AuthlibOAuthError as e:
            flash(f'Η σύνδεση μέσω Google ακυρώθηκε ή απέτυχε. {e}', 'error')
            print(f"Google Auth Error (Authlib): {e}")
            return redirect(url_for('login_page'))
        except Exception as e:
            flash(f'Προέκυψε σφάλμα κατά τη σύνδεση Google: {e}', 'error')
            print(f"Google Auth Error: {e}")
            return redirect(url_for('login_page'))


    @app.route('/chat')
    @login_required
    def chat_page():
        return render_template('chat.html',
            user_id=current_user.id,
            display_name=current_user.display_name,
            role=current_user.role,
            color=current_user.color,
            avatar_url=current_user.avatar_url
        )

    @app.route('/admin')
    @login_required
    def admin_panel():
        if current_user.role not in ['owner', 'admin']:
            flash('Δεν έχετε δικαίωμα πρόσβασης.', 'error')
            return redirect(url_for('chat_page'))
        return render_template('admin_panel.html', role=current_user.role)

    
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

    @app.route('/api/v1/sign_up', methods=['POST'])
    def api_sign_up():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password are required.'}), 400

        if User.query.filter_by(display_name=username).first():
            return jsonify({'error': 'Username already exists.'}), 409

        new_user = User(
            display_name=username,
            role='user',
            color=get_default_color_by_role('user')
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201

    @app.route('/api/v1/users', methods=['GET'])
    @login_required
    def api_get_all_users():
        if current_user.role not in ['admin', 'owner']:
             return jsonify({'error': 'Access Denied'}), 403
        
        users = User.query.all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'display_name': user.display_name,
                'email': user.email,
                'role': user.role,
                'color': user.color,
                'google_id': user.google_id is not None # True αν είναι Google χρήστης
            })
        return jsonify(user_list)

    @app.route('/api/v1/user/<int:user_id>', methods=['PUT', 'DELETE'])
    @login_required
    def api_manage_user(user_id):
        if current_user.role not in ['admin', 'owner']:
             return jsonify({'error': 'Access Denied'}), 403

        user = User.query.get_or_404(user_id)
        
        # Αποτροπή διαγραφής/αλλαγής του ίδιου του owner
        if user.role == 'owner' and current_user.role != 'owner':
            return jsonify({'error': 'Only the owner can manage the owner account.'}), 403
            
        if user.role == 'owner' and user_id != current_user.id:
            return jsonify({'error': 'Cannot manage other owner accounts.'}), 403


        if request.method == 'DELETE':
            if user_id == current_user.id:
                return jsonify({'error': 'Cannot delete your own account while logged in.'}), 400

            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': f'User {user.display_name} deleted successfully'}), 200

        elif request.method == 'PUT':
            data = request.get_json()
            new_role = data.get('role')
            new_color = data.get('color')

            if new_role:
                # Ο admin δεν μπορεί να δώσει/αφαιρέσει το ρόλο owner
                if new_role == 'owner' and current_user.role != 'owner':
                    return jsonify({'error': 'Only the owner can set the owner role.'}), 403
                
                # Ο admin δεν μπορεί να αλλάξει το ρόλο άλλου admin
                if user.role == 'admin' and current_user.role == 'admin' and user_id != current_user.id:
                    return jsonify({'error': 'Admin cannot modify another admin\'s role.'}), 403

                user.role = new_role
                user.color = get_default_color_by_role(new_role) # Reset color based on new role
                
            if new_color:
                user.color = new_color
                
            db.session.commit()
            return jsonify({'message': f'User {user.display_name} updated successfully', 'user': {'role': user.role, 'color': user.color}}), 200
    
    # --- Error Handlers ---

    @app.errorhandler(401)
    def unauthorized(error):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401
            
        flash("Πρέπει να συνδεθείτε για να δείτε αυτή τη σελίδα.", 'warning')
        return redirect(url_for('login_page'))

    # ----------------------------------------------------
    # 6. ΟΡΙΣΜΟΣ SOCKETIO EVENTS - ΕΠΙΣΗΣ ΜΕΣΑ ΣΤΟ create_app()
    # ----------------------------------------------------

    @socketio.on('connect')
    def handle_connect():
        """Χειρίζεται τη σύνδεση ενός νέου χρήστη."""
        if current_user.is_authenticated:
            # Προσθήκη του χρήστη στη λίστα ONLINE_USERS
            ONLINE_USERS[request.sid] = {
                'id': current_user.id,
                'display_name': current_user.display_name,
                'role': current_user.role,
                'color': current_user.color,
                'avatar_url': current_user.avatar_url
            }
            # Ενημέρωση όλων των χρηστών για τη νέα λίστα
            emit('users_update', get_online_users_list(), broadcast=True)
            print(f"User connected: {current_user.display_name}. Online: {len(ONLINE_USERS)}")

    @socketio.on('disconnect')
    def handle_disconnect():
        """Χειρίζεται την αποσύνδεση ενός χρήστη."""
        if request.sid in ONLINE_USERS:
            del ONLINE_USERS[request.sid]
            # Ενημέρωση όλων των χρηστών για την αλλαγή
            socketio.emit('users_update', get_online_users_list(), broadcast=True)
            print(f"User disconnected. Remaining: {len(ONLINE_USERS)}")

    @socketio.on('message')
    def handle_message(data):
        """Χειρίζεται την αποστολή ενός νέου μηνύματος."""
        if not current_user.is_authenticated:
            return 

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


    return app

# --------------------------------------------------------------------------
# 7. ΕΚΚΙΝΗΣΗ (Run)
# --------------------------------------------------------------------------
if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        # Δημιουργία των πινάκων της βάσης δεδομένων αν δεν υπάρχουν
        # ΣΗΜΕΙΩΣΗ: Σε παραγωγή, χρησιμοποιήστε 'flask db upgrade'
        db.create_all() 

        # Δημιουργία ενός admin χρήστη αν δεν υπάρχει
        if not User.query.filter_by(role='owner').first():
            print("Δημιουργία Owner User...")
            owner = User(
                display_name='owner_admin',
                role='owner',
                color=get_default_color_by_role('owner')
            )
            owner.set_password('ownerpass') # Αλλάξτε τον κωδικό αυτόν!
            db.session.add(owner)
            db.session.commit()
            print("Owner User created. Username: owner_admin, Password: ownerpass")

    print("Starting Radioparea server...")
    # Χρησιμοποιούμε το eventlet αν είναι διαθέσιμο (κατάλληλο για SocketIO)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)