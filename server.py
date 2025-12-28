import eventlet
eventlet.monkey_patch(all=True)

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO, emit
import secrets
import random

# ΕΚΤΑΣΕΙΣ

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
oauth = OAuth()
socketio = SocketIO()

ONLINE_USERS = {}
CHAT_COLORS = [
    "#D4AF37",
    "#E57373",
    "#81C784",
    "#64B5F6",
    "#FFD54F",
    "#BA68C8",
    "#4DB6AC",
    "#FF8A65",
]


def get_online_users_list():
    users_data = []
    unique_users = {}
    print(f"Current SID list: {ONLINE_USERS.keys()}")  # Debug print
    for sid, user_data in ONLINE_USERS.items():
        unique_users[user_data["id"]] = user_data
    for user_data in unique_users.values():
        users_data.append(
            {
                "id": user_data["id"],
                "display_name": user_data["display_name"],
                "role": user_data["role"],
                "color": user_data["color"],
                "avatar_url": user_data.get("avatar_url")
                or f"https://ui-avatars.com/api/?name={user_data['display_name']}&background=random",
            }
        )
    return users_data


class User(UserMixin, db.Model):
    has_setup_profile = db.Column(db.Boolean, default=False)
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    google_id = db.Column(db.String(120), unique=True, nullable=True)
    role = db.Column(db.String(20), default="user")
    color = db.Column(db.String(20), default="#008000")
    avatar_url = db.Column(db.String(256), nullable=True)
    messages = db.relationship("Message", backref="author", lazy="dynamic")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return (
            check_password_hash(self.password_hash, password)
            if self.password_hash
            else False
        )


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_app():
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1, x_prefix=1
    )
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "radioparea_2025")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///site.db"
    ).replace("postgres://", "postgresql://", 1)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    oauth.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")

    oauth.register(
        name="google",
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

    @app.route("/")
    def index():
        return (
            redirect(url_for("chat_page"))
            if current_user.is_authenticated
            else render_template("index.html")
        )

    @app.route("/login", methods=["GET", "POST"])
    def login_page():
        if request.method == "POST":
            user = User.query.filter_by(
                display_name=request.form.get("username")
            ).first()
            if user and user.check_password(request.form.get("password")):
                login_user(user, remember=True)
                return """
        <script>
            if (window.opener) {
                // Στέλνει την κύρια σελίδα στο chat
                window.opener.location.href = "/chat";
                // Κλείνει το popup
                window.close();
            } else {
                // Αν για κάποιο λόγο δεν υπάρχει opener, κάνει κανονικό redirect
                window.location.href = "/chat";
            }
        </script>
        """
        return render_template("login.html")

    @app.route("/google_login")
    def google_login():
        nonce = secrets.token_urlsafe(16)
        session["nonce"] = nonce
        return oauth.google.authorize_redirect(
            url_for("google_auth", _external=True, _scheme="https"), nonce=nonce
        )

    @app.route("/google_auth")
    def google_auth():
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token, nonce=session.pop("nonce", None))
        user = User.query.filter_by(email=user_info.get("email")).first()
        if not user:
            user = User(
                email=user_info.get("email"),
                display_name=user_info.get(
                    "name", "User" + str(random.randint(1000, 9999))
                ),
                color=random.choice(CHAT_COLORS),
                avatar_url=user_info.get("picture"),
                has_setup_profile=False,
            )
            db.session.add(user)
            db.session.commit()
        
        login_user(user, remember=True)

        # ΑΥΤΟ ΕΙΝΑΙ ΠΟΥ ΠΡΕΠΕΙ ΝΑ ΠΡΟΣΘΕΣΕΙΣ (Ιδιο με το login_page):
        return """
        <script>
            if (window.opener) {
                window.opener.location.href = "/chat";
                window.close();
            } else {
                window.location.href = "/chat";
            }
        </script>
        """

    @app.route("/chat")
    @login_required
    def chat_page():
        # Φέρνουμε τα 50 τελευταία (desc) και μετά τα αντιστρέφουμε για τη σωστή σειρά εμφάνισης
        history = Message.query.order_by(Message.id.desc()).limit(50).all()
        history.reverse() 
        return render_template("chat.html", history=history)

    @app.route("/update_profile", methods=["POST"])
    @login_required
    def update_profile():
        # ΕΛΕΓΧΟΣ: Αν έχει ήδη φτιάξει προφίλ, δεν τον αφήνουμε να ξαναλλάξει όνομα
        if current_user.has_setup_profile:
            return jsonify({"status": "error", "message": "Έχετε ήδη ορίσει το όνομά σας μία φορά!"}), 403

        data = request.get_json()
        new_name = data.get("display_name")
        if not data:
            return jsonify({"status": "error", "message": "No data"}), 400
        # --- ΕΔΩ ΠΡΟΣΘΕΤΟΥΜΕ ΤΟΝ ΕΛΕΓΧΟ ---

        new_name = data.get("display_name")
        if new_name:
            # Ψάχνουμε αν το όνομα υπάρχει σε ΑΛΛΟΝ χρήστη (όχι στον εαυτό μας)

            existing_user = User.query.filter(
                User.display_name == new_name, User.id != current_user.id
            ).first()
            if existing_user:
                return (
                    jsonify(
                        {"status": "error", "message": "Το όνομα χρησιμοποιείται ήδη!"}
                    ),
                    400,
                )
        # Ενημέρωση στοιχείων στη βάση

        current_user.display_name = data.get("display_name", current_user.display_name)
        current_user.avatar_url = data.get("avatar_url", current_user.avatar_url)
        current_user.color = data.get("color", current_user.color)
        current_user.has_setup_profile = True

        try:
            db.session.commit()

            # Ενημέρωση του ONLINE_USERS dictionary
            for sid, info in list(ONLINE_USERS.items()):
                if info["id"] == current_user.id:
                    ONLINE_USERS[sid].update({
                        "display_name": current_user.display_name,
                        "avatar_url": current_user.avatar_url,
                        "color": current_user.color,
                    })

            # Στέλνουμε τη λίστα χρησιμοποιώντας τη συνάρτηση που ήδη έχεις
            socketio.emit("users_update", get_online_users_list())
            
            return jsonify({"status": "success"}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Update error: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Αποσυνδεθήκατε με επιτυχία.", "info")
        return redirect(url_for("login_page"))
    @socketio.on("connect")
    def handle_connect():
        if current_user.is_authenticated:
            ONLINE_USERS[request.sid] = {
                "id": current_user.id,
                "display_name": current_user.display_name,
                "role": current_user.role,
                "color": current_user.color,
                "avatar_url": current_user.avatar_url,
            }
            emit("users_update", get_online_users_list(), broadcast=True)

    @socketio.on("disconnect")
    def handle_disconnect():
        ONLINE_USERS.pop(request.sid, None)
        emit("users_update", get_online_users_list(), broadcast=True)

    @socketio.on("message")
    def handle_message(data):
        if current_user.is_authenticated:
            new_msg = Message(content=data["content"], author=current_user)
            db.session.add(new_msg)
            db.session.commit()

            avatar = (
                current_user.avatar_url
                or f"https://ui-avatars.com/api/?name={current_user.display_name}&background=random"
            )

            emit(
                "message",
                {
                    "display_name": current_user.display_name,
                    "content": data["content"],
                    "color": current_user.color,
                    "avatar_url": avatar,
                },
                broadcast=True,
            )

    @socketio.on("clear_chat_request")
    def clear_chat():
        if current_user.is_authenticated and current_user.role == "owner":
            Message.query.delete()
            db.session.commit()
            emit("clear_chat_client", broadcast=True)

    @socketio.on("admin_change_bg")
    def handle_bg_change(data):
        if current_user.is_authenticated and current_user.role == "owner":
            emit("update_bg", {"url": data["url"]}, broadcast=True)

    with app.app_context():
        db.create_all()
    
    return app  # <--- Πρέπει να έχει 4 κενά (μία εσοχή) από την αρχή της γραμμής

app = create_app()

if __name__ == "__main__":
 
    port = int(os.environ.get("PORT", 8000))
    socketio.run(app, host="0.0.0.0", port=port)