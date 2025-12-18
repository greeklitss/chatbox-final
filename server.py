import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required
from flask_socketio import SocketIO, emit
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'radio-parea-2024-secure'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///radio_parea.db'

db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- ΜΟΝΤΕΛΟ ΧΡΗΣΤΗ ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user') # owner, admin, user
    color = db.Column(db.String(20), default='#D4AF37')
    can_change_name = db.Column(db.Boolean, default=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', backref='messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- API LINK PREVIEW ---
@app.route('/api/link-preview')
def link_preview():
    url = request.args.get('url')
    try:
        res = requests.get(url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(res.text, 'html.parser')
        title = soup.find("meta", property="og:title")
        image = soup.find("meta", property="og:image")
        return jsonify({
            "title": title['content'] if title else soup.title.string if soup.title else url,
            "image": image['content'] if image else None
        })
    except: return jsonify({"error": "failed"}), 400

# --- UPDATE PROFILE (Nickname 1 φορά) ---
@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.json
    new_name = data.get('display_name')
    new_color = data.get('color')
    
    if new_color:
        current_user.color = new_color
    
    if new_name and new_name != current_user.display_name:
        if current_user.role in ['owner', 'admin'] or current_user.can_change_name:
            exists = User.query.filter(User.display_name == new_name).first()
            if not exists:
                current_user.display_name = new_name
                if current_user.role not in ['owner', 'admin']:
                    current_user.can_change_name = False
            else: return jsonify({"status": "error", "message": "Το όνομα υπάρχει"}), 400
        else: return jsonify({"status": "error", "message": "Το όνομα έχει ήδη αλλαχθεί"}), 403
        
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/chat')
@login_required
def chat():
    msgs = Message.query.order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', messages=msgs)

# --- SOCKET EVENTS ---
@socketio.on('message')
def handle_msg(data):
    if current_user.is_authenticated:
        msg = Message(user_id=current_user.id, content=data['content'])
        db.session.add(msg)
        db.session.commit()
        emit('message', {
            'id': msg.id, 'display_name': current_user.display_name,
            'content': data['content'], 'color': current_user.color, 'role': current_user.role
        }, broadcast=True)

@socketio.on('delete_message')
def delete_msg(data):
    if current_user.role in ['admin', 'owner']:
        msg = Message.query.get(data['id'])
        if msg:
            db.session.delete(msg)
            db.session.commit()
            emit('message_deleted', {'id': data['id']}, broadcast=True)

@socketio.on('clear_chat')
def clear_chat():
    if current_user.role in ['admin', 'owner']:
        Message.query.delete()
        db.session.commit()
        emit('chat_cleared', broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)