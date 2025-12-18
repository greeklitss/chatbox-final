import eventlet
eventlet.monkey_patch()

import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user
from flask_socketio import SocketIO, emit
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'radio-parea-2025'

# Ρύθμιση Βάσης Δεδομένων
db_url = os.environ.get('DATABASE_URL', 'sqlite:///radio_parea.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Μοντέλα
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')
    color = db.Column(db.String(20), default='#D4AF37')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(80))
    author_color = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Δημιουργία βάσης αν δεν υπάρχει
with app.app_context():
    db.create_all()

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat')
def chat_page():
    history = Message.query.order_by(Message.timestamp.asc()).all()
    return render_template('chat.html', messages=history)

# --- SOCKETS ---

@socketio.on('message')
def handle_msg(data):
    msg = Message(
        content=data['content'],
        author_name=data.get('display_name', 'Guest'),
        author_color=data.get('color', '#D4AF37')
    )
    db.session.add(msg)
    db.session.commit()
    emit('message', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000)