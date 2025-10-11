import os
import json
from flask import Flask, send_from_directory, request, jsonify, url_for, session, redirect
from flask_session import Session 
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from datetime import datetime

# --- Ρυθμίσεις Εφαρμογής & Session ---
app = Flask(__name__) 

# Ρύθμιση Session
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', 'default_fallback_secret_key_for_dev')
app.config["SESSION_TYPE"] = "filesystem" 
app.config["SESSION_PERMANENT"] = False

Session(app) 

# Ρύθμιση φακέλου upload
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Δημιουργία φακέλου αν δεν υπάρχει
os.makedirs(os.path.join(os.getcwd(), UPLOAD_FOLDER), exist_ok=True)

# Ρύθμιση SocketIO (Ο Gunicorn θα παρέχει τον gevent worker)
socketio = SocketIO(app)

# --- MOCK USER DATABASE (Δοκιμαστικοί Χρήστες & Ρόλοι) ---
USERS = {
    'admin': {'password': '123', 'role': 'admin', 'display_name': 'Administrator 👑'},
    'user1': {'password': '123', 'role': 'user', 'display_name': 'Δημήτρης'},
    'guest': {'password': '123', 'role': 'guest', 'display_name': 'Guest User'}
}


# --- AUTHENTICATION ROUTES ---

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in USERS and USERS[username]['password'] == password:
        session['logged_in'] = True
        session['username'] = username
        session['role'] = USERS[username]['role']
        session['display_name'] = USERS[username]['display_name']
        return jsonify({'message': 'Login successful', 'redirect': '/'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('display_name', None)
    return jsonify({'message': 'Logged out', 'redirect': '/login.html'}), 200

# --- ΕΛΕΓΧΟΣ ΣΥΝΔΕΣΗΣ ---
@app.route('/check_login', methods=['GET'])
def check_login():
    if session.get('logged_in'):
        return jsonify({
            'logged_in': True,
            'display_name': session.get('display_name'),
            'role': session.get('role')
        }), 200
    else:
        return jsonify({'logged_in': False}), 401

# --- WEB PAGES ROUTES (Frontend) ---

@app.route('/login.html')
def serve_login():
    if session.get('logged_in'):
        return redirect(url_for('serve_chat'))
    return send_from_directory('.', 'login.html')

@app.route('/')
def serve_chat():
    if not session.get('logged_in'):
        return redirect(url_for('serve_login'))
    return send_from_directory('.', 'chat.html')

# --- API ROUTES (Upload & Settings) ---

@app.route('/upload', methods=['POST'])
def upload_file():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    # Χρησιμοποιούμε 'file' (όπως στο frontend)
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file:
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
        
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        file.save(save_path)
        
        file_url = url_for('static', filename=f'uploads/{filename}', _external=True)
        
        return jsonify({'url': file_url}), 200
        
    return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/settings')
def get_settings():
    # Επιστρέφουμε τις ρυθμίσεις για το frontend
    return jsonify({
        "app_title": "Chatbox",
        "message_opacity": 0.85,
        "input_row_opacity": 0.90,
        "top_bar_opacity": 0.95,
        "default_font_color": '#E0E0E0',
        "allow_gif_searches": 'true' 
    })


# --- WEBSOCKET EVENT HANDLERS (SocketIO) ---

@socketio.on('connect')
def handle_connect():
    if not session.get('logged_in'):
        return False
    display_name = session.get('display_name', 'Guest')
    emit('userStatus', {'displayName': display_name, 'status': 'connected'}, broadcast=True) 

@socketio.on('disconnect')
def handle_disconnect():
    display_name = session.get('display_name', 'Guest')
    emit('userStatus', {'displayName': display_name, 'status': 'disconnected'}, broadcast=True)

@socketio.on('message')
def handle_message(message_content_json_string):
    if not session.get('logged_in'):
        return 

    try:
        # Αναμένουμε το απλό JSON payload: {text: "...", isBold: true, isItalic: true, ...}
        data = json.loads(message_content_json_string) 
    except json.JSONDecodeError:
        # Fallback για plain text ή αν σταλθεί απλά το URL
        data = {'text': message_content_json_string}
        
    # ΑΝΑΚΤΗΣΗ ΔΕΔΟΜΕΝΩΝ ΑΠΟ ΤΟ SESSION
    display_name = session.get('display_name', 'Guest')
    user_role = session.get('role', 'guest')
    
    # Χρησιμοποιούμε το 'text' ή το 'url'
    message_body = data.get('text') or data.get('url')
    
    if not message_body:
        return

    message_data = {
        'messageId': str(datetime.now().timestamp()), 
        'displayName': display_name,
        'message': message_body, 
        'timestamp': datetime.utcnow().isoformat(),
        'role': user_role, 
        'isBold': data.get('isBold', False),
        'isItalic': data.get('isItalic', False), # ✅ ΠΡΟΣΘΗΚΗ isItalic
        'color': data.get('color', '#E0E0E0')
    }
    
    emit('message', message_data, broadcast=True)


if __name__ == '__main__':
    socketio.run(app, debug=True)