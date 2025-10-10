# --- ΠΡΟΣΘΗΚΗ ΣΤΟ server.py ---
@app.route('/logout', methods=['POST'])
def logout():
    # Εδώ θα βάλετε τη λογική για το logout
    # π.χ. διαγραφή του session cookie.
    # Επειδή το Flask-Session/login δεν είναι fully set up,
    # επιστρέφουμε απλά επιτυχία.
    response = jsonify({'message': 'Logged out'})
    # Προσθέστε εδώ την αφαίρεση του session cookie
    return response, 200

import os 
from flask_socketio import SocketIO


import os
import json
from flask import Flask, send_from_directory, request, jsonify, url_for
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from datetime import datetime

# --- Ρυθμίσεις Εφαρμογής ---
# Αντικαταστήστε με το όνομα του αρχείου σας!
app = Flask(__name__, static_folder='.') # Το static_folder='.' είναι για να σερβίρει το chat.html

# Ρύθμιση φακέλου upload
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Δημιουργία φακέλου αν δεν υπάρχει (χρειάζεται για τοπική ανάπτυξη, ο Render το κάνει)
if not os.path.exists(os.path.join(os.getcwd(), UPLOAD_FOLDER)):
    os.makedirs(os.path.join(os.getcwd(), UPLOAD_FOLDER))

# Εάν το περιβάλλον είναι Render (παραγωγή), βάζουμε CORS για WebSockets
# ΚΩΔΙΚΑΣ ΠΡΟΣΘΗΚΗΣ Ή ΑΝΤΙΚΑΤΑΣΤΑΣΗΣ ΣΤΟ server.py

# 1. Παίρνουμε το Redis URL από τις μεταβλητές περιβάλλοντος του Render
REDIS_URL = os.environ.get('REDIS_URL')

# ΚΩΔΙΚΑΣ ΠΡΟΣΘΗΚΗΣ Ή ΑΝΤΙΚΑΤΑΣΤΑΣΗΣ ΣΤΟ server.py

# 1. Παίρνουμε το Redis URL από τις μεταβλητές περιβάλλοντος του Render
REDIS_URL = os.environ.get('REDIS_URL')

# --- ΡΥΘΜΙΣΗ REDIS/SOCKETIO (Οριστική) ---
REDIS_URL = os.environ.get('REDIS_URL')

if REDIS_URL:
    if REDIS_URL.startswith('rediss://'):
        # 1. ΑΝΤΙΚΑΤΑΣΤΑΣΗ: rediss:// -> redis:// για να δουλέψει το redis-py
        message_queue_url = REDIS_URL.replace('rediss://', 'redis://')
        
        # 2. ΟΡΙΣΜΟΣ: Χρησιμοποιούμε message_queue_options για να παρακάμψουμε το SSL.
        socketio = SocketIO(
            app, 
            message_queue=message_queue_url, 
            async_mode='gevent',
            message_queue_options={'ssl_verify': False} # <--- ΤΟ ΣΩΣΤΟ ΚΛΕΙΔΙ
        )
    else:
        # Για απλή σύνδεση (redis://)
        socketio = SocketIO(app, message_queue=REDIS_URL, async_mode='gevent')
else:
    # Fallback για τοπική λειτουργία
    socketio = SocketIO(app, async_mode='gevent')

# --- WEB PAGES ROUTES (Frontend) ---

@app.route('/')
def serve_chat():
    # Εξυπηρέτηση του chat.html
    return send_from_directory('.', 'chat.html')

# (Εάν έχετε login.html, θα χρειαστείτε και ένα route για αυτό)

# --- ΑΠΑΡΑΙΤΗΤΟ ROUTE: API SETTINGS (Το ζητά το chat.html) ---

@app.route('/api/settings')
def get_settings():
    # Εδώ θα επιστρέφονται οι ρυθμίσεις από τη βάση δεδομένων
    # ΠΡΟΣΩΡΙΝΗ ΑΠΑΝΤΗΣΗ για να μη σπάσει το Frontend
    return jsonify({
        "app_title": "Chatbox",
        "message_opacity": 0.85,
        "input_row_opacity": 0.90,
        "top_bar_opacity": 0.95,
        "default_font_color": '#E0E0E0',
        "allow_gif_searches": 'true' 
    })


# --- ΔΙΟΡΘΩΣΗ: UPLOAD ROUTE (για το σφάλμα 404) ---

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'image' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = secure_filename(file.filename)
        # Χρησιμοποιούμε το 'uploads' directory που είναι μέσα στο static
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        
        # Επιστροφή του URL: /static/uploads/filename
        # Σημαντικό: βάζουμε _external=True για το πλήρες URL
        file_url = url_for('static', filename=f'uploads/{filename}', _external=True)
        
        return jsonify({'url': file_url}), 200
        
    return jsonify({'error': 'Upload failed'}), 500


# --- WEBSOCKET EVENT HANDLERS (SocketIO) ---

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('userStatus', {'displayName': 'System', 'status': 'connected'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    emit('userStatus', {'displayName': 'System', 'status': 'disconnected'}, broadcast=True)

@socketio.on('message')
def handle_message(data):
    # Εδώ γίνεται η επεξεργασία του JSON που στέλνει το chat.html
    # Το chat.html στέλνει: { type: 'message', message: JSON.stringify(format) }
    
    # ΠΡΟΣΩΡΙΝΕΣ ΤΙΜΕΣ
    display_name = "User"
    user_role = "user"
    
    message_data = {
        'messageId': str(datetime.now().timestamp()), # Προσωρινό ID
        'displayName': display_name,
        'message': data['message'],
        'timestamp': datetime.utcnow().isoformat(),
        'role': user_role
    }
    
    # Στέλνουμε το μήνυμα πίσω σε όλους
    emit('message', message_data, broadcast=True)

# --- ΕΚΚΙΝΗΣΗ (ΔΕΝ ΤΡΕΧΕΙ ΣΤΟΝ RENDER) ---
if __name__ == '__main__':
    socketio.run(app, debug=True)