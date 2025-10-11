import os
import json
from flask import Flask, send_from_directory, request, jsonify, url_for
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from datetime import datetime

# --- Ρυθμίσεις Εφαρμογής ---
# Χρησιμοποιούμε την προεπιλεγμένη ρύθμιση static_folder='static'
app = Flask(__name__) 

# Ρύθμιση φακέλου upload
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Δημιουργία φακέλου αν δεν υπάρχει. 
# Χρησιμοποιούμε exist_ok=True για να επιλύσουμε το FileExistsError στο Gunicorn.
os.makedirs(os.path.join(os.getcwd(), UPLOAD_FOLDER), exist_ok=True)

# Ρύθμιση SocketIO
# Χρησιμοποιούμε message_queue='redis://localhost:6379' (ή ανάλογο για Render) αν χρησιμοποιούσαμε πολλαπλούς workers
socketio = SocketIO(app)


# --- AUTHENTICATION ROUTES ---

@app.route('/logout', methods=['POST'])
def logout():
    # Εδώ θα ήταν η λογική για το logout (π.χ. διαγραφή session/cookie).
    response = jsonify({'message': 'Logged out'})
    # Προσθέστε εδώ την αφαίρεση του session cookie (αν υπάρχει)
    return response, 200

# --- WEB PAGES ROUTES (Frontend) ---

@app.route('/')
def serve_chat():
    # Εξυπηρέτηση του chat.html
    return send_from_directory('.', 'chat.html')

# --- API ROUTES ---

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file:
        filename = secure_filename(file.filename)
        # Χρησιμοποιούμε το app.config['UPLOAD_FOLDER'] που είναι 'static/uploads'
        save_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename)
        
        # Διασφάλιση ότι ο φάκελος static/uploads υπάρχει
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
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
def handle_message(message_content_json_string):
    # ΔΙΟΡΘΩΣΗ: Πρέπει να κάνουμε parse το string που έρχεται από το JS
    try:
        data = json.loads(message_content_json_string)
    except json.JSONDecodeError:
        print(f"Received invalid JSON message: {message_content_json_string}")
        return
        
    # ΠΡΟΣΩΡΙΝΕΣ ΤΙΜΕΣ
    display_name = "User"
    user_role = "user"
    
    # Χρησιμοποιούμε το 'text' (ή 'url') που βρίσκεται μέσα στο JSON payload του chat.html
    
    # Ελέγχουμε αν υπάρχει 'text' ή 'url' στο payload
    if 'text' in data:
        message_body = data['text']
    elif 'url' in data:
        message_body = data['url']
    else:
        # Αγνοούμε αν το payload δεν έχει κείμενο/url
        return

    message_data = {
        'messageId': str(datetime.now().timestamp()), 
        'displayName': display_name,
        'message': message_body, # Το κείμενο ή το URL
        'timestamp': datetime.utcnow().isoformat(),
        'role': user_role,
        'isBold': data.get('isBold', False),
        'color': data.get('color', '#E0E0E0')
    }
    
    # Στέλνουμε το μήνυμα πίσω σε όλους
    emit('message', message_data, broadcast=True)


if __name__ == '__main__':
    # Αυτό δεν χρησιμοποιείται σε deployment με Gunicorn
    socketio.run(app, debug=True)