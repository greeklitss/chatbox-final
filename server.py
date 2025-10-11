import os 
import json
import uuid # Για τη δημιουργία μοναδικών IDs χρήστη
from flask import Flask, send_from_directory, request, jsonify, url_for, redirect
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename
from datetime import datetime

# --- Ρυθμίσεις Εφαρμογής ---
app = Flask(__name__, static_folder='.') 
app.config['SECRET_KEY'] = 'a_super_secret_key' # Απαιτείται για SocketIO/Sessions
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Ρύθμιση φακέλου upload
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(os.path.join(os.getcwd(), UPLOAD_FOLDER)):
    os.makedirs(os.path.join(os.getcwd(), UPLOAD_FOLDER))

# --- ΚΑΘΟΛΙΚΕΣ ΔΟΜΕΣ ΔΕΔΟΜΕΝΩΝ ΓΙΑ ΧΡΗΣΤΕΣ/ΡΥΘΜΙΣΕΙΣ ---
# Χρησιμοποιούμε μια απλή dictionary ως in-memory βάση δεδομένων χρηστών
# Key: SocketIO SID
# Value: {'display_name': '...', 'role': '...'}
connected_users = {} 
app_settings = {'allow_gif_searches': 'true', 'default_font_color': '#F0F0F0'}

# --- MOCK LOGIN / SESSION MANAGEMENT ---

@app.route('/login_mock', methods=['GET'])
def login_mock():
    """
    Μια απλή σελίδα για να επιλέξει ο χρήστης το όνομα του.
    Στην πραγματική εφαρμογή, θα αντικατασταθεί με Login/Register.
    """
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Login</title>
    <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Roboto', sans-serif; background-color: #121212; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #1f1f1f; padding: 30px; border-radius: 8px; box-shadow: 0 0 20px #FF0066; }
        h2 { color: #FF0066; text-align: center; }
        input[type="text"] { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #39FF14; background: #333; color: white; border-radius: 4px; }
        button { background: #39FF14; color: black; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-weight: bold; transition: background 0.3s; }
        button:hover { background: #FF0066; color: white; }
    </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Welcome to Web Radio Chat</h2>
            <form action="/check_login" method="GET">
                <label for="name">Enter your display name:</label>
                <input type="text" id="name" name="name" required>
                <button type="submit">Join Chat</button>
            </form>
        </div>
    </body>
    </html>
    """
    return html_content

@app.route('/check_login', methods=['GET'])
def check_login():
    """
    Αυτό το route μιμείται τον έλεγχο session. 
    Στην πραγματικότητα, ο χρήστης λαμβάνει ένα όνομα από το login_mock.
    """
    display_name = request.args.get('name', f'Guest_{uuid.uuid4().hex[:4]}')
    
    # Logic για τον ρόλο
    user_role = 'user'
    if display_name.lower() == 'admin':
        user_role = 'admin'
    
    # Επειδή το chat.html καλεί /check_login, αν δεν υπάρχει όνομα, τον στέλνουμε πίσω
    if 'name' not in request.args:
        return redirect(url_for('login_mock'))

    return jsonify({'display_name': display_name, 'role': user_role}), 200

@app.route('/logout', methods=['POST'])
def logout():
    # Στην τρέχουσα υλοποίηση, το logout απλώς ανακατευθύνει στο login mock.
    # Σε πλήρες σύστημα, θα διέγραφε το session.
    return jsonify({'message': 'Logged out', 'redirect': url_for('login_mock')}), 200

@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify(app_settings), 200

# Route για την εξυπηρέτηση του chat.html
@app.route('/')
def index():
    # Πρώτα, ελέγχουμε αν έχει όνομα, αλλιώς πάμε για "login"
    if 'name' not in request.args:
        return redirect(url_for('login_mock'))
        
    # Αν έχει όνομα, σερβίρουμε το chat.html
    return send_from_directory(app.static_folder, 'chat.html')

# --- FILE UPLOAD ---

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file:
        filename = secure_filename(file.filename)
        # Προσθήκη timestamp για μοναδικότητα
        timestamp_prefix = datetime.now().strftime('%Y%m%d%H%M%S_')
        unique_filename = timestamp_prefix + filename
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(save_path)
        
        # Επιστροφή του πλήρους URL για χρήση στο chat.html
        file_url = url_for('static', filename=f'uploads/{unique_filename}', _external=True)
        
        return jsonify({'url': file_url}), 200
        
    return jsonify({'error': 'Upload failed'}), 500


# --- WEBSOCKET EVENT HANDLERS (SocketIO) ---

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    # Εδώ πρέπει να βρούμε τα στοιχεία χρήστη από το HTTP session.
    # Επειδή δεν έχουμε πλήρες Flask Session, χρησιμοποιούμε το query string 
    # που στάλθηκε με την αρχική κλήση του '/' route.
    
    # Προσομοίωση ανάκτησης δεδομένων χρήστη
    # Για να λειτουργήσει, η κλήση io() στο chat.html πρέπει να γίνει με το display_name
    
    # NOTE: Στην πραγματικότητα, το socketio connection δεν έχει access στο request.args 
    # της αρχικής HTTP GET request του '/'. 
    # Χρειάζεται να περάσουμε το όνομα του χρήστη ως query parameter στο io() call του client.

    # Λόγω της πολυπλοκότητας του session passing, θα το κάνουμε απλό:
    # Ο χρήστης θα συνδέεται με το SID του και θα λαμβάνει τα στοιχεία του 
    # από την HTTP GET request του chat.html (π.χ. /chat.html?name=...)
    
    # ΕΔΩ ΧΡΕΙΑΖΕΤΑΙ ΕΝΗΜΕΡΩΣΗ ΤΟΥ CLIENT (chat.html)
    # Προς το παρόν, αντλούμε το όνομα από το query string, το οποίο είναι hacky,
    # ή χρησιμοποιούμε το όνομα που έχει αποθηκεύσει ο client localy.
    
    # --- TEMPORARY HACK: Assume the display_name is passed in query args ---
    # Ο client θα πρέπει να συνδέεται με: io('?display_name=...')
    
    display_name = request.args.get('display_name', f'Guest_{sid[:4]}')
    
    # Ανάθεση ρόλου
    user_role = 'user'
    if display_name.lower() == 'admin':
        user_role = 'admin'

    # Αποθήκευση του νέου χρήστη
    connected_users[sid] = {'display_name': display_name, 'role': user_role}
    print(f'Client connected: {display_name} ({sid})')
    
    # Αποστολή μηνύματος σύνδεσης
    emit('userStatus', {'displayName': display_name, 'status': 'connected'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in connected_users:
        user = connected_users.pop(sid)
        print(f'Client disconnected: {user["display_name"]} ({sid})')
        # Αποστολή μηνύματος αποσύνδεσης
        emit('userStatus', {'displayName': user['display_name'], 'status': 'disconnected'}, broadcast=True)

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    user = connected_users.get(sid, {'display_name': 'Unknown', 'role': 'user'})

    # Το data είναι το JSON string που στέλνει το chat.html
    try:
        message_format = json.loads(data)
        
        # Ανάκτηση του κειμένου ή του URL
        text_or_url = message_format.get('text') or message_format.get('url')

        message_data = {
            'messageId': str(datetime.now().timestamp()), 
            'displayName': user['display_name'],
            'role': user['role'],
            'message': text_or_url,
            'timestamp': datetime.now().isoformat(),
            'isBold': message_format.get('isBold', False),
            'isItalic': message_format.get('isItalic', False),
            'color': message_format.get('color', app_settings['default_font_color'])
        }

        # Εκτύπωση και αποστολή σε όλους τους συνδεδεμένους clients
        print(f"[{user['role']}] {user['display_name']}: {text_or_url}")
        emit('message', message_data, broadcast=True)

    except json.JSONDecodeError:
        print(f"Received invalid JSON message from {user['display_name']}: {data}")

# --- ΕΚΚΙΝΗΣΗ ΤΟΥ SERVER ---
if __name__ == '__main__':
    socketio.run(app, debug=True, port=os.environ.get("PORT", 5000), host='0.0.0.0')