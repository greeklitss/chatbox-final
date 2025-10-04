// server.js (ΤΕΛΙΚΗ ΔΙΟΡΘΩΜΕΝΗ ΕΚΔΟΣΗ)

const express = require('express');
const http = require('http');
const path = require('path');
const { Pool } = require('pg');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const expressWs = require('express-ws');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const LocalStrategy = require('passport-local').Strategy;
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const axios = require('axios'); 

const app = express();
const server = http.createServer(app);
const wsInstance = expressWs(app, server);

// --- 1. ΚΡΙΣΙΜΟ: ΡΥΘΜΙΣΗ CSP (ΓΙΑ ΤΟ DEPLOYMENT) ---
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'self' data: https://; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net; connect-src 'self' wss: https://api.giphy.com; img-src 'self' data: https:;");
    next();
});

// --- STATIC FILES & UPLOADS ---
app.use(express.static(__dirname));

const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}
app.use('/uploads', express.static('uploads'));

// --- MULTER & AVATAR UPLOAD DEFINITION (ΣΩΣΤΗ ΘΕΣΗ) ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, uuidv4() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });
// -----------------------------------------------------------

// --- DATABASE & MIDDLEWARE ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || 'mysecret',
    resave: false,
    saveUninitialized: false
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// --- PASSPORT SERIALIZATION/DESERIALIZATION ---
passport.serializeUser((user, done) => { done(null, user.id); });

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (error) {
        done(error);
    }
});

// *************** ΣΥΜΠΛΗΡΩΣΕ ΕΔΩ ΤΙΣ PASSPORT ΣΤΡΑΤΗΓΙΚΕΣ ΣΟΥ ***************
// *************** (LocalStrategy, GoogleStrategy, FacebookStrategy) ***************
// *************** (Και τα auth routes: /login, /logout, /create-user) ***************

// --- ENDPOINTS (ΜΕΤΑ ΤΟΝ ΟΡΙΣΜΟ ΤΟΥ UPLOAD) ---

// Endpoint 1: Αλλαγή avatar μέσω ΑΡΧΕΙΟΥ
app.post('/change-avatar', upload.single('avatar'), async (req, res) => {
    if (!req.isAuthenticated()) { return res.status(401).send('Not authenticated.'); }
    if (!req.file) { return res.status(400).send('No file uploaded.'); }

    const userId = req.user.id;
    const avatarUrl = `/uploads/${req.file.filename}`; 
    
    try {
        const result = await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2 RETURNING *', [avatarUrl, userId]);
        const updatedUser = result.rows[0];

        req.login(updatedUser, (err) => { 
            if (err) { return res.status(500).json({ success: false, error: 'Could not update session.', avatarUrl }); }
            res.status(200).json({ success: true, avatarUrl });
        });
        
    } catch (error) {
        console.error('Error updating avatar:', error);
        res.status(500).send('An error occurred while updating avatar.');
    }
});

// Endpoint 2: Αλλαγή avatar μέσω URL
app.post('/change-avatar-url', async (req, res) => {
    if (!req.isAuthenticated()) { return res.status(401).send('Not authenticated.'); }
    const { avatarUrl } = req.body;
    
    if (!avatarUrl || (!avatarUrl.startsWith('http://') && !avatarUrl.startsWith('https://'))) {
        return res.status(400).send('Invalid or missing URL.');
    }

    const userId = req.user.id;
    
    try {
        const result = await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2 RETURNING *', [avatarUrl, userId]);
        const updatedUser = result.rows[0];

        req.login(updatedUser, (err) => { 
            if (err) { return res.status(500).json({ success: false, error: 'Could not update session.' }); }
            res.status(200).json({ success: true, avatarUrl });
        });
        
    } catch (error) {
        console.error('Error updating avatar URL:', error);
        res.status(500).send('An error occurred while updating avatar URL.');
    }
});

// --- GIF SEARCH ---
app.get('/search-gifs', async (req, res) => {
    if (!req.isAuthenticated()) { return res.status(401).send('Unauthorized'); }
    const query = req.query.q;
    const GIPHY_API_KEY = process.env.GIPHY_API_KEY; 
    
    if (!query || !GIPHY_API_KEY) {
        return res.status(400).send('Query is required or GIPHY_API_KEY is missing.');
    }

    try {
        const response = await axios.get('https://api.giphy.com/v1/gifs/search', {
            params: {
                api_key: GIPHY_API_KEY,
                q: query,
                limit: 1 
            }
        });

        const gifUrl = response.data.data.length > 0 ? response.data.data[0].images.original.url : null;

        if (gifUrl) {
            res.json({ success: true, url: gifUrl });
        } else {
             res.json({ success: false, url: null, message: 'No GIF found.' });
        }

    } catch (error) {
        console.error('Giphy API Error:', error.response ? error.response.data : error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch GIFs.' });
    }
});

// --- DELETE MESSAGE ---
app.delete('/delete-message/:id', async (req, res) => {
    if (!req.isAuthenticated() || (req.user.role !== 'admin' && req.user.role !== 'moderator')) {
        return res.status(403).send('Forbidden: Only admins and moderators can delete messages.');
    }

    const messageId = req.params.id;
    if (!messageId || isNaN(parseInt(messageId))) {
         return res.status(400).send('Invalid or missing message ID.');
    }

    try {
        const result = await pool.query('DELETE FROM messages WHERE id = $1 RETURNING *', [messageId]);
        
        if (result.rowCount === 0) {
            return res.status(404).send('Message not found.');
        }

        // Ενημέρωση όλων των συνδεδεμένων πελατών μέσω WebSockets
        wsInstance.getWss().clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ type: 'deleteMessage', messageId: messageId }));
            }
        });

        res.status(200).send('Message deleted successfully.');
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).send('Server error.');
    }
});

// --- ROOT ROUTES (ΓΙΑ ΝΑ ΦΟΡΤΩΝΕΙ ΤΟΠΙΚΑ) ---
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'chat.html'));
    } else {
        res.sendFile(path.join(__dirname, 'login.html'));
    }
});

app.get('/chat', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'chat.html'));
    } else {
        res.redirect('/login.html');
    }
});


// --- WEBSOCKET CONNECTION ---
wsInstance.app.ws('/', async (ws, req) => {
    const sessionData = req.session;

    ws.on('message', async (msg) => {
        const messageData = JSON.parse(msg);

        if (messageData.type === 'requestUserInfo') {
            if (req.isAuthenticated()) {
                const user = req.user;
                ws.send(JSON.stringify({
                    type: 'userInfo',
                    displayName: user.display_name,
                    role: user.role,
                    avatarUrl: user.avatar_url,
                    userId: user.id
                }));
            }
        } else if (messageData.type === 'chatMessage' && req.isAuthenticated()) {
            const user = req.user;
            const messageText = messageData.message;

            try {
                // Αποθήκευση στο PostgreSQL
                const result = await pool.query(
                    'INSERT INTO messages (user_id, message) VALUES ($1, $2) RETURNING *',
                    [user.id, messageText]
                );
                const newMessage = result.rows[0];

                // Διαμόρφωση απάντησης
                const response = {
                    type: 'chatMessage',
                    id: newMessage.id,
                    user_id: user.id,
                    message: messageText,
                    display_name: user.display_name,
                    timestamp: newMessage.timestamp,
                    role: user.role,
                    avatar_url: user.avatar_url
                };
                
                // Προώθηση σε όλους τους clients
                wsInstance.getWss().clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(response));
                    }
                });
                
            } catch (error) {
                console.error('Error inserting message:', error);
            }
        } else if (messageData.type === 'requestOldMessages') {
             // Αν ζητηθούν ξανά τα μηνύματα
             try {
                const result = await pool.query('SELECT m.id, m.message, m.timestamp, u.display_name, u.role, u.avatar_url, u.id as user_id FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp ASC');
                ws.send(JSON.stringify({ type: 'oldMessages', messages: result.rows }));
            } catch (error) {
                console.error('Error fetching old messages for client request:', error);
            }
        }
    });

    ws.on('close', () => {
        console.log('Ο χρήστης αποσυνδέθηκε');
    });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`Ο server τρέχει στο http://localhost:${PORT}`);
});