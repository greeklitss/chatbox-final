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
// const fetch = require('node-fetch'); // ΑΝ χρησιμοποιείτε παλιά έκδοση Node.js, κάντε uncomment αυτή τη γραμμή και εγκαταστήστε το node-fetch

const app = express();
const server = http.createServer(app); 
const wsInstance = expressWs(app, server); 

// --- ΣΗΜΑΝΤΙΚΗ ΔΙΟΡΘΩΣΗ: STATIC FILES ---
app.use(express.static(__dirname));

const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}
app.use('/uploads', express.static('uploads'));
// ----------------------------------------

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://chat_user:password@localhost:5432/chat_db',
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Συνάρτηση για έλεγχο σύνδεσης
function requireAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login.html');
}

// Session configuration
app.use(session({
    secret: 'secret-key-for-chat', 
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 ώρες
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Serialization ---
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (err) {
        done(err);
    }
});

// --- Local Strategy (Login/Register) ---
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return done(null, false, { message: 'Incorrect username.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Incorrect password.' });
        }

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

// --- ROUTES ---

app.get('/', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'chat.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true 
}));

// ΔΙΟΡΘΩΣΗ: Logout πλέον λειτουργεί με POST
app.post('/logout', (req, res) => {
    req.logout(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).send('Logout failed');
        }
        res.status(200).send('Logged out');
    });
});

app.post('/create-user', async (req, res) => {
    const { username, password, displayName } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, display_name) VALUES ($1, $2, $3)', 
                         [username, hashedPassword, displayName]);
        res.status(201).send('User created successfully');
    } catch (error) {
        console.error('Error creating user:', error);
        if (error.code === '23505') { // PostgreSQL unique violation error code
            return res.status(409).send('Username already exists');
        }
        res.status(500).send('Internal server error');
    }
});

app.get('/user-info', requireAuth, (req, res) => {
    res.json({
        id: req.user.id,
        displayName: req.user.display_name,
        role: req.user.role,
        avatarUrl: req.user.avatar_url // Για να πάρει το avatarUrl
    });
});

// --- Admin Endpoints ---

app.get('/users', requireAuth, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    try {
        const result = await pool.query('SELECT id, display_name, role FROM users ORDER BY display_name');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal server error');
    }
});

app.post('/change-role', requireAuth, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    const { userId, newRole } = req.body;
    if (!['user', 'moderator', 'admin'].includes(newRole)) {
        return res.status(400).send('Invalid role');
    }
    try {
        await pool.query('UPDATE users SET role = $1 WHERE id = $2', [newRole, userId]);
        res.status(200).send('Role updated');
    } catch (error) {
        console.error('Error changing role:', error);
        res.status(500).send('Internal server error');
    }
});

// Διαγραφή μηνύματος (Admin/Moderator)
app.delete('/delete-message/:messageId', requireAuth, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'moderator') {
        return res.status(403).send('Forbidden');
    }
    const messageId = req.params.messageId;
    try {
        const result = await pool.query('DELETE FROM messages WHERE id = $1 RETURNING *', [messageId]);
        
        if (result.rowCount === 0) {
            return res.status(404).send('Message not found');
        }
        
        // Ενημέρωση όλων των συνδεδεμένων πελατών μέσω WebSocket
        const response = { type: 'deleteMessage', messageId };
        wsInstance.getWss().clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(response));
            }
        });

        res.status(200).send('Message deleted');
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).send('Internal server error');
    }
});

// Καθαρισμός Ιστορικού (Admin)
app.delete('/clear-history', requireAuth, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    try {
        await pool.query('TRUNCATE messages');
        
        // Ενημέρωση όλων των συνδεδεμένων πελατών μέσω WebSocket
        const response = { type: 'clearChat' };
        wsInstance.getWss().clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(response));
            }
        });

        res.status(200).send('Chat history cleared');
    } catch (error) {
        console.error('Error clearing chat history:', error);
        res.status(500).send('Internal server error');
    }
});

// --- File Upload / Avatar ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir); 
    },
    filename: (req, file, cb) => {
        // Δημιουργία μοναδικού ονόματος αρχείου με επέκταση
        const extension = path.extname(file.originalname);
        cb(null, uuidv4() + extension);
    }
});
const upload = multer({ storage: storage });

app.post('/change-avatar', requireAuth, upload.single('avatar'), async (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded');
    }
    const newAvatarUrl = `/uploads/${req.file.filename}`;
    const userId = req.user.id;

    try {
        // Ενημέρωση της βάσης δεδομένων
        await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [newAvatarUrl, userId]);
        
        // Διαγραφή παλιού avatar (προαιρετικό)
        if (req.user.avatar_url && req.user.avatar_url.startsWith('/uploads/')) {
            const oldPath = path.join(__dirname, req.user.avatar_url);
            if (fs.existsSync(oldPath) && path.basename(oldPath) !== 'default-avatar.png') {
                 fs.unlink(oldPath, (err) => {
                    if (err) console.error('Error deleting old avatar:', err);
                 });
            }
        }
        
        // Ενημέρωση του req.user.avatar_url για το session
        req.user.avatar_url = newAvatarUrl;
        
        res.json({ message: 'Avatar updated successfully', avatarUrl: newAvatarUrl });

    } catch (error) {
        console.error('Error updating avatar:', error);
        res.status(500).send('Internal server error during avatar update');
    }
});

// --- ΝΕΟ ENDPOINT: Αναζήτηση GIF ---
// Χρησιμοποιεί το Giphy API key: UQxRacYoTn67CWCJ5zbdOvUnzmU0QnUs
app.get('/search-gifs', requireAuth, async (req, res) => {
    const GIPHY_API_KEY = 'UQxRacYoTn67CWCJ5zbdOvUnzmU0QnUs'; 
    const query = req.query.q;
    const limit = 5;

    if (!query) {
        return res.status(400).send({ error: 'Query parameter "q" is required' });
    }
    
    try {
        const url = `https://api.giphy.com/v1/gifs/search?api_key=${GIPHY_API_KEY}&q=${encodeURIComponent(query)}&limit=${limit}&rating=g`;
        
        // Χρησιμοποιούμε fetch (απαιτεί Node.js 18+ ή node-fetch)
        const response = await fetch(url); 
        
        if (!response.ok) {
             throw new Error(`Giphy API returned status: ${response.status}`);
        }
        
        const data = await response.json();
        
        const gifUrls = data.data.map(gif => ({
            id: gif.id,
            url: gif.images.fixed_height.url 
        })); 
        
        res.json({ urls: gifUrls });
        
    } catch (error) {
        console.error('Giphy API error:', error.message);
        res.status(500).send({ error: 'Could not fetch GIFs from Giphy.' });
    }
});


// --- WebSockets ---
app.ws('/chat', async (ws, req) => {
    // Ελέγχουμε αν ο χρήστης είναι συνδεδεμένος
    if (!req.isAuthenticated()) {
        ws.close(1008, 'Unauthorized'); // 1008: Policy Violation
        return;
    }

    const userId = req.user.id;
    const displayName = req.user.display_name;
    const role = req.user.role;
    const avatarUrl = req.user.avatar_url;

    // Αποστολή παλιών μηνυμάτων κατά τη σύνδεση
    try {
        const result = await pool.query('SELECT m.id, m.message, m.timestamp, u.display_name, u.role, u.avatar_url, u.id as user_id FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp ASC');
        ws.send(JSON.stringify({ type: 'oldMessages', messages: result.rows }));
    } catch (error) {
        console.error('Error fetching old messages:', error);
    }

    ws.on('message', async (msg) => {
        const messageData = JSON.parse(msg);

        if (messageData.type === 'chatMessage') {
            try {
                // Εισαγωγή μηνύματος
                const result = await pool.query(
                    'INSERT INTO messages (user_id, message) VALUES ($1, $2) RETURNING id, timestamp',
                    [userId, messageData.message]
                );
                const newMessage = result.rows[0];

                // Διαμόρφωση απάντησης
                const response = {
                    type: 'newMessage',
                    displayName,
                    message: messageData.message,
                    timestamp: newMessage.timestamp,
                    role,
                    avatarUrl,
                    userId,
                    messageId: newMessage.id
                };
                
                // Αποστολή σε όλους τους συνδεδεμένους clients
                wsInstance.getWss().clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(response));
                    }
                });
                
            } catch (error) {
                console.error('Error inserting message:', error);
            }
        } else if (messageData.type === 'requestOldMessages') {
             // Αν ζητηθούν ξανά τα μηνύματα (π.χ. μετά την αλλαγή avatar)
             try {
                const result = await pool.query('SELECT m.id, m.message, m.timestamp, u.display_name, u.role, u.avatar_url, u.id as user_id FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp ASC');
                ws.send(JSON.stringify({ type: 'oldMessages', messages: result.rows }));
            } catch (error) {
                console.error('Error fetching old messages for client request:', error);
            }
        }
    });

    ws.on('close', () => {
        console.log(`Ο χρήστης ${displayName} αποσυνδέθηκε`);
    });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});