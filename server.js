const express = require('express');
const http = require('http');
const path = require('path');
const { Pool } = require('pg');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const expressWs = require('express-ws'); // Χρησιμοποιούμε αυτό το module
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);

// Ενσωμάτωση του express-ws
const wsInstance = expressWs(app, server);

// Σύνδεση με τη βάση δεδομένων PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Ρύθμιση Session
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || 'mysecret',
    resave: false,
    saveUninitialized: false
});
app.use(sessionMiddleware);

// Ρύθμιση Passport
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json()); // Για να μπορούμε να διαβάσουμε JSON από τα αιτήματα POST

// Passport Serializer/Deserializer
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (error) {
        done(error);
    }
});

// Ρύθμιση Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await pool.query('SELECT * FROM users WHERE google_id = $1', [profile.id]);
            if (user.rows.length === 0) {
                user = await pool.query('INSERT INTO users (google_id, display_name, role) VALUES ($1, $2, $3) RETURNING *', [profile.id, profile.displayName, 'user']);
            }
            done(null, user.rows[0]);
        } catch (error) {
            done(error);
        }
    }
));

// Ρύθμιση Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    callbackURL: "/auth/facebook/callback",
    profileFields: ['id', 'displayName']
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await pool.query('SELECT * FROM users WHERE facebook_id = $1', [profile.id]);
            if (user.rows.length === 0) {
                user = await pool.query('INSERT INTO users (facebook_id, display_name, role) VALUES ($1, $2, \'user\') RETURNING *', [profile.id, profile.displayName]);
            }
            done(null, user.rows[0]);
        } catch (error) {
            done(error);
        }
    }
));

// Δημιουργία πινάκων χρηστών και μηνυμάτων
async function createTables() {
    try {
        await pool.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, google_id TEXT UNIQUE, facebook_id TEXT UNIQUE, display_name TEXT, role TEXT DEFAULT \'user\')');
        await pool.query('CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, message TEXT NOT NULL, user_id INTEGER REFERENCES users(id), timestamp TIMESTAMPTZ DEFAULT NOW())');
        console.log('Οι πίνακες "users" και "messages" δημιουργήθηκαν/ενημερώθηκαν επιτυχώς.');
    } catch (error) {
        console.error('Σφάλμα κατά τη δημιουργία των πινάκων:', error);
    }
}
createTables();

// Routes για τον έλεγχο ταυτότητας
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => { res.redirect('/chat'); });
app.get('/auth/facebook', passport.authenticate('facebook'));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => { res.redirect('/chat'); });

// Main Route
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/chat');
    } else {
        res.sendFile(path.join(__dirname, 'login.html'));
    }
});

// Route για το chatbox
app.get('/chat', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'chat.html'));
    } else {
        res.redirect('/');
    }
});

// Νέος route για αποσύνδεση
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        }
        res.status(200).send('Logged out successfully.');
    });
});

// Νέος route για να ορίσουμε χρήστη ως admin
app.post('/set-admin', async (req, res) => {
    // Έλεγχος αν ο συνδεδεμένος χρήστης είναι ήδη admin
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).send('Forbidden: Only admins can perform this action.');
    }

    const { userId } = req.body;
    if (!userId) {
        return res.status(400).send('User ID is required.');
    }

    try {
        await pool.query('UPDATE users SET role = \'admin\' WHERE id = $1', [userId]);
        res.status(200).send('User role updated to admin.');
    } catch (error) {
        console.error('Error setting user as admin:', error);
        res.status(500).send('An error occurred.');
    }
});

// Νέος route για διαγραφή μηνυμάτων
app.delete('/delete-message/:messageId', async (req, res) => {
    // Έλεγχος αν ο συνδεδεμένος χρήστης είναι admin
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).send('Forbidden: Only admins can delete messages.');
    }

    const { messageId } = req.params;
    try {
        await pool.query('DELETE FROM messages WHERE id = $1', [messageId]);
        // Ενημέρωση όλων των clients ότι το μήνυμα διαγράφηκε
        wsInstance.getWss().clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ type: 'deleteMessage', messageId: messageId }));
            }
        });
        res.status(200).send('Message deleted.');
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).send('An error occurred.');
    }
});

// Χειρισμός συνδέσεων WebSocket
app.ws('/chat', async (ws, req) => {
    const userId = req.session.passport.user;
    const user = req.session.user;

    // Load old messages
    try {
        const result = await pool.query('SELECT m.id, m.message, m.timestamp, u.display_name, u.role, u.id as user_id FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp ASC');
        ws.send(JSON.stringify({ type: 'oldMessages', messages: result.rows }));
    } catch (error) {
        console.error('Error fetching old messages:', error);
    }

    ws.on('message', async (msg) => {
        const messageData = JSON.parse(msg);
        if (messageData.type === 'chatMessage') {
            const { message } = messageData;
            try {
                const result = await pool.query('INSERT INTO messages (user_id, message) VALUES ($1, $2) RETURNING *', [userId, message]);
                const newMessage = result.rows[0];

                const userResult = await pool.query('SELECT display_name, role FROM users WHERE id = $1', [userId]);
                const displayName = userResult.rows[0].display_name;
                const role = userResult.rows[0].role;
                
                const response = {
                    type: 'newMessage',
                    message: newMessage.message,
                    displayName,
                    timestamp: newMessage.timestamp,
                    role,
                    userId,
                    messageId: newMessage.id
                };
                
                // Broadcast to all connected clients
                wsInstance.getWss().clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(response));
                    }
                });
                
            } catch (error) {
                console.error('Error inserting message:', error);
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