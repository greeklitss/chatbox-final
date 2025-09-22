const express = require('express');
const http = require('http');
const path = require('path');
const { Pool } = require('pg');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const expressWs = require('express-ws'); // Χρησιμοποιούμε αυτό το module

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
                user = await pool.query('INSERT INTO users (facebook_id, display_name, role) VALUES ($1, $2, $3) RETURNING *', [profile.id, profile.displayName, 'user']);
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

// Χειρισμός συνδέσεων WebSocket
app.ws('/chat', async (ws, req) => {
    const userId = req.session.passport.user;

    console.log(`Νέος χρήστης συνδέθηκε με user ID: ${userId}`);

    // Φόρτωση παλαιότερων μηνυμάτων
    try {
        const result = await pool.query('SELECT m.message, u.display_name, u.role FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp');
        result.rows.forEach(row => {
            const role = row.role === 'admin' ? '[Admin]' : '';
            ws.send(`<strong>${row.display_name} ${role}:</strong> ${row.message}`);
        });
    } catch (error) {
        console.error('Σφάλμα φόρτωσης μηνυμάτων:', error);
    }

    ws.on('message', async message => {
        try {
            const userResult = await pool.query('SELECT display_name, role FROM users WHERE id = $1', [userId]);
            const displayName = userResult.rows[0].display_name;
            const role = userResult.rows[0].role;
            const roleTag = role === 'admin' ? '[Admin]' : '';
            const formattedMessage = `<strong>${displayName} ${roleTag}:</strong> ${message.toString()}`;

            await pool.query('INSERT INTO messages(message, user_id) VALUES($1, $2)', [message.toString(), userId]);
            console.log(`Το μήνυμα αποθηκεύτηκε: ${formattedMessage}`);

            // Στέλνει το μήνυμα σε όλους τους συνδεδεμένους clients
            wsInstance.getWss().clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(formattedMessage);
                }
            });
        } catch (error) {
            console.error("Σφάλμα κατά την αποθήκευση του μηνύματος:", error);
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