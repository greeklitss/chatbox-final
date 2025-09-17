const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { Pool } = require('pg');

const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Σύνδεση με τη βάση δεδομένων PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Ρύθμιση Session
app.use(session({
    secret: 'mysecret', // Βάλε ένα δικό σου μυστικό κλειδί
    resave: false,
    saveUninitialized: false
}));

// Ρύθμιση Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport Serializer/Deserializer για αποθήκευση του χρήστη στη συνεδρία
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
                // Νέος χρήστης, τον αποθηκεύουμε στη βάση δεδομένων
                user = await pool.query('INSERT INTO users (google_id, display_name) VALUES ($1, $2) RETURNING *', [profile.id, profile.displayName]);
            }
            done(null, user.rows[0]);
        } catch (error) {
            done(error);
        }
    }
));

// Δημιουργία πίνακα χρηστών και μηνυμάτων
async function createTables() {
    try {
        await pool.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, google_id TEXT UNIQUE, display_name TEXT)');
        await pool.query('CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, message TEXT NOT NULL, user_id INTEGER REFERENCES users(id), timestamp TIMESTAMPTZ DEFAULT NOW())');
        console.log('Οι πίνακες "users" και "messages" δημιουργήθηκαν επιτυχώς.');
    } catch (error) {
        console.error('Σφάλμα κατά τη δημιουργία των πινάκων:', error);
    }
}
createTables();

// Routes για τον έλεγχο ταυτότητας
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/');
    });

// Middleware για τον έλεγχο αν ο χρήστης είναι συνδεδεμένος
app.get('/', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.send('<a href="/auth/google">Σύνδεση με Google</a>');
    }
    // Αν ο χρήστης είναι συνδεδεμένος, φόρτωσε το chat
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Χειρισμός συνδέσεων WebSocket
wss.on('connection', async ws => {
    console.log('Νέος χρήστης συνδέθηκε');

    // Φόρτωση παλαιότερων μηνυμάτων
    try {
        const result = await pool.query('SELECT m.message, u.display_name FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp');
        result.rows.forEach(row => {
            ws.send(`${row.display_name}: ${row.message}`);
        });
    } catch (error) {
        console.error('Σφάλμα φόρτωσης μηνυμάτων:', error);
    }

    ws.on('message', async message => {
        try {
            const userId = ws.userId; // Θα πρέπει να αποθηκεύσεις το ID του χρήστη
            const formattedMessage = message.toString();

            // Αποθήκευση του μηνύματος στη βάση δεδομένων
            await pool.query('INSERT INTO messages(message, user_id) VALUES($1, $2)', [formattedMessage, userId]);
            console.log(`Το μήνυμα αποθηκεύτηκε: ${formattedMessage}`);

            // Στείλε το μήνυμα σε όλους τους συνδεδεμένους χρήστες
            wss.clients.forEach(client => {
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