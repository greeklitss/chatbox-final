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

const app = express();
const server = http.createServer(app); 
const wsInstance = expressWs(app, server); 



// --- DYNAMIC SETTINGS FROM DB ---
let appSettings = {};

// Συνάρτηση για τη φόρτωση των ρυθμίσεων από τη βάση δεδομένων
async function loadSettings() {
    try {
        const result = await pool.query('SELECT key, value FROM settings');
        appSettings = result.rows.reduce((acc, row) => {
            // Μετατροπή των τιμών στον σωστό τύπο (π.χ. 'true' -> true, '0.85' -> 0.85)
            let parsedValue = row.value;
            if (row.value === 'true') parsedValue = true;
            else if (row.value === 'false') parsedValue = false;
            // Μετατροπή σε float μόνο για ρυθμίσεις διαφάνειας (opacity)
            else if (!isNaN(parseFloat(row.value)) && isFinite(row.value) && row.key.includes('opacity')) {
                parsedValue = parseFloat(row.value);
            }
            acc[row.key] = parsedValue;
            return acc;
        }, {});
        console.log('Οι ρυθμίσεις της εφαρμογής φορτώθηκαν επιτυχώς:', appSettings);
    } catch (error) {
        console.error('Σφάλμα κατά τη φόρτωση ρυθμίσεων από τη βάση:', error);
        // Χρησιμοποίησε default values αν αποτύχει η φόρτωση
        appSettings = {
            message_opacity: 0.85,
            input_row_opacity: 0.90,
            top_bar_opacity: 0.95,
            default_font_color: '#E0E0E0',
            allow_gif_searches: true,
            app_title: 'Chat App'
        };
    }
}

// Καλούμε τη συνάρτηση για να φορτώσει τις ρυθμίσεις αμέσως
loadSettings();
// --- END DYNAMIC SETTINGS ---

// --- ΣΗΜΑΝΤΙΚΗ ΔΙΟΡΘΩΣΗ: STATIC FILES ---
// 1. Εξυπηρετεί όλα τα αρχεία στον root φάκελο (chat.html, login.html, akoyme_background.png)
app.use(express.static(__dirname));

// Δημιουργία του φακέλου 'uploads' αν δεν υπάρχει (Πρέπει να γίνει πριν την χρήση του)
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// 2. Εξυπηρετεί τον φάκελο uploads για τα avatar
app.use('/uploads', express.static('uploads'));
// ----------------------------------------

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Εγκατάσταση του multer για αποθήκευση εικόνων
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = uuidv4();
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

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
app.use(sessionMiddleware);

app.use(passport.initialize());
app.use(passport.session());

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

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
},
    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await pool.query('SELECT * FROM users WHERE google_id = $1', [profile.id]);
            if (user.rows.length === 0) {
                user = await pool.query('INSERT INTO users (google_id, display_name, role, avatar_url) VALUES ($1, $2, $3, $4) RETURNING *', [profile.id, profile.displayName, 'user', '/uploads/default-avatar.png']);
            }
            done(null, user.rows[0]);
        } catch (error) {
            done(error);
        }
    }
));

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
                user = await pool.query('INSERT INTO users (facebook_id, display_name, role, avatar_url) VALUES ($1, $2, \'user\', $3) RETURNING *', [profile.id, profile.displayName, '/uploads/default-avatar.png']);
            }
            done(null, user.rows[0]);
        } catch (error) {
            done(error);
        }
    }
));

passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return done(null, false, { message: 'Incorrect username.' });
        }
        const user = result.rows[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Incorrect password.' });
        }

        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

async function createTables() {
    try {
        // Ενημέρωση του πίνακα users με το πεδίο avatar_url
        await pool.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, google_id TEXT UNIQUE, facebook_id TEXT UNIQUE, display_name TEXT, role TEXT DEFAULT \'user\', username TEXT UNIQUE, password TEXT, avatar_url TEXT)');
        await pool.query('CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, message TEXT NOT NULL, user_id INTEGER REFERENCES users(id), timestamp TIMESTAMPTZ DEFAULT NOW())');
        // Προσθήκη του avatar_url αν δεν υπάρχει ήδη
        await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT');
        // Set default avatar for existing users if the column was just added
        await pool.query('UPDATE users SET avatar_url = $1 WHERE avatar_url IS NULL', ['/uploads/default-avatar.png']);
        
        console.log('Οι πίνακες "users" και "messages" δημιουργήθηκαν/ενημερώθηκαν επιτυχώς.');
    } catch (error) {
        console.error('Σφάλμα κατά τη δημιουργία των πινάκων:', error);
    }
}
createTables();

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => { res.redirect('/chat'); });
app.get('/auth/facebook', passport.authenticate('facebook'));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => { res.redirect('/chat'); });

app.post('/direct-login', passport.authenticate('local', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/chat');
});

app.get('/user-info', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            id: req.user.id,
            displayName: req.user.display_name,
            role: req.user.role,
            avatarUrl: req.user.avatar_url
        });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

app.get('/users', async (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    try {
        // ΔΙΟΡΘΩΣΗ: Εξαίρεση του password από το αποτέλεσμα
        const result = await pool.query('SELECT id, display_name, role FROM users ORDER BY display_name');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('An error occurred.');
    }
});

app.post('/change-role', async (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    const { userId, newRole } = req.body;
    if (!userId || !newRole) {
        return res.status(400).send('User ID and new role are required.');
    }
    try {
        await pool.query('UPDATE users SET role = $1 WHERE id = $2', [newRole, userId]);
        res.status(200).send('User role updated successfully.');
    } catch (error) {
        console.error('Error changing user role:', error);
        res.status(500).send('An error occurred.');
    }
});

// Endpoint για αλλαγή avatar
app.post('/change-avatar', upload.single('avatar'), async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).send('Not authenticated.');
    }
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const userId = req.user.id;
    const newAvatarUrl = `/uploads/${req.file.filename}`;
    
    try {
        // 1. Βρες το παλιό avatar url για διαγραφή
        const oldUserResult = await pool.query('SELECT avatar_url FROM users WHERE id = $1', [userId]);
        const oldAvatarUrl = oldUserResult.rows[0].avatar_url;
        
        // 2. Ενημέρωσε τη βάση με το νέο
        await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [newAvatarUrl, userId]);
        
        // 3. Διέγραψε το παλιό αρχείο, αν δεν είναι το default
        if (oldAvatarUrl && oldAvatarUrl !== '/uploads/default-avatar.png') {
             // Το path του αρχείου είναι το path χωρίς το /uploads
             const fileNameToDelete = oldAvatarUrl.replace('/uploads/', '');
             const fullPathToDelete = path.join(__dirname, 'uploads', fileNameToDelete);

             if (fs.existsSync(fullPathToDelete)) {
                 fs.unlink(fullPathToDelete, (err) => {
                     if (err) console.error('Error deleting old avatar file:', err);
                 });
             }
        }

        // Ενημέρωση του req.user για το τρέχον session
        req.user.avatar_url = newAvatarUrl;
        
        res.status(200).json({ success: true, avatarUrl: newAvatarUrl });
    } catch (error) {
        console.error('Error updating avatar:', error);
        res.status(500).send('An error occurred while updating avatar.');
    }
});

app.delete('/clear-history', async (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    try {
        await pool.query('DELETE FROM messages');
        wsInstance.getWss().clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ type: 'clearChat' }));
            }
        });
        res.status(200).send('Chat history cleared successfully.');
    } catch (error) {
        console.error('Error clearing chat history:', error);
        res.status(500).send('An error occurred.');
    }
});

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/chat');
    } else {
        res.sendFile(path.join(__dirname, 'login.html'));
    }
});

app.get('/chat', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'chat.html'));
    } else {
        res.redirect('/');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Could not log out.');
        }
        res.status(200).send('Logged out successfully.');
    });
});

app.post('/create-user', async (req, res) => {
    const { username, password, displayName } = req.body;
    if (!username || !password || !displayName) {
        return res.status(400).send('Username, password, and display name are required.');
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, display_name, role, avatar_url) VALUES ($1, $2, $3, \'user\', $4)', [username, hashedPassword, displayName, '/uploads/default-avatar.png']);
        res.status(201).send('User created successfully.');
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).send('Username already exists.');
        }
        console.error('Error creating user:', error);
        res.status(500).send('An error occurred.');
    }
});

app.delete('/delete-message/:id', async (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(403).send('Forbidden: Only admins can delete messages.');
    }

    const messageId = req.params.id;

    try {
        const result = await pool.query('DELETE FROM messages WHERE id = $1 RETURNING *', [messageId]);
        
        if (result.rowCount === 0) {
            return res.status(404).send('Message not found.');
        }

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

// Endpoint για να δώσει τις ρυθμίσεις στον client (chat.html)
app.get('/api/settings', (req, res) => {
    // Επιστρέφει τις ρυθμίσεις που έχουν ήδη φορτωθεί στη μνήμη του server
    res.json(appSettings);
});

// Endpoint για ενημέρωση ρυθμίσεων (Απαιτείται Admin role)
app.post('/api/settings', async (req, res) => {
    // *ΣΗΜΕΙΩΣΗ: Εάν δεν έχεις ρόλους ακόμα, μπορείς να αφαιρέσεις το '|| req.user.role !== 'admin'' προσωρινά.*
    if (!req.isAuthenticated()) {
        return res.status(403).send('Access denied. Login required.');
    }
    
    // Εάν το role δεν υπάρχει ακόμα, απλώς ελέγχουμε το login
    if (req.user && req.user.role && req.user.role !== 'admin') {
         return res.status(403).send('Access denied. Admin role required.');
    }
    
    const { key, value } = req.body;
    if (!key || value === undefined) {
        return res.status(400).send('Missing key or value.');
    }

    try {
        await pool.query('UPDATE settings SET value = $1 WHERE key = $2', [value, key]);
        
        // Επαναφόρτωση των ρυθμίσεων στη μνήμη για να ενημερωθούν όλοι οι χρήστες
        await loadSettings(); 
        
        res.status(200).send('Settings updated successfully. Changes applied.');
    } catch (error) {
        console.error('Error updating setting:', error);
        res.status(500).send('Internal server error during settings update.');
    }
});

app.ws('/chat', async (ws, req) => {
    // ΔΙΟΡΘΩΣΗ: Πρέπει να αποθηκεύσουμε τα user info στο ws session 
    // για να είναι διαθέσιμα σε άλλα events (όπως deleteMessage)
    if (!req.isAuthenticated()) {
        ws.close();
        return;
    }
    ws.userId = req.user.id;
    ws.userRole = req.user.role;
    
    // Στέλνει τα παλιά μηνύματα κατά τη σύνδεση
    try {
        const result = await pool.query('SELECT m.id, m.message, m.timestamp, u.display_name, u.role, u.avatar_url, u.id as user_id FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp ASC');
        ws.send(JSON.stringify({ type: 'oldMessages', messages: result.rows }));
    } catch (error) {
        console.error('Error fetching old messages:', error);
    }

    ws.on('message', async (msg) => {
        const messageData = JSON.parse(msg);
        if (messageData.type === 'chatMessage') {
            const { message } = messageData;
            try {
                const result = await pool.query('INSERT INTO messages (user_id, message) VALUES ($1, $2) RETURNING *', [req.user.id, message]);
                const newMessage = result.rows[0];

                const userResult = await pool.query('SELECT display_name, role, avatar_url FROM users WHERE id = $1', [req.user.id]);
                const { display_name, role, avatar_url } = userResult.rows[0];
                
                const response = {
                    type: 'newMessage',
                    message: newMessage.message,
                    displayName: display_name,
                    timestamp: newMessage.timestamp,
                    role,
                    avatarUrl: avatar_url,
                    userId: req.user.id,
                    messageId: newMessage.id
                };
                
                wsInstance.getWss().clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(response));
                    }
                });
                
            } catch (error) {
                console.error('Error inserting message:', error);
            }
        } else if (messageData.type === 'requestOldMessages') {
             // Αν ζητηθούν ξανά τα μηνύματα (π.χ. μετά το φόρτωμα του ρόλου του admin)
             try {
                const result = await pool.query('SELECT m.id, m.message, m.timestamp, u.display_name, u.role, u.avatar_url, u.id as user_id FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.timestamp ASC');
                ws.send(JSON.stringify({ type: 'oldMessages', messages: result.rows }));
            } catch (error) {
                console.error('Error fetching old messages for client request:', error);
            }
        }
    });

    ws.on('close', () => {
        console.log(`Ο χρήστης ${ws.userId} αποσυνδέθηκε`);
    });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`Ο server τρέχει στο http://localhost:${PORT}`);
});