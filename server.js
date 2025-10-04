// server.js (ΠΛΗΡΩΣ ΔΙΟΡΘΩΜΕΝΟ)

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
const axios = require('axios'); // ΝΕΑ ΠΡΟΣΘΗΚΗ: Για την GIPHY API

const app = express();
const server = http.createServer(app);
const wsInstance = expressWs(app, server);

// --- 1. ΚΡΙΣΙΜΟ: ΡΥΘΜΙΣΗ CSP (ΓΙΑ ΤΟ DEPLOYMENT) ---
// Λύνει το σφάλμα 'Refused to compile/unsafe-eval' και επιτρέπει φόρτωση από τρίτους
app.use((req, res, next) => {
    // default-src: 'self' (δική σου σελίδα), data: (π.χ. data:base64 images), https:// (εξωτερικοί πόροι)
    // script-src: 'unsafe-eval' (απαραίτητο για ορισμένες βιβλιοθήκες, αν και ρισκαδόρικο)
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
// ------------------------------

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- ΥΠΟΛΟΙΠΟΣ ΚΩΔΙΚΑΣ (Pool, Session, Passport, Strategies, Auth Routes, Users, Change-Role) ---
// (ΔΕΝ ΑΛΛΑΞΑΝ)

// ... (storage, upload, pool, sessionMiddleware, app.use(sessionMiddleware), passport.initialize(), passport.session(), serialize/deserializeUser, Strategies, createTables, auth routes, users, change-role) ...


// --- ΔΙΟΡΘΩΜΕΝΟ & ΝΕΟ: AVATAR ENDPOINTS ---

// Endpoint 1: Αλλαγή avatar μέσω ΑΡΧΕΙΟΥ (για Local/Ephemeral storage)
app.post('/change-avatar', upload.single('avatar'), async (req, res) => {
    if (!req.isAuthenticated()) { return res.status(401).send('Not authenticated.'); }
    if (!req.file) { return res.status(400).send('No file uploaded.'); }

    const userId = req.user.id;
    const avatarUrl = `/uploads/${req.file.filename}`;
    
    try {
        const result = await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2 RETURNING *', [avatarUrl, userId]);
        const updatedUser = result.rows[0];

        // Ενημέρωση session
        req.login(updatedUser, (err) => { 
            if (err) { return res.status(500).json({ success: false, error: 'Could not update session.', avatarUrl }); }
            res.status(200).json({ success: true, avatarUrl });
        });
        
    } catch (error) {
        console.error('Error updating avatar:', error);
        res.status(500).send('An error occurred while updating avatar.');
    }
});

// Endpoint 2: ΝΕΟ - Αλλαγή avatar μέσω URL (Για Hosting/Μόνιμη λύση 404)
app.post('/change-avatar-url', async (req, res) => {
    if (!req.isAuthenticated()) { return res.status(401).send('Not authenticated.'); }
    const { avatarUrl } = req.body;
    
    if (!avatarUrl || (!avatarUrl.startsWith('http://') && !avatarUrl.startsWith('https://'))) {
        return res.status(400).send('Invalid or missing URL. Must start with http:// or https://.');
    }

    const userId = req.user.id;
    
    try {
        const result = await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2 RETURNING *', [avatarUrl, userId]);
        const updatedUser = result.rows[0];

        // Ενημέρωση session
        req.login(updatedUser, (err) => { 
            if (err) { return res.status(500).json({ success: false, error: 'Could not update session.' }); }
            res.status(200).json({ success: true, avatarUrl });
        });
        
    } catch (error) {
        console.error('Error updating avatar URL:', error);
        res.status(500).send('An error occurred while updating avatar URL.');
    }
});
// -------------------------------------------------------------

// --- ΝΕΟ: GIF SEARCH ENDPOINT (Λύνει το 401) ---
app.get('/search-gifs', async (req, res) => {
    if (!req.isAuthenticated()) { return res.status(401).send('Unauthorized'); }
    const query = req.query.q;
    const GIPHY_API_KEY = process.env.GIPHY_API_KEY; 
    
    if (!query || !GIPHY_API_KEY) {
        return res.status(400).send('Query is required or GIPHY_API_KEY might be missing.');
    }

    try {
        const response = await axios.get('https://api.giphy.com/v1/gifs/search', {
            params: {
                api_key: GIPHY_API_KEY,
                q: query,
                limit: 1 // Παίρνουμε μόνο το πρώτο αποτέλεσμα
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
        res.status(500).json({ success: false, message: 'Failed to fetch GIFs. Check API Key.' });
    }
});
// -------------------------------------------------------------

// --- ΔΙΟΡΘΩΣΗ: DELETE MESSAGE (για το 500/undefined) ---
app.delete('/delete-message/:id', async (req, res) => {
    // Επιτρέπουμε σε admin και moderator
    if (!req.isAuthenticated() || (req.user.role !== 'admin' && req.user.role !== 'moderator')) {
        return res.status(403).send('Forbidden: Only admins and moderators can delete messages.');
    }

    const messageId = req.params.id;
    // ΕΛΕΓΧΟΣ: Εάν το messageId είναι 'undefined' ή μη αριθμητικό (το οποίο είναι το σφάλμα στην εικόνα), επιστρέφουμε 400.
    if (!messageId || isNaN(parseInt(messageId))) {
         return res.status(400).send('Invalid or missing message ID.');
    }

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

// ... (rest of admin/ban/clear history endpoints and WS connection) ...

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`Ο server τρέχει στο http://localhost:${PORT}`);
});