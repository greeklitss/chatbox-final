const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { Pool } = require('pg');

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

// Αυτόματη δημιουργία πίνακα μηνυμάτων κατά την εκκίνηση
async function createTable() {
    try {
        await pool.query('CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, message TEXT NOT NULL)');
        console.log('Ο πίνακας "messages" δημιουργήθηκε επιτυχώς.');
    } catch (error) {
        console.error('Σφάλμα κατά τη δημιουργία του πίνακα:', error);
    }
}
createTable();

// Φόρτωση του αρχείου index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Χειρισμός συνδέσεων WebSocket
wss.on('connection', async ws => {
    console.log('Νέος χρήστης συνδέθηκε');

    // Φόρτωση παλαιότερων μηνυμάτων
    try {
        const result = await pool.query('SELECT message FROM messages ORDER BY id');
        result.rows.forEach(row => {
            ws.send(row.message);
        });
    } catch (error) {
        console.error('Σφάλμα φόρτωσης μηνυμάτων:', error);
    }

    ws.on('message', async message => {
        try {
            const formattedMessage = message.toString();
            // Αποθήκευση του μηνύματος στη βάση δεδομένων
            await pool.query('INSERT INTO messages(message) VALUES($1)', [formattedMessage]);
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