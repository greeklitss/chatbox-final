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
});

// Δημιουργία πίνακα μηνυμάτων αν δεν υπάρχει
async function createTable() {
  await pool.query('CREATE TABLE IF NOT EXISTS messages (message TEXT)');
}
createTable();

// Φόρτωση του αρχείου index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

wss.on('connection', async ws => {
  console.log('Νέος χρήστης συνδέθηκε');

  // Φόρτωση παλαιότερων μηνυμάτων
  try {
    const res = await pool.query('SELECT message FROM messages ORDER BY id');
    res.rows.forEach(row => {
      ws.send(row.message);
    });
  } catch (err) {
    console.error('Σφάλμα φόρτωσης μηνυμάτων:', err.stack);
  }

  ws.on('message', async message => {
    const msg = message.toString();
    console.log(`Λάβαμε μήνυμα: ${msg}`);

    // Αποθήκευση του μηνύματος στη βάση δεδομένων
    try {
      await pool.query('INSERT INTO messages(message) VALUES($1)', [msg]);
    } catch (err) {
      console.error('Σφάλμα αποθήκευσης μηνύματος:', err.stack);
    }

    // Στείλε το μήνυμα σε όλους τους συνδεδεμένους χρήστες
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(msg);
      }
    });
  });

  ws.on('close', () => {
    console.log('Ο χρήστης αποσυνδέθηκε');
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Ο server τρέχει στο http://localhost:${PORT}`);
});