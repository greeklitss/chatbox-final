const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Φόρτωση του αρχείου index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

wss.on('connection', ws => {
  console.log('Νέος χρήστης συνδέθηκε');

  ws.on('message', message => {
    const msg = message.toString();
    console.log(`Λάβαμε μήνυμα: ${msg}`);

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