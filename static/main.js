// static/js/main.js - ΔΙΟΡΘΩΜΕΝΟ

document.addEventListener('DOMContentLoaded', () => {
    // 1. ΣΥΝΔΕΣΗ SOCKETIO (ΕΔΩ ΟΡΙΖΕΤΑΙ Η ΜΕΤΑΒΛΗΤΗ socket)
    const socket = io({
        path: '/socket.io/'
    });
    
    // 2. ΛΗΨΗ DOM ΣΤΟΙΧΕΙΩΝ
    const chatbox = document.getElementById('chatbox');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    const notificationSound = new Audio('/static/sounds/notification.mp3');
    notificationSound.volume = 0.5;
    
    // 3. 🚨 ΚΡΙΣΙΜΟ: ΟΛΗ Η ΛΟΓΙΚΗ SOCKETIO ΠΡΕΠΕΙ ΝΑ ΕΙΝΑΙ ΕΔΩ ΜΕΣΑ

    // Σύνδεση με τον Server
    socket.on('connect', () => {
        console.log('Connected to chat server!');
        // 🚨 ΑΠΑΡΑΙΤΗΤΟ: Ειδοποιούμε τον server να μας βάλει στο chat room
        socket.emit('join'); 
    });
    
    // Χειρισμός Νέου Μηνύματος
    // (Χρησιμοποιώ 'message' για να είναι συμβατό με τον server κώδικα που σας έδωσα)
    socket.on('message', function(data) {
        // ... (Λογική για δημιουργία messageDiv και append) ...
        const messageDiv = document.createElement('div');
        const roleClass = `role-${data.role}`; 
        
        const messageHtml = `
            <span class="${roleClass}" style="font-weight: 700;">${data.username}</span> 
            <span style="color: #bbb;">[${data.timestamp}]:</span> 
            ${data.msg} // 🚨 ΧΡΗΣΙΜΟΠΟΙΟΥΜΕ data.msg ΑΝΤΙ data.message
        `;
        
        messageDiv.innerHTML = messageHtml;
        chatbox.appendChild(messageDiv);
        chatbox.scrollTop = chatbox.scrollHeight;

        // Παίζει τον ήχο μόνο αν δεν είναι δικό μας μήνυμα
        // (Η μεταβλητή {{ user.display_name }} δεν λειτουργεί σε εξωτερικό JS. 
        // Πρέπει να οριστεί μια JS μεταβλητή σε ένα <script> στο HTML)
        // Προσωρινά, χρησιμοποιούμε τον έλεγχο που είχατε:
        if (data.username !== '{{ user.display_name }}' && !document.getElementById('toggle-sound').checked) {
             notificationSound.play().catch(e => console.log("Sound play prevented:", e));
        }
    });

    // 4. ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    if (sendButton) {
        sendButton.onclick = function(e) {
            e.preventDefault();
            const msg = messageInput.value.trim();
            if (msg) {
                // 🚨 ΣΩΣΤΗ ΚΛΗΣΗ SOCKET.EMIT
                socket.emit('message', { msg: msg });
                messageInput.value = '';
            }
        };
    }
    
    // ... (Υπόλοιπη λογική για applyFormatting, keydown, κλπ. Πρέπει να είναι και αυτή εδώ μέσα)

    // 🚨 5. ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ ΜΟΡΦΟΠΟΙΗΣΗΣ (Πρέπει να είναι εδώ!)
    function applyFormatting(tag, placeholder) {
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const value = messageInput.value;

        let selectedText = value.substring(start, end);
        if (!selectedText) {
            selectedText = placeholder;
        }

        const newText = value.substring(0, start) + 
                        `[${tag}]` + selectedText + `[/${tag}]` + 
                        value.substring(end);
        
        messageInput.value = newText;
        messageInput.focus();
        messageInput.selectionStart = start + tag.length + 2; 
        messageInput.selectionEnd = messageInput.selectionStart + selectedText.length;
    }

    document.getElementById('bold-button').onclick = () => applyFormatting('b', 'text');
    document.getElementById('italic-button').onclick = () => applyFormatting('i', 'text');
    document.getElementById('underline-button').onclick = () => applyFormatting('u', 'text');
    
    document.getElementById('color-picker-button').onclick = () => {
        colorInput.click();
    };

    colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            // 🚨 ΑΝΤΙ ΓΙΑ sendButton.click(), ΚΑΝΤΕ ΑΠΕΥΘΕΙΑΣ ΤΟ EMIT
            sendButton.onclick({ preventDefault: () => {} }); // Χρησιμοποιούμε τη συνάρτηση onclick
        }
    });
}); // <--- ΤΕΛΙΚΟ ΚΛΕΙΣΙΜΟ DOMContentLoaded