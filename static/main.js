// static/js/main.js - ΟΡΙΣΤΙΚΑ ΔΙΟΡΘΩΜΕΝΟ

document.addEventListener('DOMContentLoaded', () => {

    // Helper function to append a single message to the chatbox
    function appendMessage(data) {
        const messageDiv = document.createElement('div');
        // Χρησιμοποιούμε role από το data του server
        const roleClass = `role-${data.role || 'user'}`; 
        
        // Δημιουργία κειμένου με χρωματισμένο username
        const messageHtml = `
            <span class="${roleClass}" style="font-weight: 700;">${data.username}</span> 
            <span style="color: #bbb;">[${new Date(data.timestamp).toLocaleTimeString()}]:</span> 
            ${data.msg || data.message} 
        `;
        
        messageDiv.innerHTML = messageHtml;
        chatbox.appendChild(messageDiv);
        
        // Μετακίνηση στο κάτω μέρος
        chatbox.scrollTop = chatbox.scrollHeight;
    }

    // 🚨 1. ΛΟΓΙΚΗ ΑΝΑΚΤΗΣΗΣ COOKIE (ΠΡΙΝ ΤΗ ΣΥΝΔΕΣΗ SOCKET)
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        // Το session cookie του Flask-Session ονομάζεται συνήθως 'session'
        const parts = value.split(`; ${name}=`); 
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
    const sessionId = getCookie('session'); // Ανάκτηση του session ID

    // 🚨 2. ΣΩΣΤΗ ΣΥΝΔΕΣΗ SOCKETIO (ΜΕΤΑ ΤΟ SESSION ID)
    const socket = io({
        path: '/socket.io/',
        // ΚΡΙΣΙΜΟ: Στέλνουμε το session ID στον server
        query: {
             session_id: sessionId 
        }
    });
    
    // 3. ΟΡΙΣΜΟΣ ΣΤΟΙΧΕΙΩΝ DOM
    const chatbox = document.getElementById('chatbox');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input'); 
    // Έλεγχος για το audio, καθώς είναι στο chat.html
    const notificationSound = new Audio('/static/sounds/notification.mp3'); 
    notificationSound.volume = 0.5;

    // ----------------------------------------------------
    // 4. 🟢 ΟΛΗ Η ΛΟΓΙΚΗ SOCKETIO ΕΙΝΑΙ ΕΔΩ ΜΕΣΑ
    // ----------------------------------------------------

    // Σύνδεση με τον Server
    socket.on('connect', () => {
        console.log('Connected to chat server!');
        // Ειδοποιούμε τον server να μας βάλει στο chat room και να στείλει ιστορικό
        socket.emit('join'); 
    });
    
    // 🚨 Listener για νέα μηνύματα
    socket.on('message', function(data) {
        appendMessage(data);

        // Παίζει τον ήχο μόνο αν δεν είναι δικό μας μήνυμα
        // Χρησιμοποιούμε το display_name που έρχεται από το Jinja στο chat.html
        if (data.username !== '{{ user.display_name }}' && document.getElementById('toggle-sound') && !document.getElementById('toggle-sound').checked) {
             notificationSound.play().catch(e => console.log("Sound play prevented:", e));
        }
    });
    
    // 🚨 ΚΡΙΣΙΜΟ: Listener για το ιστορικό μηνυμάτων
    socket.on('history', function(messages) {
        // Εμφάνιση των μηνυμάτων
        messages.forEach(msg => {
            appendMessage(msg);
        });
        console.log(`Loaded ${messages.length} messages of history.`);
    });
    
    // Listener για status messages (π.χ. 'User joined')
    socket.on('status_message', function(data) {
        appendMessage({
             username: 'System', 
             msg: data.msg, 
             role: 'system', 
             timestamp: new Date()
        });
    });


    // ----------------------------------------------------
    // 5. 🟢 ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ / ΦΟΡΜΑΣ
    // ----------------------------------------------------

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

    // Handlers για τα κουμπιά
    if (document.getElementById('bold-button')) document.getElementById('bold-button').onclick = () => applyFormatting('b', 'text');
    if (document.getElementById('italic-button')) document.getElementById('italic-button').onclick = () => applyFormatting('i', 'text');
    if (document.getElementById('underline-button')) document.getElementById('underline-button').onclick = () => applyFormatting('u', 'text');
    
    if (document.getElementById('color-picker-button')) document.getElementById('color-picker-button').onclick = () => {
        if (colorInput) colorInput.click();
    };

    if (colorInput) colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    // ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    if (sendButton) {
        sendButton.addEventListener('click', (e) => {
            e.preventDefault();
            const msg = messageInput.value.trim();
            if (msg) {
                socket.emit('message', { msg: msg });
                messageInput.value = '';
            }
        });
    }

    // Λειτουργία αποστολής με Enter
    if (messageInput) {
        messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (sendButton) {
                    sendButton.click();
                }
            }
        });
    }

});