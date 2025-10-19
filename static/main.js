// static/js/main.js - ΤΕΛΙΚΗ ΔΙΟΡΘΩΣΗ ΓΙΑ BBCODE ΚΑΙ ΝΕΟ UI

document.addEventListener('DOMContentLoaded', () => {

    // --- HELPER FUNCTIONS (BBCode Parser) ---
    // 🚨 1. ΠΛΗΡΗΣ BBCode Parser - ΚΡΙΣΙΜΟ για τη μορφοποίηση κειμένου
    function parseBBCode(text) {
        if (!text) return '';
        
        // 1. [b] -> <strong>
        text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<strong>$1</strong>');
        
        // 2. [i] -> <em>
        text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<em>$1</em>');
        
        // 3. [color=#hex] -> <span style="color:#hex;">
        text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');
    
        // 4. [url] -> <a> (Εάν χρησιμοποιείται)
        text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>');
        
        // 5. [img] -> <img> (Εάν χρησιμοποιείται)
        text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" alt="Image" style="max-width:100%; height:auto;">');

        return text;
    }

    // --- HELPER FUNCTIONS (Message Renderer) ---
    // 🚨 2. ΕΠΑΝΑΓΡΑΦΗ: Εμφάνιση μηνύματος με τη νέα δομή του chat.html
    function appendMessage(msg) {
        // Ελέγχουμε αν το chatbox υπάρχει
        if (!chatbox) return; 

        const messageContainer = document.createElement('div');
        messageContainer.className = 'message-container';
        
        // --- Avatar ---
        const avatar = document.createElement('img');
        avatar.className = 'avatar';
        // Προσοχή: Επειδή είναι JS αρχείο, δεν μπορούμε να χρησιμοποιήσουμε url_for. Υποθέτουμε ότι το default είναι στο /static/default_avatar.png
        avatar.src = msg.avatar_url || '/static/default_avatar.png';
        avatar.alt = `${msg.username}'s avatar`;

        // --- Content Wrapper ---
        const messageContentDiv = document.createElement('div');
        messageContentDiv.className = 'message-content';
        messageContentDiv.classList.add(msg.role || 'user'); // Προσθήκη κλάσης ρόλου

        // Header (Username + Timestamp)
        const messageHeader = document.createElement('div');
        messageHeader.className = 'message-header';

        const usernameSpan = document.createElement('span');
        usernameSpan.className = 'username';
        usernameSpan.textContent = msg.username;

        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'timestamp';
        const date = msg.timestamp ? new Date(msg.timestamp) : new Date();
        timestampSpan.textContent = `[${date.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}]`;

        messageHeader.appendChild(usernameSpan);
        messageHeader.appendChild(timestampSpan);
        
        // Message Box (Το κείμενο)
        const messageBox = document.createElement('div');
        messageBox.className = 'message-box';
        // 🚨 ΚΡΙΣΙΜΟ: Εφαρμογή του BBCode Parser
        messageBox.innerHTML = parseBBCode(msg.content || msg.message || msg.msg); 

        // Δόμηση του μηνύματος
        messageContentDiv.appendChild(messageHeader);
        messageContentDiv.appendChild(messageBox);

        messageContainer.appendChild(avatar);
        messageContainer.appendChild(messageContentDiv);

        chatbox.appendChild(messageContainer);
        chatbox.scrollTop = chatbox.scrollHeight;
    }


    // --- ΒΑΣΙΚΕΣ ΜΕΤΑΒΛΗΤΕΣ DOM ---
    // 🚨 3. ΔΙΟΡΘΩΣΗ: Το ID του chat area στο HTML είναι 'chat-messages'
    const chatbox = document.getElementById('chat-messages'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input'); 
    const audioStream = document.getElementById('audio-stream'); // Το ράδιο
    
    // --- ΛΟΓΙΚΗ COOKIE/SOCKETIO ---
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`); 
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
    const sessionId = getCookie('session');

    // 🚨 4. ΣΩΣΤΗ ΣΥΝΔΕΣΗ SOCKETIO
    const socket = io({
        path: '/socket.io/',
        query: {
             session_id: sessionId 
        }
    });
    
    // --- ΛΟΓΙΚΗ AUDIO ---
    if (audioStream) {
        audioStream.volume = 0.3; 
        audioStream.load();
        // Το Play πρέπει να γίνει από τον χρήστη, αλλά το volume είναι ρυθμισμένο.
    }
    
    // ----------------------------------------------------
    // 5. 🟢 ΛΟΓΙΚΗ SOCKETIO
    // ----------------------------------------------------

    socket.on('connect', () => {
        console.log('Connected to chat server!');
        socket.emit('join'); 
    });
    
    // Listener για νέα μηνύματα
    socket.on('message', function(data) {
        appendMessage(data);
    });
    
    // Listener για το ιστορικό μηνυμάτων
    socket.on('history', function(messages) {
        if (chatbox) chatbox.innerHTML = ''; // Καθαρισμός πριν τη φόρτωση
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
    // 6. 🟢 ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ / ΦΟΡΜΑΣ
    // ----------------------------------------------------

    function applyFormatting(tag, placeholder) {
        // Λογική μορφοποίησης κειμένου (παραμένει σωστή)
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const value = messageInput.value;

        let selectedText = value.substring(start, end);
        if (!selectedText) {
            selectedText = placeholder;
        }
        
        // Ειδικός χειρισμός για [color]
        const prefix = tag.startsWith('color=') ? `[${tag}]` : `[${tag}]`;
        const suffix = tag.startsWith('color=') ? `[/color]` : `[/${tag.replace('color=', '').split(' ')[0]}]`; // Διορθωμένο suffix

        const newText = value.substring(0, start) + 
                        prefix + selectedText + suffix + 
                        value.substring(end);
        
        messageInput.value = newText;
        messageInput.focus();
        // Επαναφορά cursor στη θέση που πρέπει
        messageInput.selectionStart = start + prefix.length; 
        messageInput.selectionEnd = messageInput.selectionStart + selectedText.length;
    }

    // Handlers για τα κουμπιά
    if (document.getElementById('bold-button')) document.getElementById('bold-button').onclick = () => applyFormatting('b', 'bold text');
    if (document.getElementById('italic-button')) document.getElementById('italic-button').onclick = () => applyFormatting('i', 'italic text');
    
    if (document.getElementById('color-picker-button')) document.getElementById('color-picker-button').onclick = () => {
        if (colorInput) colorInput.click();
    };

    if (colorInput) colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    // ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    if (sendButton) {
        const sendMessage = () => {
            const msg = messageInput.value.trim();
            if (msg) {
                socket.emit('message', { msg: msg });
                messageInput.value = '';
                // Αυτόματη προσαρμογή ύψους
                messageInput.style.height = 'auto'; 
            }
        };

        sendButton.addEventListener('click', (e) => {
            e.preventDefault();
            sendMessage();
        });

        // Λειτουργία αποστολής με Enter
        if (messageInput) {
            messageInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                }
            });
            
            // Αυτόματη προσαρμογή ύψους του textarea
            messageInput.addEventListener('input', () => {
                messageInput.style.height = 'auto';
                // Περιορισμός στο μέγιστο ύψος (π.χ. 100px)
                messageInput.style.height = (Math.min(messageInput.scrollHeight, 100)) + 'px';
            });
        }
    }
});