// static/js/main.js - ΤΕΛΙΚΗ ΔΙΟΡΘΩΣΗ ΓΙΑ BBCODE, ΝΕΟ UI ΚΑΙ ΛΟΓΙΚΗ ΗΧΟΥ

let isNotificationSoundEnabled = true;

// 0. ΣΥΝΑΡΤΗΣΗ ΗΧΟΥ ΕΙΔΟΠΟΙΗΣΗΣ
function playNotificationSound() {
    if (!isNotificationSoundEnabled) return;
    try {
        // 🚨 Βεβαιωθείτε ότι υπάρχει το αρχείο static/sounds/notification.mp3
        const audio = new Audio('/static/sounds/notification.mp3'); 
        audio.volume = 0.5; 
        audio.play().catch(e => console.log("Notification audio blocked by browser:", e));
    } catch (error) {
        console.error("Error playing notification sound:", error);
    }
}

document.addEventListener('DOMContentLoaded', () => {

    // --- HELPER FUNCTIONS (BBCode Parser) ---
    function parseBBCode(text) {
        if (!text) return '';
        
        text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<strong>$1</strong>');
        text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<em>$1</em>');
        text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');
        text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>');
        text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" alt="Image" style="max-width:100%; height:auto;">');
        
        // Καθαρισμός τυχόν tags που δεν υποστηρίζονται (π.χ. [u])
        text = text.replace(/\[\/?(u|emoticon)[^\]]*\]/g, '');
        
        return text;
    }

    // --- HELPER FUNCTIONS (Message Renderer) ---
    function appendMessage(msg) {
        // 🚨 ΔΙΟΡΘΩΣΗ: Χρησιμοποιούμε 'chat-box' όπως στο chat.html
        if (!chatbox) return; 

        const messageContainer = document.createElement('div');
        messageContainer.className = 'message-container';
        
        // --- Avatar ---
        const avatar = document.createElement('img');
        avatar.className = 'avatar';
        avatar.src = msg.avatar_url || '/static/default_avatar.png';
        avatar.alt = `${msg.username}'s avatar`;

        // --- Content Wrapper ---
        const messageContentDiv = document.createElement('div');
        messageContentDiv.className = 'message-content';
        messageContentDiv.classList.add(msg.role || 'user'); 

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
    const chatbox = document.getElementById('chat-box'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input'); 
    const audioStream = document.getElementById('audio-stream'); 
    const notificationButton = document.getElementById('notification-volume-button'); // Το κουμπί ήχου
    
    // --- ΛΟΓΙΚΗ COOKIE/SOCKETIO ---
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`); 
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
    const sessionId = getCookie('session');

    // ΣΩΣΤΗ ΣΥΝΔΕΣΗ SOCKETIO
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
    }
    
    // ----------------------------------------------------
    // 5. 🟢 ΛΟΓΙΚΗ SOCKETIO
    // ----------------------------------------------------

    socket.on('connect', () => {
        console.log('Connected to chat server!');
        socket.emit('join'); 
    });
    
    // 🚨 ΔΙΟΡΘΩΣΗ: Listener για νέα μηνύματα (πρέπει να είναι 'new_message' και να καλεί τον ήχο)
    socket.on('new_message', function(data) {
        appendMessage(data);
        playNotificationSound(); // Κλήση ήχου
    });
    
    // Listener για το ιστορικό μηνυμάτων
    socket.on('history', function(messages) {
        if (chatbox) chatbox.innerHTML = '';
        messages.forEach(msg => {
            appendMessage(msg);
        });
        console.log(`Loaded ${messages.length} messages of history.`);
    });
    
    // Listener για status messages
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
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const value = messageInput.value;

        let selectedText = value.substring(start, end);
        if (!selectedText) {
            selectedText = placeholder;
        }
        
        const prefix = tag.startsWith('color=') ? `[${tag}]` : `[${tag}]`;
        const suffix = tag.startsWith('color=') ? `[/color]` : `[/${tag.replace('color=', '').split(' ')[0]}]`;

        const newText = value.substring(0, start) + 
                        prefix + selectedText + suffix + 
                        value.substring(end);
        
        messageInput.value = newText;
        messageInput.focus();
        messageInput.selectionStart = start + prefix.length; 
        messageInput.selectionEnd = messageInput.selectionStart + selectedText.length;
    }

    // Handlers για τα κουμπιά μορφοποίησης
    if (document.getElementById('bold-button')) document.getElementById('bold-button').onclick = () => applyFormatting('b', 'bold text');
    if (document.getElementById('italic-button')) document.getElementById('italic-button').onclick = () => applyFormatting('i', 'italic text');
    
    if (document.getElementById('color-picker-button')) document.getElementById('color-picker-button').onclick = () => {
        if (colorInput) colorInput.click();
    };

    if (colorInput) colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    // ΛΟΓΙΚΗ ΓΙΑ ΤΟ ΚΟΥΜΠΙ ΕΙΔΟΠΟΙΗΣΗΣ (ΝΕΟ)
    if (notificationButton) {
        notificationButton.addEventListener('click', () => {
            isNotificationSoundEnabled = !isNotificationSoundEnabled;
            const icon = notificationButton.querySelector('i');
            
            if (isNotificationSoundEnabled) {
                icon.classList.replace('fa-bell-slash', 'fa-bell');
                notificationButton.title = 'Notification Sound ON';
                playNotificationSound(); // Δοκιμαστικός ήχος
            } else {
                icon.classList.replace('fa-bell', 'fa-bell-slash');
                notificationButton.title = 'Notification Sound OFF';
            }
        });
        // Αρχική ρύθμιση εικονιδίου
        notificationButton.querySelector('i').classList.add(isNotificationSoundEnabled ? 'fa-bell' : 'fa-bell-slash');
    }

    // ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    if (sendButton) {
        const sendMessage = () => {
            const msg = messageInput.value.trim();
            if (msg) {
                socket.emit('message', { msg: msg });
                messageInput.value = '';
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
                messageInput.style.height = (Math.min(messageInput.scrollHeight, 100)) + 'px';
            });
        }
    }
});