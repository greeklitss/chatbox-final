// static/js/main.js - FINAL VERSION

let isNotificationSoundEnabled = true;

// 1. ΣΥΝΑΡΤΗΣΗ ΗΧΟΥ ΕΙΔΟΠΟΙΗΣΗΣ
function playNotificationSound() {
    if (!isNotificationSoundEnabled) return;
    try {
        // 🚨 ΣΩΣΤΗ ΔΙΑΔΡΟΜΗ ΗΧΟΥ ΕΙΔΟΠΟΙΗΣΗΣ
        const audio = new Audio('/static/sounds/chat_notification.mp3'); 
        audio.volume = 0.5; 
        audio.play().catch(e => console.log("Notification audio blocked by browser:", e));
    } catch (error) {
        console.error("Error playing notification sound:", error);
    }
}

// 2. BBCode Parser (Υποθέτουμε ότι είναι πλήρης)
function parseBBCode(text) {
    if (!text) return '';
    
    text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<strong>$1</strong>');
    text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<em>$1</em>');
    text = text.replace(/\[u\](.*?)\[\/u\]/gs, '<u>$1</u>'); // Προστέθηκε [u]
    text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');
    text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>');
    // 🚨 ΔΙΟΡΘΩΣΗ: Σωστό Alt text
    text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" alt="User Image" style="max-width:100%; height:auto;">');
    
    // Καθαρισμός τυχόν tags που δεν υποστηρίζονται
    text = text.replace(/\[\/?(emoticon)[^\]]*\]/g, ''); 
    
    return text;
}

document.addEventListener('DOMContentLoaded', () => {

    const chatbox = document.getElementById('chat-messages'); // 👍 ΔΙΟΡΘΩΣΗ!
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input'); 
    const notificationButton = document.getElementById('notification-volume-button'); 
    
    // Χρησιμοποιούμε σωστό path για Render
    const socket = io('https://chatbox-final.onrender.com');
    
    // HELPER: Προσθήκη μηνύματος στο UI
    function appendMessage(msg) {
        if (!chatbox) return; 

        const messageContainer = document.createElement('div');
        messageContainer.className = 'message-container';
        
        // 🚨 ΣΩΣΤΗ ΔΙΑΔΡΟΜΗ DEFAULT AVATAR
        const avatar = document.createElement('img');
        avatar.className = 'avatar';
        avatar.src = msg.avatar_url || '/static/default_avatar.png'; 
        avatar.alt = `${msg.username}'s avatar`;

        const messageContentDiv = document.createElement('div');
        messageContentDiv.className = 'message-content';
        messageContentDiv.classList.add(msg.role || 'user'); 

        const messageHeader = document.createElement('div');
        messageHeader.className = 'message-header';

        const usernameSpan = document.createElement('span');
        usernameSpan.className = 'username';
        usernameSpan.textContent = msg.username;
    
    // 🚨 ΕΦΑΡΜΟΓΗ ΧΡΩΜΑΤΟΣ ΣΤΟ USERNAME
        if (msg.color) {
           usernameSpan.style.color = msg.color; 
    }
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'timestamp';
        const date = msg.timestamp ? new Date(msg.timestamp) : new Date();
        timestampSpan.textContent = `[${date.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}]`;

        messageHeader.appendChild(usernameSpan);
        messageHeader.appendChild(timestampSpan);
        
        const messageBox = document.createElement('div');
        messageBox.className = 'message-box';
        messageBox.innerHTML = parseBBCode(msg.content || msg.message || msg.msg); 

        messageContentDiv.appendChild(messageHeader);
        messageContentDiv.appendChild(messageBox);
        messageContainer.appendChild(avatar);
        messageContainer.appendChild(messageContentDiv);

        chatbox.appendChild(messageContainer);
        chatbox.scrollTop = chatbox.scrollHeight;
    }

    // --- SOCKET.IO EVENTS ---

    // 🚨 ΔΙΟΡΘΩΣΗ: Listener για νέα μηνύματα
    socket.on('new_message', function(data) {
        appendMessage(data);
        playNotificationSound(); // Κλήση ήχου
    });
    
    socket.on('history', function(messages) {
        if (chatbox) chatbox.innerHTML = '';
        messages.forEach(appendMessage);
        chatbox.scrollTop = chatbox.scrollHeight;
    });

    // --- ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ / ΦΟΡΜΑΣ ---

    // Λογική για τον ήχο ειδοποίησης
    if (notificationButton) {
        notificationButton.addEventListener('click', () => {
            isNotificationSoundEnabled = !isNotificationSoundEnabled;
            const icon = notificationButton.querySelector('i');
            
            if (isNotificationSoundEnabled) {
                icon.classList.replace('fa-bell-slash', 'fa-bell');
                notificationButton.title = 'Notification Sound ON';
                playNotificationSound(); 
            } else {
                icon.classList.replace('fa-bell', 'fa-bell-slash');
                notificationButton.title = 'Notification Sound OFF';
            }
        });
        notificationButton.querySelector('i').classList.add(isNotificationSoundEnabled ? 'fa-bell' : 'fa-bell-slash');
    }

    // --- ΣΥΝΑΡΤΗΣΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ ---
    function sendMessage() {
        // Υποθέτουμε ότι το messageInput ορίστηκε σωστά στην κορυφή του DOMContentLoaded
        const content = messageInput.value.trim(); 
        if (!content) return; // Αποφυγή κενών μηνυμάτων
        
        // Υποθέτουμε ότι το colorInput ορίστηκε σωστά
        const selectedColor = colorInput ? colorInput.value : ''; 
        
        const messageData = {
            'msg': content,
            'color': selectedColor,
        };

        try {
            // Αυτή η γραμμή στέλνει το μήνυμα στον server (server.py)
            socket.emit('message', messageData); 
            messageInput.value = ''; // Καθαρισμός πεδίου εισαγωγής
        } catch (e) {
            console.error("Socket emit failed. Is the connection open?", e);
        }
    }

    // --- ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ / ΦΟΡΜΑΣ (ΣΥΝΕΧΕΙΑ) ---

    // 1. Event Listener για το κουμπί Αποστολής (ID: send-button)
    if (sendButton) {
        sendButton.addEventListener('click', sendMessage);
        console.log("Send button listener attached."); // Ελέγξτε αυτό στην Console!
    } else {
        console.error("Element with ID 'send-button' not found.");
    }

    // 2. Event Listener για το Enter στο πεδίο εισαγωγής (ID: message-input)
    if (messageInput) {
        messageInput.addEventListener('keydown', function(event) {
            // Πατάμε Enter, αλλά όχι Shift+Enter
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault(); // Αποτρέπει τη νέα γραμμή
                sendMessage();
            }
        });
    }

// ... (εδώ συνεχίζει το τελικό }); του DOMContentLoaded)
    // (Αυτός ο κώδικας υποτίθεται ότι είναι ήδη σωστός στην τελευταία σας έκδοση του main.js)
    
});