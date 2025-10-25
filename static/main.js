// static/js/main.js - FINAL VERSION

let isNotificationSoundEnabled = true;

// 1. ΣΥΝΑΡΤΗΣΗ ΗΧΟΥ ΕΙΔΟΠΟΙΗΣΗΣ
function playNotificationSound() {
    if (!isNotificationSoundEnabled) return;
    try {
        const audio = new Audio('/static/sounds/chat_notification.mp3'); 
        audio.volume = 0.5; 
        audio.play().catch(e => console.log("Notification audio blocked by browser:", e));
    } catch (error) {
        console.error("Error playing notification sound:", error);
    }
}

// 2. BBCode Parser 
function parseBBCode(text) {
    if (!text) return '';
    
    text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<strong>$1</strong>');
    text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<em>$1</em>');
    text = text.replace(/\[u\](.*?)\[\/u\]/gs, '<u>$1</u>'); 
    text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');
    text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>');
    text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" alt="User Image" style="max-width:100%; height:auto;">');
    
    // Καθαρισμός τυχόν tags που δεν υποστηρίζονται
    text = text.replace(/\[\/?(emoticon)[^\]]*\]/g, ''); 
    
    return text;
}

// 3. HELPER: Προσθήκη μηνύματος στο UI (ΠΛΗΡΩΣ ΔΙΟΡΘΩΜΕΝΟ)
function appendMessage(msg) {
    // 🚨 ΚΡΙΣΙΜΟ: Το ID πρέπει να είναι 'chat-messages'
    const chatbox = document.getElementById('chat-messages'); 
    if (!chatbox) {
        console.error("Error: Chatbox element not found (ID: chat-messages).");
        return; 
    }

    // 1. Ασφαλής ανάκτηση δεδομένων
    const username = msg.username || 'Unknown User';
    // 🚨 ΔΙΟΡΘΩΣΗ: Χρησιμοποιούμε msg.msg, το οποίο έρχεται από τον server
    const msgContent = msg.msg || msg.content || 'Message failed to load.'; 
    const role = msg.role || 'user';
    const color = msg.color || '#FFFFFF'; 
    const avatarUrl = msg.avatar_url || '/static/default_avatar.png';
    
    const timestamp = msg.timestamp ? new Date(msg.timestamp) : new Date();

    // 2. Δημιουργία DOM elements
    const messageContainer = document.createElement('div');
    messageContainer.className = 'message-container';
    messageContainer.setAttribute('data-user-id', msg.user_id || 'system');
    
    // Χειρισμός status messages
    if (msg.status_message || role === 'system_status' || role === 'status') {
        messageContainer.className = 'status-message';
        messageContainer.innerHTML = `<p>${msgContent}</p>`;
        chatbox.appendChild(messageContainer);
        chatbox.scrollTop = chatbox.scrollHeight;
        return;
    }

    // 3. Avatar
    const avatar = document.createElement('img');
    avatar.className = 'avatar';
    avatar.src = avatarUrl;
    avatar.alt = `${username}'s avatar`;

    // 4. Message Content Box (το κεντρικό box)
    const messageContentDiv = document.createElement('div');
    messageContentDiv.className = 'message-content';
    messageContentDiv.classList.add(role); // Προσθήκη ρόλου ως κλάση

    // 5. Header (Username & Time)
    const messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';

    const usernameSpan = document.createElement('span');
    usernameSpan.className = 'username';
    usernameSpan.textContent = username;
    // ΕΦΑΡΜΟΓΗ ΧΡΩΜΑΤΟΣ ΣΤΟ USERNAME
    usernameSpan.style.color = color; 
    
    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'timestamp';
    timestampSpan.textContent = `[${timestamp.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}]`;

    messageHeader.appendChild(usernameSpan);
    messageHeader.appendChild(timestampSpan);
    
    // 6. Message Body (το box με το περιεχόμενο)
    const messageBox = document.createElement('div');
    messageBox.className = 'message-box';
    messageBox.innerHTML = parseBBCode(msgContent); 

    // 7. Σύνδεση όλων
    messageContentDiv.appendChild(messageHeader);
    messageContentDiv.appendChild(messageBox);
    messageContainer.appendChild(avatar);
    messageContainer.appendChild(messageContentDiv); // Το κεντρικό container

    chatbox.appendChild(messageContainer);
    
    // 8. Κύλιση προς τα κάτω
    chatbox.scrollTop = chatbox.scrollHeight;
}

document.addEventListener('DOMContentLoaded', () => {

    const chatbox = document.getElementById('chat-messages'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input'); 
    const notificationButton = document.getElementById('notification-volume-button'); 
    
    // 🚨 Βεβαιωθείτε ότι το URL είναι σωστό για το Render
    const socket = io('https://chatbox-final.onrender.com'); 
    
    // --- SOCKET.IO EVENTS ---

    socket.on('new_message', function(data) {
        appendMessage(data);
        playNotificationSound(); 
    });
    
    socket.on('history', function(messages) {
        if (chatbox) chatbox.innerHTML = '';
        messages.forEach(appendMessage);
        chatbox.scrollTop = chatbox.scrollHeight;
    });

    // ... (ο κώδικας για notificationButton παραμένει) ...

    // --- ΣΥΝΑΡΤΗΣΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ ---
    function sendMessage() {
        const content = messageInput.value.trim(); 
        if (!content) return; 
        
        const selectedColor = colorInput ? colorInput.value : '#FFFFFF'; 
        
        const messageData = {
            'msg': content,
            'color': selectedColor,
        };

        try {
            socket.emit('message', messageData); 
            messageInput.value = ''; 
        } catch (e) {
            console.error("Socket emit failed. Is the connection open?", e);
        }
    }

    // --- ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ / ΦΟΡΜΑΣ (ΣΥΝΕΧΕΙΑ) ---

    // 1. Event Listener για το κουμπί Αποστολής (ID: send-button)
    if (sendButton) {
        sendButton.addEventListener('click', sendMessage);
    } else {
        console.error("Element with ID 'send-button' not found.");
    }

    // 2. Event Listener για το Enter στο πεδίο εισαγωγής (ID: message-input)
    if (messageInput) {
        messageInput.addEventListener('keydown', function(event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault(); 
                sendMessage();
            }
        });
    }

    // ... (εδώ συνεχίζει ο υπόλοιπος κώδικας) ...
});