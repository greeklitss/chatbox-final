// static/main.js - FINAL & COMPLETE DIAGNOSTIC VERSION

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
    
    // Αντικαταστήστε [b], [i], [u], [color], [url], [img]
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

// 3. HELPER: Προσθήκη μηνύματος στο UI
function appendMessage(msg) {
    const chatbox = document.getElementById('chat-messages'); 
    if (!chatbox) {
        console.error("Error: Chatbox element not found (ID: chat-messages).");
        return; 
    }

    const username = msg.username || 'Unknown User';
    const msgContent = msg.msg || msg.content || 'Message failed to load.'; 
    const role = msg.role || 'user';
    const color = msg.color || '#FFFFFF'; 
    const avatarUrl = msg.avatar_url || '/static/default_avatar.png';
    const timestamp = msg.timestamp ? new Date(msg.timestamp) : new Date();

    const messageContainer = document.createElement('div');
    messageContainer.className = 'message-container';
    messageContainer.setAttribute('data-user-id', msg.user_id || 'system');
    
    // Χειρισμός status messages
    if (msg.role === 'system_status' || role === 'status') {
        messageContainer.className = 'status-message';
        messageContainer.innerHTML = `<p>${msgContent}</p>`;
        chatbox.appendChild(messageContainer);
        chatbox.scrollTop = chatbox.scrollHeight;
        return;
    }

    const avatar = document.createElement('img');
    avatar.className = 'avatar';
    avatar.src = avatarUrl;
    avatar.alt = `${username}'s avatar`;

    const messageContentDiv = document.createElement('div');
    messageContentDiv.className = 'message-content';
    messageContentDiv.classList.add(role); 

    const messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';

    const usernameSpan = document.createElement('span');
    usernameSpan.className = 'username';
    usernameSpan.textContent = username;
    usernameSpan.style.color = color; 
    
    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'timestamp';
    timestampSpan.textContent = `[${timestamp.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}]`;

    messageHeader.appendChild(usernameSpan);
    messageHeader.appendChild(timestampSpan);
    
    const messageBox = document.createElement('div');
    messageBox.className = 'message-box';
    messageBox.innerHTML = parseBBCode(msgContent); 

    messageContentDiv.appendChild(messageHeader);
    messageContentDiv.appendChild(messageBox);
    messageContainer.appendChild(avatar);
    messageContainer.appendChild(messageContentDiv); 

    chatbox.appendChild(messageContainer);
    chatbox.scrollTop = chatbox.scrollHeight;
}


// --- DOMContentLoaded & INITIALIZATION ---

document.addEventListener('DOMContentLoaded', () => {

    // 🚨 1. ΑΝΑΚΤΗΣΗ ΒΑΣΙΚΩΝ ΣΤΟΙΧΕΙΩΝ
    const chatbox = document.getElementById('chat-messages'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input'); 
    const colorPickerButton = document.getElementById('color-picker-button');
    const emoticonButton = document.getElementById('emoticon-button'); 
    const emoticonSelector = document.getElementById('emoticon-selector'); // Υποθέτουμε ότι υπάρχει στο chat.html
    const notificationButton = document.getElementById('notification-volume-button'); 
    
    // 🚨 2. ΣΥΝΔΕΣΗ SOCKET.IO (Η ΠΙΟ ΑΣΦΑΛΗΣ ΜΟΡΦΗ ΓΙΑ RENDER)
    const socket = io({ 
        transports: ['websocket', 'polling'] 
    }); 
    
    // --- SOCKET.IO EVENTS (ΔΙΑΓΝΩΣΤΙΚΑ) ---

    socket.on('connect', () => {
        console.log("SUCCESS: Socket.IO Connected!");
        socket.emit('join'); 
        
        if (chatbox) {
            appendMessage({
                username: 'SYSTEM',
                msg: `Connected successfully. Loading messages...`,
                role: 'system_status'
            });
        }
    });
    
    socket.on('connect_error', (error) => {
        console.error("FATAL ERROR: Socket.IO Connection Failed!", error);
        if (chatbox) {
            appendMessage({
                username: 'SYSTEM',
                msg: `Connection FAILED: Cannot connect to server. Check browser console for details.`,
                role: 'system_status'
            });
        }
    });


    socket.on('new_message', function(data) {
        appendMessage(data);
        playNotificationSound(); 
    });
    
    socket.on('history', function(messages) {
        if (chatbox) chatbox.innerHTML = '';
        messages.forEach(appendMessage);
        chatbox.scrollTop = chatbox.scrollHeight;
    });

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

    // --- 3. ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ / LISTENERS ---

    // Κουμπί Αποστολής (Enter)
    if (sendButton) {
        sendButton.addEventListener('click', sendMessage);
    }
    if (messageInput) {
        messageInput.addEventListener('keydown', function(event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault(); 
                sendMessage();
            }
        });
    }
    
    // Color Picker Button
    if (colorPickerButton && colorInput) {
        colorPickerButton.addEventListener('click', () => {
            colorInput.click();
        });
    }

    // Emoticon Button
    if (emoticonButton && emoticonSelector) {
        emoticonButton.addEventListener('click', () => {
            emoticonSelector.style.display = emoticonSelector.style.display === 'block' ? 'none' : 'block';
        });
        
        document.addEventListener('click', (event) => {
            if (!emoticonButton.contains(event.target) && !emoticonSelector.contains(event.target)) {
                emoticonSelector.style.display = 'none';
            }
        });
    }
    
    // Notification Button
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
    
});