

// Υποθέτουμε ότι η συνάρτηση parseBBCode(text) υπάρχει έξω από το DOMContentLoaded
function parseBBCode(text) {
    if (!text) return '';
    
    // 1. [b] -> <strong>
    text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<strong>$1</strong>');
    
    // 2. [i] -> <em>
    text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<em>$1</em>');
    
    // 3. [u] -> <u>
    text = text.replace(/\[u\](.*?)\[\/u\]/gs, '<u>$1</u>');

    // 4. [color=#hex] -> <span style="color:#hex;">
    text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');

    // 5. [url=link]text[/url] -> <a href>
    text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>');
    
    // 6. [img]url[/img] -> <img>
    text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" style="max-width: 100%; height: auto;" loading="lazy" alt="User image"/>');
    
    // Επιστρέφουμε το τελικό HTML
    return text;
}


document.addEventListener('DOMContentLoaded', () => {

    // 🚨 Βεβαιωθείτε ότι αυτά τα IDs υπάρχουν στο chat.html
    const chatbox = document.getElementById('chatbox');
    const onlineUsersList = document.getElementById('online-users-list');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    
    // 🚨 1. ΚΡΙΣΙΜΗ ΣΥΝΔΕΣΗ SOCKET.IO (με path για Render)
    const socket = io({ path: '/socket.io/' }); 

    // --- HELPER FUNCTIONS ---

    // Συνάρτηση για προσθήκη ενός μηνύματος στο chatbox (χρησιμοποιεί BBCode)
    function appendMessage(data) {
        if (!chatbox) return;
        
        const messageDiv = document.createElement('div');
        const roleClass = `role-${data.role || 'user'}`; 
        
        // Χρησιμοποιούμε parseBBCode για να μετατρέψουμε το κείμενο
        const parsedMessage = parseBBCode(data.msg || data.message || '');
        
        // Δημιουργία HTML με username, ρόλο και timestamp
        const messageHtml = `
            <span class="user-info">
                <img src="${data.avatar_url || '/static/default_avatar.png'}" class="message-avatar" alt="Avatar">
                <span class="${roleClass}" style="font-weight: 700;">${data.username}</span> 
                <span style="color: #bbb;">[${new Date(data.timestamp).toLocaleTimeString('el-GR')}]:</span>
            </span> 
            <span class="message-content">${parsedMessage}</span> 
        `;
        
        messageDiv.innerHTML = messageHtml;
        messageDiv.className = 'chat-message';
        chatbox.appendChild(messageDiv);
        
        // Μετακίνηση στο κάτω μέρος
        chatbox.scrollTop = chatbox.scrollHeight;
    }

    // Νέα συνάρτηση: Φόρτωση Ιστορικού Μηνυμάτων
    async function loadMessageHistory() {
        if (!chatbox) return;
        try {
            const response = await fetch('/api/v1/messages');
            if (!response.ok) {
                throw new Error('Failed to load message history.');
            }
            const history = await response.json();
            
            // Προσθέτουμε τα μηνύματα στο chatbox
            history.forEach(data => {
                appendMessage(data); 
            });
            chatbox.scrollTop = chatbox.scrollHeight; // Σκρολάρισμα στο κάτω μέρος
        } catch (error) {
            console.error('Error loading history:', error);
        }
    }
    
    // Νέα συνάρτηση: Ενημέρωση Λίστας Online Χρηστών
    function updateActiveUsersList(users) {
        if (!onlineUsersList) return;
        onlineUsersList.innerHTML = ''; // Καθαρισμός λίστας
        
        users.forEach(user => {
            const listItem = document.createElement('li');
            listItem.className = `role-${user.role}`; 
            
            const avatar = user.avatar_url || '/static/default_avatar.png';
            
            listItem.innerHTML = `
                <img src="${avatar}" class="user-avatar-list" alt="${user.username}">
                <span>${user.username}</span>
                <span class="role-badge">(${user.role.toUpperCase()})</span>
            `;
            onlineUsersList.appendChild(listItem);
        });
    }
    
    // --- SOCKET.IO EVENTS ---
    
    // 🚨 2. Λήψη νέου μηνύματος (για να εμφανίζεται στο chatbox)
    socket.on('new_message', function(data) {
        appendMessage(data); 
    });

    // 🚨 3. Ενημέρωση λίστας ενεργών χρηστών (για να εμφανίζονται οι Online)
    socket.on('update_active_users', function(users) {
        updateActiveUsersList(users);
        // Προαιρετικό: Εμφάνιση αριθμού χρηστών
        const countElement = document.getElementById('online-users-count');
        if (countElement) {
             countElement.textContent = users.length;
        }
    });

    // --- DOM EVENT LISTENERS & INITIAL CALLS ---
    
    // 🚨 4. Φόρτωση Ιστορικού κατά την εκκίνηση
    loadMessageHistory(); 
    
    
    // --- ΛΟΓΙΚΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ ---
    const sendMessage = () => {
        const msg = messageInput.value.trim();
        if (msg) {
            // 🚨 ΚΑΛΕΣΜΑ SOCKET.IO
            socket.emit('message', { msg: msg });
            messageInput.value = '';
            // Αυτόματη προσαρμογή ύψους
            messageInput.style.height = 'auto'; 
        }
    };

    if (sendButton) {
        sendButton.addEventListener('click', (e) => {
            e.preventDefault();
            sendMessage();
        });
    }

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
            messageInput.style.height = (messageInput.scrollHeight) + 'px';
        });
    }

    // --- ΛΟΓΙΚΗ FORMATTING (BBCode) ---
    function applyFormatting(tag, placeholder) {
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const text = messageInput.value;
        const selectedText = text.substring(start, end) || placeholder;
        
        let newText;
        if (tag.startsWith('color')) {
            // [color=#hex]text[/color]
            const color = tag.split('=')[1];
            newText = `[color=${color}]${selectedText}[/color]`;
            tag = 'color'; // Για να βρούμε το σωστό μήκος
        } else {
            // [tag]text[/tag]
            newText = `[${tag}]${selectedText}[/${tag}]`;
        }

        messageInput.value = text.substring(0, start) + newText + text.substring(end);
        
        // Μετακίνηση του cursor στο τέλος του tag
        const newCursorPos = start + newText.length;
        messageInput.focus();
        messageInput.selectionEnd = newCursorPos;
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
    
});