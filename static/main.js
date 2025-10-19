// static/js/main.js - ΟΡΙΣΤΙΚΑ ΔΙΟΡΘΩΜΕΝΟ

document.addEventListener('DOMContentLoaded', () => {
    
    // --- ΒΑΣΙΚΕΣ ΜΕΤΑΒΛΗΤΕΣ DOM ---
    const chatbox = document.getElementById('chat-messages');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    const socket = io(); // Σύνδεση με τον SocketIO server
    
    // --- HELPER FUNCTIONS ---

    // 🚨 ΝΕΟ: BBCode Parser Function - Απαραίτητο για εμφάνιση [b], [color]
    function parseBBCode(text) {
        if (!text) return '';
        
        // 1. [b] -> <strong>
        text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<strong>$1</strong>');
        
        // 2. [i] -> <em>
        text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<em>$1</em>');
        
        // 3. [color=#hex] -> <span style="color:#hex;">
        text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');
    
        // 4. [url] -> <a> 
        text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>');
        
        // 5. [img] -> <img> (Εμφάνιση εικόνων)
        text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" alt="Image" style="max-width:100%; height:auto;">');

        return text;
    }

    // 🚨 ΔΙΟΡΘΩΜΕΝΟ: Προσθήκη μηνύματος στο chat (χρησιμοποιεί τη νέα δομή HTML/CSS)
    function addMessageToChat(msg) {
        const messageContainer = document.createElement('div');
        messageContainer.className = 'message-container';
        
        // --- Avatar ---
        const avatar = document.createElement('img');
        avatar.className = 'avatar';
        // Χρησιμοποιούμε είτε το avatar_url που έρχεται με το μήνυμα, είτε ένα default
        avatar.src = msg.avatar_url || '{{ url_for("static", filename="default_avatar.png") }}';
        avatar.alt = `${msg.username}'s avatar`;

        // --- Content ---
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
        // Μορφοποίηση ώρας σε μορφή [9:51:26 μ.μ.]
        timestampSpan.textContent = `[${new Date(msg.timestamp).toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}]`;

        messageHeader.appendChild(usernameSpan);
        messageHeader.appendChild(timestampSpan);
        
        // Box (Το κείμενο του μηνύματος)
        const messageBox = document.createElement('div');
        messageBox.className = 'message-box';
        // 🚨 ΚΡΙΣΙΜΟ: Εφαρμογή του BBCode Parser
        messageBox.innerHTML = parseBBCode(msg.content || msg.message); 

        // Δόμηση του μηνύματος
        messageContentDiv.appendChild(messageHeader);
        messageContentDiv.appendChild(messageBox);

        messageContainer.appendChild(avatar);
        messageContainer.appendChild(messageContentDiv);

        chatbox.appendChild(messageContainer);
        chatbox.scrollTop = chatbox.scrollHeight;
    }

    // --- BBCODE/FORMATTING LOGIC ---
    function applyFormatting(tag, placeholder) {
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const currentText = messageInput.value;
        let prefix, suffix, newSelectionStart, newSelectionEnd;
        
        if (tag.includes('=')) { // Για [color=#hex]
            prefix = '[' + tag + ']';
            suffix = '[/color]';
        } else { // Για [b], [i]
            prefix = `[${tag}]`;
            suffix = `[/${tag}]`;
        }

        if (start === end) {
            // Δεν έχει επιλεγεί κείμενο: εισάγει το placeholder
            const newText = currentText.substring(0, start) + prefix + placeholder + suffix + currentText.substring(end);
            messageInput.value = newText;
            newSelectionStart = start + prefix.length;
            newSelectionEnd = newSelectionStart + placeholder.length;
        } else {
            // Έχει επιλεγεί κείμενο: εφαρμόζει το tag
            const selectedText = currentText.substring(start, end);
            const newText = currentText.substring(0, start) + prefix + selectedText + suffix + currentText.substring(end);
            messageInput.value = newText;
            newSelectionStart = start;
            newSelectionEnd = start + prefix.length + selectedText.length + suffix.length;
        }

        // Επαναφορά του focus και της επιλογής
        messageInput.focus();
        messageInput.selectionStart = newSelectionStart;
        messageInput.selectionEnd = newSelectionEnd;
    }

    // --- EVENT HANDLERS ---
    
    // Handlers για τα κουμπιά μορφοποίησης
    document.getElementById('bold-button').onclick = () => applyFormatting('b', 'bold text');
    document.getElementById('italic-button').onclick = () => applyFormatting('i', 'italic text');
    
    // Color Picker Logic
    document.getElementById('color-picker-button').onclick = () => {
        if (colorInput) colorInput.click();
    };

    if (colorInput) colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    // 🚨 Υποθέτουμε ότι το gif-button και emoticon-button θα έχουν δική τους λογική αργότερα
    
    // ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    if (sendButton) {
        sendButton.addEventListener('click', (e) => {
            e.preventDefault();
            const msg = messageInput.value.trim();
            if (msg) {
                socket.emit('message', { msg: msg });
                messageInput.value = '';
                // Αυτόματη προσαρμογή ύψους μετά την αποστολή
                messageInput.style.height = 'auto'; 
            }
        });
    }

    // Λειτουργία αποστολής με Enter
    if (messageInput) {
        messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault(); // Αποτρέπει τη νέα γραμμή
                sendButton.click();
            }
        });
        
        // Αυτόματη προσαρμογή ύψους του textarea
        messageInput.addEventListener('input', () => {
            messageInput.style.height = 'auto';
            messageInput.style.height = (messageInput.scrollHeight) + 'px';
        });
    }
    
    // --- SOCKETIO LISTENERS ---

    // Λήψη ιστορικού
    socket.on('history', (messages) => {
        chatbox.innerHTML = '';
        messages.forEach(msg => addMessageToChat(msg));
    });

    // Λήψη νέου μηνύματος
    socket.on('message', (data) => {
        addMessageToChat(data);
    });
    
    // Λήψη ενημέρωσης avatar (εάν υπάρχει)
    socket.on('user_avatar_updated', (data) => {
        // Εδώ μπορείτε να προσθέσετε λογική για να ενημερώνει όλα τα avatars του χρήστη στο chat
        console.log(`User ${data.user_id} avatar updated to ${data.avatar_url}`);
        // Για την ώρα, αφήνουμε την επόμενη φόρτωση του ιστορικού να το ενημερώσει.
    });
    
    // --- ΛΟΓΙΚΗ LOGOUT ---
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.onclick = () => {
            window.location.href = '/logout'; 
        };
    }
    
    // --- ΛΟΓΙΚΗ PROFILE ---
    const profileButton = document.getElementById('profile-button');
    if (profileButton) {
        profileButton.onclick = () => {
            window.location.href = '/settings'; 
        };
    }
    
    // --- ΛΟΓΙΚΗ EXPORT ---
    // (Χρειάζεται υλοποίηση export PDF αργότερα)
    const exportButton = document.getElementById('export-button');
    if (exportButton) {
        exportButton.onclick = () => {
            alert('Export functionality coming soon!');
        };
    }
    
    // --- ΛΟΓΙΚΗ ΕΚΚΙΝΗΣΗΣ ---
    // Ζητάμε το ιστορικό με τη σύνδεση
    socket.on('connect', () => {
        socket.emit('request_history');
    });

});