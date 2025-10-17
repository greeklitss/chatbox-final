// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {
    // 1. 🟢 ΣΩΣΤΗ ΣΥΝΔΕΣΗ SOCKETIO (ΟΛΑ ΜΕΣΑ ΣΤΟ SCOPE)
    const socket = io({
        path: '/socket.io/' 
    });
    
    // 2. 🟢 ΟΛΑ ΤΑ ΣΤΟΙΧΕΙΑ
    const chatbox = document.getElementById('chatbox');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    // Νέα κουμπιά
    const urlButton = document.getElementById('url-button');
    const gifButton = document.getElementById('gif-button');
    
    
    // 3. ΛΟΓΙΚΗ ΕΜΦΑΝΙΣΗΣ ΜΗΝΥΜΑΤΟΣ
    function displayMessage(data) {
        const messageElement = document.createElement('div');
        messageElement.innerHTML = `[${data.timestamp}] <strong class="role-${data.role}">${data.username}</strong>: ${data.message}`;
        chatbox.appendChild(messageElement);
        // Κάνουμε scroll στο κάτω μέρος
        chatbox.scrollTop = chatbox.scrollHeight;
    }

    function displayStatus(data) {
        const statusElement = document.createElement('div');
        statusElement.innerHTML = `<span style="color: #666; font-style: italic;">--- ${data.msg} ---</span>`;
        chatbox.appendChild(statusElement);
        chatbox.scrollTop = chatbox.scrollHeight;
    }

    // 🚨 1. ΗΧΟΣ ΜΗΝΥΜΑΤΟΣ
    const notificationSound = new Audio('/static/sounds/notification.mp3');
    notificationSound.volume = 0.5;

    // 4. 🟢 ΟΛΗ Η ΛΟΓΙΚΗ SOCKETIO (ΕΝΤΟΣ SCOPE!)
    socket.on('connect', () => {
        console.log('Connected to chat server!');
        // Εδώ μπορεί να γίνει η φόρτωση των ρυθμίσεων αν χρειάζεται
    });
    
    socket.on('new_message', (data) => {
        displayMessage(data);
        // Παίζουμε ήχο μόνο αν το μήνυμα δεν είναι από εμάς (απλοϊκή προσέγγιση)
        // notificationSound.play().catch(e => console.log("Sound play prevented."));
    });

    socket.on('status', (data) => {
        displayStatus(data);
    });
    
    // 5. ΛΕΙΤΟΥΡΓΙΑ FORMATTING (BBCode)
    function applyFormatting(tag, placeholder) {
        const value = messageInput.value;
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        let selectedText = value.substring(start, end);

        // Αν δεν υπάρχει επιλεγμένο κείμενο, χρησιμοποιούμε placeholder
        if (!selectedText) {
            selectedText = placeholder;
        }

        let prefix = `[${tag}]`;
        let suffix = `[/${tag.split('=')[0]}]`; // Λειτουργεί και για [color=...]

        const newText = value.substring(0, start) + 
                        prefix + selectedText + suffix + 
                        value.substring(end);
        
        messageInput.value = newText;
        // Τοποθέτηση cursor
        messageInput.focus();
        // Τοποθετούμε τον κέρσο μέσα στο tag για να πληκτρολογήσει ο χρήστης
        messageInput.selectionStart = start + prefix.length; 
        messageInput.selectionEnd = messageInput.selectionStart + selectedText.length;
    }

    // --- BBCODE BUTTONS ---
    document.getElementById('bold-button').onclick = () => applyFormatting('b', 'text');
    document.getElementById('italic-button').onclick = () => applyFormatting('i', 'text');
    document.getElementById('underline-button').onclick = () => applyFormatting('u', 'text');
    
    // Νέα Κουμπιά
    if (urlButton) {
        urlButton.onclick = () => {
            const url = prompt("Enter the URL:");
            const linkText = prompt("Enter the link text (optional):");
            if (url) {
                if (linkText) {
                    applyFormatting(`url=${url}`, linkText);
                } else {
                    applyFormatting('url', url);
                }
            }
        };
    }
    
    if (gifButton) {
        gifButton.onclick = () => {
            const imgUrl = prompt("Enter the GIF or Image URL:");
            if (imgUrl) {
                applyFormatting('img', imgUrl);
            }
        };
    }

    // Color Picker
    document.getElementById('color-picker-button').onclick = () => {
        colorInput.click();
    };

    colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    // 6. ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    sendButton.addEventListener('click', () => {
        const msg = messageInput.value.trim();
        if (msg) {
            // 🚨 ΚΡΙΣΙΜΗ ΔΙΟΡΘΩΣΗ: Αλλαγή event σε 'send_message' (όπως περιμένει ο server)
            socket.emit('send_message', { msg: msg }); 
            messageInput.value = '';
        }
    });

    // Αποστολή με Enter
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendButton.click();
        }
    });
    
    // Λογική για Emoticons (Placeholder)
    document.getElementById('emoticon-button').onclick = () => {
        console.log("Emoticons functionality to be implemented.");
        // Εδώ θα εμφανίζατε ένα popover με τα emoticons
    };

}); // End of DOMContentLoaded