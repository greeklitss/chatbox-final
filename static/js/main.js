// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {
    // 1. 🟢 ΣΩΣΤΗ ΣΥΝΔΕΣΗ SOCKETIO (Με το path μέσα στην κλήση)
    const socket = io({
        path: '/socket.io/' // Το path είναι μέσα στο io({})
    });
    
    // 2. 🟢 ΟΛΑ ΤΑ ΣΤΟΙΧΕΙΑ ΠΡΕΠΕΙ ΝΑ ΕΙΝΑΙ ΕΔΩ ΜΕΣΑ
    const chatbox = document.getElementById('chatbox');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    
    // 3. ΣΥΝΔΕΣΗ ΚΟΥΜΠΙΩΝ
    if (sendButton) {
        sendButton.onclick = function(e) {
            e.preventDefault();
        };
    }
});
    // 4. 🟢 ΟΛΗ Η ΛΟΓΙΚΗ SOCKETIO (ΠΡΕΠΕΙ ΝΑ ΕΙΝΑΙ ΕΔΩ!)
    socket.on('connect', () => {
        console.log('Connected to chat server!');
    });
    
    // 🚨 1. ΗΧΟΣ ΜΗΝΥΜΑΤΟΣ
    const notificationSound = new Audio('/static/sounds/notification.mp3');
    notificationSound.volume = 0.5;
    // 🚨 2. ΧΕΙΡΙΣΜΟΣ ΝΕΟΥ ΜΗΝΥΜΑΤΟΣ
    socket.on('new_message', function(data) {
        const messageDiv = document.createElement('div');
        const roleClass = `role-${data.role}`; 
        
        // Δημιουργία κειμένου με χρωματισμένο username
        const messageHtml = `
            <span class="${roleClass}" style="font-weight: 700;">${data.username}</span> 
            <span style="color: #bbb;">[${data.timestamp}]:</span> 
            ${data.message}
        `;
        
        messageDiv.innerHTML = messageHtml;
        chatbox.appendChild(messageDiv);
        chatbox.scrollTop = chatbox.scrollHeight;

        // Παίζει τον ήχο μόνο αν δεν είναι δικό μας μήνυμα
        // (Χρειάζεται να περάσουμε το user_id στο emit για καλύτερο έλεγχο)
        if (data.username !== '{{ user.display_name }}' && !document.getElementById('toggle-sound').checked) {
             notificationSound.play().catch(e => console.log("Sound play prevented:", e));
        }
    });

    // 🚨 3. ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ ΜΟΡΦΟΠΟΙΗΣΗΣ
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
        // Τοποθέτηση cursor
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
    
    // 4. ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    sendButton.addEventListener('click', () => {
        const msg = messageInput.value.trim();
        if (msg) {
            socket.emit('message', { msg: msg });
            messageInput.value = '';
        }
    });

    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendButton.click();
        }
    });
});