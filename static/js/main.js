// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {

    // 1. ΔΗΛΩΣΗ SOCKET
    const socket = io({
        path: '/socket.io/' 
    });
    
    // 2. ΔΗΛΩΣΗ ΟΛΩΝ ΤΩΝ ΣΤΟΙΧΕΙΩΝ DOM
    const chatbox = document.getElementById('chatbox');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    
    // 3. ΔΗΛΩΣΗ ΗΧΟΥ ΜΗΝΥΜΑΤΟΣ
    const notificationSound = new Audio('/static/sounds/notification.mp3');
    notificationSound.volume = 0.5;

    // 4. ΛΟΓΙΚΗ ΜΟΡΦΟΠΟΙΗΣΗΣ (Function Declaration)
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

    // 5. 🟢 ΟΛΗ Η ΛΟΓΙΚΗ SOCKETIO (EVENTS)
    socket.on('connect', () => {
        console.log('Connected to chat server!');
    });
    
    socket.on('new_message', function(data) {
        const messageDiv = document.createElement('div');
        const roleClass = `role-${data.role}`; 
        
        const messageHtml = `
            <span class="${roleClass}" style="font-weight: 700;">${data.username}</span> 
            <span style="color: #bbb;">[${data.timestamp}]:</span> 
            ${data.message}
        `;
        
        messageDiv.innerHTML = messageHtml;
        chatbox.appendChild(messageDiv);
        chatbox.scrollTop = chatbox.scrollHeight;

        if (data.username !== '{{ user.display_name }}' && !document.getElementById('toggle-sound').checked) {
             notificationSound.play().catch(e => console.log("Sound play prevented:", e));
        }
    });

    // 6. ΣΥΝΔΕΣΗ ΚΟΥΜΠΙΩΝ (Handlers)

    // A. Formatting buttons
    document.getElementById('bold-button').onclick = () => applyFormatting('b', 'text');
    document.getElementById('italic-button').onclick = () => applyFormatting('i', 'text');
    document.getElementById('underline-button').onclick = () => applyFormatting('u', 'text');
    
    document.getElementById('color-picker-button').onclick = () => {
        colorInput.click();
    };

    colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    // Β. Send Button Logic (The real click handler)
    if (sendButton) {
        sendButton.onclick = function(e) {
            e.preventDefault();
        };

        sendButton.addEventListener('click', () => {
            const msg = messageInput.value.trim();
            if (msg) {
                socket.emit('message', { msg: msg });
                messageInput.value = '';
            }
        });
    }

    // Γ. Keydown Listener
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendButton.click();
        }
    });

// 🟢 ΤΟ ΤΕΛΙΚΟ ΚΛΕΙΣΙΜΟ ΤΟΥ DOMContentLoaded
});