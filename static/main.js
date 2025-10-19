// static/js/main.js - ΟΡΙΣΤΙΚΑ ΔΙΟΡΘΩΜΕΝΟ

document.addEventListener('DOMContentLoaded', () => {
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`); 
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// 🚨 1. Ανάκτηση του session ID (το όνομα του cookie είναι 'session')
const sessionId = getCookie('session'); 


// 2. 🟢 ΣΩΣΤΗ ΣΥΝΔΕΣΗ SOCKETIO 
const socket = io({
    path: '/socket.io/',
    // 🚨 ΚΡΙΣΙΜΟ: Στέλνουμε το session ID στον server
    query: {
        session_id: sessionId 
    }
});

    // ----------------------------------------------------
    // 3. 🟢 ΟΛΗ Η ΛΟΓΙΚΗ SOCKETIO ΕΙΝΑΙ ΕΔΩ ΜΕΣΑ
    // ----------------------------------------------------

    // Σύνδεση με τον Server
    socket.on('connect', () => {
        console.log('Connected to chat server!');
        // Ειδοποιούμε τον server να μας βάλει στο chat room
        socket.emit('join'); 
    });
    
    // 🚨 ΔΙΟΡΘΩΣΗ EVENT NAME: Ακούμε για 'message' (όπως στέλνει ο server)
    socket.on('message', function(data) {
        const messageDiv = document.createElement('div');
        // Χρησιμοποιούμε role από το data του server
        const roleClass = `role-${data.role || 'user'}`; 
        
        // Δημιουργία κειμένου με χρωματισμένο username
        const messageHtml = `
            <span class="${roleClass}" style="font-weight: 700;">${data.username}</span> 
            <span style="color: #bbb;">[${data.timestamp}]:</span> 
            ${data.msg || data.message} // Χρησιμοποιούμε data.msg (που στέλνει ο server)
        `;
        
        messageDiv.innerHTML = messageHtml;
        chatbox.appendChild(messageDiv);
        chatbox.scrollTop = chatbox.scrollHeight;

        // Παίζει τον ήχο
        // Προσοχή: Χρησιμοποιούμε data.username για να ελέγξουμε αν είναι δικό μας μήνυμα
        if (data.username !== '{{ user.display_name }}' && document.getElementById('toggle-sound') && !document.getElementById('toggle-sound').checked) {
             notificationSound.play().catch(e => console.log("Sound play prevented:", e));
        }
    });

    // ----------------------------------------------------
    // 4. 🟢 ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ / ΦΟΡΜΑΣ
    // ----------------------------------------------------

    // Λειτουργία μορφοποίησης κειμένου
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

    // Handlers για τα κουμπιά
    document.getElementById('bold-button').onclick = () => applyFormatting('b', 'text');
    document.getElementById('italic-button').onclick = () => applyFormatting('i', 'text');
    document.getElementById('underline-button').onclick = () => applyFormatting('u', 'text');
    
    document.getElementById('color-picker-button').onclick = () => {
        colorInput.click();
    };

    colorInput.onchange = () => {
        applyFormatting('color=' + colorInput.value, 'colored text');
    };
    
    // 🚨 ΔΙΟΡΘΩΣΗ: ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button) - Εντός εύρους
    if (sendButton) {
        sendButton.addEventListener('click', (e) => {
            e.preventDefault();
            const msg = messageInput.value.trim();
            if (msg) {
                // 🚨 ΣΩΣΤΗ ΚΛΗΣΗ SOCKET.EMIT
                socket.emit('message', { msg: msg });
                messageInput.value = '';
            }
        });
    }

    // Λειτουργία αποστολής με Enter
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            if (sendButton) {
                sendButton.click();
            }
        }
    });

}); // <--- ΤΕΛΙΚΟ ΚΛΕΙΣΙΜΟ DOMContentLoaded