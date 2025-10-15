// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {
    
    // 🚨 ΝΕΟ ID: Χρησιμοποιούμε #message-container
    const socket = io();
    const messageContainer = document.getElementById('message-container'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    const toggleSound = document.getElementById('toggle-sound');
    
    // 🚨 1. ΗΧΟΣ ΜΗΝΥΜΑΤΟΣ (ΥΠΟΘΕΣΗ: Έχετε το αρχείο /static/sounds/notification.mp3)
    const notificationSound = new Audio('/static/sounds/notification.mp3'); 
    notificationSound.volume = 0.5;

    // Μεταφέρει τον scrollbar στο τέλος του chatbox κατά τη φόρτωση
    if(messageContainer) {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }

    // 🚨 2. Συνάρτηση για Parsing BBCode σε HTML (για να εμφανίζεται η μορφοποίηση)
    function parseBBCode(text) {
        // [b]bold[/b], [i]italic[/i], [u]underline[/u]
        text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<b>$1</b>');
        text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<i>$1</i>');
        text = text.replace(/\[u\](.*?)\[\/u\]/gs, '<u>$1</u>');
        // [color=#HEX]text[/color]
        text = text.replace(/\[color=(#[0-9A-Fa-f]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');
        // [url]link[/url]
        text = text.replace(/\[url\](http[s]?:\/\/[^\[]+)\[\/url\]/gs, '<a href="$1" target="_blank" style="color: var(--link-color);"> $1</a>');
        // [gif]url[/gif]
        text = text.replace(/\[gif\](http[s]?:\/\/[^\[]+)\[\/gif\]/gs, '<img src="$1" style="max-width:200px; max-height:150px; display:block; margin: 5px 0;" loading="lazy">');
        
        return text;
    }

    // 🚨 3. ΧΕΙΡΙΣΜΟΣ ΝΕΟΥ ΜΗΝΥΜΑΤΟΣ (SocketIO)
    socket.on('new_message', function(data) {
        if (!messageContainer) return;

        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message');
        const roleClass = `role-${data.role}`; 
        
        // Parsing του BBCode
        const formattedText = parseBBCode(data.message);
        
        const messageHtml = `
            <span class="${roleClass}" style="font-weight: 700;">${data.username}</span> 
            <span style="color: #bbb;">[${data.timestamp}]:</span> 
            ${formattedText}
        `;
        
        messageDiv.innerHTML = messageHtml;
        messageContainer.appendChild(messageDiv);
        messageContainer.scrollTop = messageContainer.scrollHeight;

        // Παίζει τον ήχο
        if (toggleSound && !toggleSound.checked) { // Ελέγχει αν το checkbox είναι UNCHECKED
             notificationSound.play().catch(e => console.log("Sound play prevented or file not found:", e));
        }
    });

    // 🚨 4. ΛΕΙΤΟΥΡΓΙΑ ΚΟΥΜΠΙΩΝ ΜΟΡΦΟΠΟΙΗΣΗΣ (BBCode Insertion)
    function applyFormatting(tag, placeholder) {
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const value = messageInput.value;

        let selectedText = value.substring(start, end);
        if (!selectedText) {
            selectedText = placeholder;
        }
        
        const openTag = `[${tag}]`;
        const closeTag = `[/${tag.split('=')[0]}]`;

        const newText = value.substring(0, start) + 
                        openTag + selectedText + closeTag + 
                        value.substring(end);
        
        messageInput.value = newText;
        messageInput.focus();
        
        // Τοποθέτηση cursor
        messageInput.selectionStart = start + openTag.length; 
        messageInput.selectionEnd = messageInput.selectionStart + selectedText.length;
    }

    // Attach click handlers to formatting buttons
    document.getElementById('bold-button').onclick = () => applyFormatting('b', 'bold text');
    document.getElementById('italic-button').onclick = () => applyFormatting('i', 'italic text');
    document.getElementById('underline-button').onclick = () => applyFormatting('u', 'underlined text');
    document.getElementById('url-button').onclick = () => applyFormatting('url', 'http://example.com');
    document.getElementById('gif-button').onclick = () => applyFormatting('gif', 'https://example.com/gif.gif');
    
    document.getElementById('color-picker-button').onclick = () => {
        colorInput.click();
    };

    colorInput.onchange = () => {
        applyFormatting(`color=${colorInput.value.toUpperCase()}`, 'colored text');
    };
    
    // 5. ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    sendButton.addEventListener('click', () => {
        const msg = messageInput.value.trim();
        if (msg) {
            socket.emit('send_message', { message: msg });
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