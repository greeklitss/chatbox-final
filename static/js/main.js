function initializeChat() {
    // 1. Αρχικοποίηση Socket.IO 
    const socket = io(); 

    // 2. ΟΡΙΣΜΟΣ ΤΩΝ DOM ΣΤΟΙΧΕΙΩΝ
    const messageInput = document.getElementById('message-input');      
    const sendButton = document.getElementById('send-button');          
    const chatBox = document.getElementById('chatbox');                 
    
    // Κουμπιά Μορφοποίησης
    const boldButton = document.getElementById('bold-button');
    const italicButton = document.getElementById('italic-button');
    const colorPickerButton = document.getElementById('color-picker-button');
    const colorInput = document.getElementById('color-input'); 

    // 3. ΜΕΤΑΒΛΗΤΗ ΚΑΤΑΣΤΑΣΗΣ ΜΟΡΦΟΠΟΙΗΣΗΣ
    let format = {
        isBold: false,
        isItalic: false,
        color: '#FFFFFF' 
    };

    // 4. LISTENERS ΜΟΡΦΟΠΟΙΗΣΗΣ
    if (boldButton) {
        boldButton.addEventListener('click', () => {
            format.isBold = !format.isBold;
            boldButton.classList.toggle('active', format.isBold); 
            messageInput.focus();
        });
    }

    if (italicButton) {
        italicButton.addEventListener('click', () => {
            format.isItalic = !format.isItalic;
            italicButton.classList.toggle('active', format.isItalic);
            messageInput.focus();
        });
    }
    
    if (colorPickerButton && colorInput) {
        colorPickerButton.addEventListener('click', () => {
            colorInput.click(); 
        });
        colorInput.addEventListener('change', (e) => {
            format.color = e.target.value;
            colorPickerButton.style.color = format.color; 
            messageInput.focus();
        });
    }

    // 5. ΛΟΓΙΚΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ
    if (sendButton && messageInput) {
        const sendMessage = () => {
            const message = messageInput.value;
            if (message.trim() !== '') {
                socket.emit('send_message', { 
                    'message': message,
                    'format': format 
                }); 
                messageInput.value = ''; 
            }
        };

        sendButton.addEventListener('click', sendMessage);

        messageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault(); 
                sendMessage();
            }
        });
    }


    // 6. SOCKET LISTENERS
    
    socket.on('connect', function() {
        console.log('Συνδέθηκε με τον server!');
    });

    socket.on('status', function(data) {
        console.log('Server Status:', data.msg);
    });

    // 7. Listener για λήψη και εμφάνιση μηνυμάτων
    socket.on('new_message', function(data) {
        if (!chatBox) return;

        const newMessageDiv = document.createElement('div');
        const userSpan = document.createElement('span');
        const messageSpan = document.createElement('span');
        
        const receivedFormat = data.format || { isBold: false, isItalic: false, color: '#FFFFFF' };
        
        messageSpan.textContent = data.message;
        
        // Εφαρμογή CSS styling
        if (receivedFormat.isBold) {
            messageSpan.style.fontWeight = 'bold';
        }
        if (receivedFormat.isItalic) {
            messageSpan.style.fontStyle = 'italic';
        }
        messageSpan.style.color = receivedFormat.color;
        
        userSpan.textContent = `[${data.timestamp}] ${data.user}: `;
        userSpan.style.fontWeight = 'bold';

        newMessageDiv.appendChild(userSpan);
        newMessageDiv.appendChild(messageSpan);
        
        chatBox.appendChild(newMessageDiv);
        chatBox.scrollTop = chatBox.scrollHeight; // Scroll down
    });

    console.log("Chat Initialization complete.");
}

// ----------------------------------------------------------------------
// 🚨 ΣΩΣΤΗ ΘΕΣΗ: TOP LEVEL FUNCTION (ΕΚΤΟΣ initializeChat)
// ----------------------------------------------------------------------

function startMetadataScrolling() {
    const scroller = document.getElementById('metadata-scroller');
    if (!scroller) return;

    scroller.textContent = "Web Radio Chatbox | Now Playing: [Artist] - [Title] | Next: [Artist] - [Title] | Welcome to the Neon Chat!";

    const duration = scroller.textContent.length * 0.2; 
    
    scroller.style.animation = `scroll-metadata ${duration}s linear infinite`;

    if (!document.getElementById('scroll-style')) {
         const style = document.createElement('style');
         style.id = 'scroll-style';
         style.textContent = `
             @keyframes scroll-metadata {
                 0%   { transform: translate(100%, 0); } 
                 100% { transform: translate(-100%, 0); } 
             }
         `;
         document.head.appendChild(style);
    }
}


// --- ΚΛΗΣΗ ΛΕΙΤΟΥΡΓΙΩΝ ΜΕΤΑ ΤΟ ΦΟΡΤΩΜΑ ΤΟΥ DOM ---

document.addEventListener('DOMContentLoaded', () => {
    // 1. Καλεί τη βασική λειτουργία chat
    initializeChat(); 
    
    // 2. Καλεί τη λειτουργία scrolling metadata
    startMetadataScrolling(); 
    
    // 3. Ρύθμιση έντασης ήχου
    const audio = document.getElementById('audio-stream');
    if (audio) {
        audio.volume = 0.3; // Αρχική ένταση 30%
    }
});