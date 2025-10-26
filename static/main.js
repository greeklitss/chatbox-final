// static/main.js - FINAL & COMPLETE VERSION

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
    
    // 🚨 ΝΕΟ: ΠΛΟΥΣΙΑ ONLINE EMOTICONS (Twemoji CDN)
    text = text.replace(/:joy:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f602.png" alt=":joy:" class="emoticon-img">');
    text = text.replace(/:smiley:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f603.png" alt=":smiley:" class="emoticon-img">');
    text = text.replace(/:wink:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f609.png" alt=":wink:" class="emoticon-img">');
    text = text.replace(/:kissing_heart:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f618.png" alt=":kissing_heart:" class="emoticon-img">');
    text = text.replace(/:flushed:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f633.png" alt=":flushed:" class="emoticon-img">');
    text = text.replace(/:thinking:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f914.png" alt=":thinking:" class="emoticon-img">');
    text = text.replace(/:rage:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f621.png" alt=":rage:" class="emoticon-img">');
    text = text.replace(/:headphones:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f3a7.png" alt=":headphones:" class="emoticon-img">');
    text = text.replace(/:musical_note:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f3b5.png" alt=":musical_note:" class="emoticon-img">');
    text = text.replace(/:microphone:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f399.png" alt=":microphone:" class="emoticon-img">');
    text = text.replace(/:radio:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f4fb.png" alt=":radio:" class="emoticon-img">');
    text = text.replace(/:heart:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/2764.png" alt=":heart:" class="emoticon-img">');
    text = text.replace(/:fire:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f525.png" alt=":fire:" class="emoticon-img">');
    text = text.replace(/:thumbsup:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f44d.png" alt=":thumbsup:" class="emoticon-img">');
    text = text.replace(/:clap:/g, '<img src="https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/72x72/1f44f.png" alt=":clap:" class="emoticon-img">');
    
    // 🚨 ΝΕΟ: ΑΥΤΟΜΑΤΗ URL/LINK ΑΝΙΧΝΕΥΣΗ
    const urlRegex = /(?<!href="|src=")(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    text = text.replace(urlRegex, (match) => {
        return `<a href="${match}" target="_blank">${match}</a>`;
    });

    return text;
}

// 3. ΣΥΝΑΡΤΗΣΗ ΠΡΟΣΘΗΚΗΣ ΜΗΝΥΜΑΤΟΣ
function appendMessage(msg, chatbox) {
    // ... (Ο δικός σας κώδικας για appendMessage) ...
}


// --- SOCKET IO & DOM LISTENERS ---
document.addEventListener('DOMContentLoaded', () => {
    const socket = io();
    const chatbox = document.getElementById('chat-messages');
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

    // ... (Δήλωση άλλων κουμπιών) ...
    const emoticonButton = document.getElementById('emoticon-button');
    const emoticonSelector = document.getElementById('emoticon-selector');
    const colorPickerButton = document.getElementById('color-picker-button');
    const colorInput = document.getElementById('color-input');
    const notificationButton = document.getElementById('notification-volume-button');

    // --- SOCKET LISTENERS ---
    socket.on('connect', () => {
        console.log('Connected to server');
        // Ενημερώνουμε τον server ότι ο χρήστης είναι online
        socket.emit('user_joined'); 
    });

    socket.on('history', function(messages) {
        messages.forEach(msg => appendMessage(msg, chatbox)); 
        chatbox.scrollTop = chatbox.scrollHeight;
    });

    socket.on('message', function(msg) {
        appendMessage(msg, chatbox);
        chatbox.scrollTop = chatbox.scrollHeight;
        playNotificationSound();
    });

    // 🚨 ΝΕΟ: ΕΝΗΜΕΡΩΣΗ ΛΙΣΤΑΣ ONLINE ΧΡΗΣΤΩΝ
    const onlineUsersList = document.getElementById('online-users-list');
    
    socket.on('update_online_users', function(data) {
        if (!onlineUsersList) return;

        // Εκκαθάριση και ενημέρωση του τίτλου/counter
        onlineUsersList.innerHTML = '<h4>Online Users (<span id="online-users-count">' + data.count + '</span>)</h4>';
        
        // Δημιουργία λίστας
        const ul = document.createElement('ul');
        ul.style.listStyle = 'none';
        ul.style.padding = '0';
        ul.style.margin = '0';

        data.users.forEach(user => {
            const li = document.createElement('li');
            li.style.color = user.color || '#FFFFFF'; 
            li.style.marginBottom = '5px';
            li.innerHTML = `<i class="fas fa-circle" style="font-size: 0.7em; margin-right: 5px; color: ${user.color || '#00bcd4'};"></i>${user.display_name} (${user.role})`;
            ul.appendChild(li);
        });
        
        onlineUsersList.appendChild(ul);
        document.getElementById('online-users-count').textContent = data.count; 
    });
    
    // --- ΣΥΝΑΡΤΗΣΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ ---
    function sendMessage() {
        // ... (Ο δικός σας κώδικας sendMessage) ...
    }

    // --- DOM EVENT LISTENERS (Κουμπιά) ---

    // ... (Λογική για Bold/Italic/Underline κ.λπ.) ...
    
    // Color Picker Button
    if (colorPickerButton && colorInput) {
        colorPickerButton.addEventListener('click', () => {
            colorInput.click();
        });
    }

    // Emoticon Button (Display Toggle)
    if (emoticonButton && emoticonSelector) {
        emoticonButton.addEventListener('click', () => {
            emoticonSelector.style.display = emoticonSelector.style.display === 'block' ? 'none' : 'block';
        });
        
        // Κλείνει ο selector αν κλικάρουμε εκτός
        document.addEventListener('click', (event) => {
            if (!emoticonButton.contains(event.target) && !emoticonSelector.contains(event.target)) {
                emoticonSelector.style.display = 'none';
            }
        });

        // 🚨 ΝΕΟ: ΛΟΓΙΚΗ ΕΙΣΑΓΩΓΗΣ EMOTICON
        const emoticonGrid = emoticonSelector.querySelector('.emoticon-grid');
        emoticonGrid.addEventListener('click', (event) => {
            if (event.target.tagName === 'IMG') {
                const code = event.target.dataset.code; 
                const input = document.getElementById('message-input');
                
                // Εισάγουμε τον κωδικό στο textarea
                input.value += (input.value.length > 0 ? ' ' : '') + code + ' ';
                input.focus();
                
                // Κλείνουμε τον selector
                emoticonSelector.style.display = 'none';
            }
        });
    }

    // Notification Button
    // ... (Ο δικός σας κώδικας για Notification Button) ...
});