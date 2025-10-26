// static/main.js - ΟΡΙΣΤΙΚΗ & ΛΕΙΤΟΥΡΓΙΚΗ ΕΚΔΟΣΗ ΓΙΑ ΤΟ CHAT

let isNotificationSoundEnabled = true;
let selectedColor = '#FF0066'; // Default χρώμα μηνύματος

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
    // Διόρθωση στο URL tag: χρησιμοποιεί $2 για το κείμενο
    text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>'); 
    text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" alt="User Image" style="max-width:100%; height:auto; display: block; margin-top: 5px;">');
    
    // Καθαρισμός τυχόν tags που δεν υποστηρίζονται
    text = text.replace(/\[\/?(emoticon)[^\]]*\]/g, ''); 
    
    // ΠΛΟΥΣΙΑ ONLINE EMOTICONS (Twemoji CDN)
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
    
    // ΑΥΤΟΜΑΤΗ URL/LINK ΑΝΙΧΝΕΥΣΗ (Μόνο αν δεν είναι ήδη μέσα σε [url] ή [img])
    const urlRegex = /(?<!href="|src=")(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    text = text.replace(urlRegex, (match) => {
        return `<a href="${match}" target="_blank">${match}</a>`;
    });

    return text;
}

// 3. ΣΥΝΑΡΤΗΣΗ ΠΡΟΣΘΗΚΗΣ ΜΗΝΥΜΑΤΟΣ (ΚΡΙΣΙΜΗ ΓΙΑ ΤΗΝ ΕΜΦΑΝΙΣΗ)
function appendMessage(msg) { 
    
    // 🚨 ΔΙΟΡΘΩΣΗ: Χρησιμοποιούμε το ΣΩΣΤΟ ID: chat-messages (όπως στο chat.html)
    const chatbox = document.getElementById('chat-messages'); 
    if (!chatbox) {
        console.error("Chatbox element not found (ID: chat-messages)");
        return; 
    } 

    if (!msg.msg && !msg.system) return;

    // Ελέγχουμε αν είναι μήνυμα συστήματος
    if (msg.system) {
        const date = new Date();
        const timeString = date.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit' });

        const systemElement = document.createElement('div');
        systemElement.classList.add('message');
        systemElement.classList.add('system-message');
        systemElement.innerHTML = `<span class="timestamp">${timeString}</span> <span class="system-text">${msg.msg}</span>`;
        chatbox.appendChild(systemElement);
        // Εγγύηση scroll στο κάτω μέρος
        chatbox.scrollTop = chatbox.scrollHeight;
        return;
    }
    
    // Εμφάνιση ώρας/ημερομηνίας
    let date;
    if (msg.timestamp) {
        // Χειρισμός ISO String από τον server
        date = new Date(msg.timestamp);
    } else {
        // Χρήση τρέχουσας ώρας αν δεν υπάρχει timestamp
        date = new Date();
    }
    const timeString = date.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit' });

    // Κανονικό μήνυμα χρήστη
    const userColor = msg.color || '#FFFFFF';
    const avatarUrl = msg.avatar_url || '/static/default_avatar.png'; // Χρησιμοποιήστε default αν δεν υπάρχει
    const parsedContent = parseBBCode(msg.msg);
    const roleIcon = msg.role === 'owner' ? '<i class="fas fa-crown owner-icon" title="Owner"></i>' : 
                     (msg.role === 'admin' ? '<i class="fas fa-shield-alt admin-icon" title="Admin"></i>' : '');

    const messageContainer = document.createElement('div');
    messageContainer.classList.add('message-container');
    
    const messageHTML = `
        <img src="${avatarUrl}" alt="Avatar" class="avatar">
        <div class="message-content">
            <div class="message-header">
                <span class="username" style="color: ${userColor};">${msg.username} ${roleIcon}</span>
                <span class="timestamp">${timeString}</span>
            </div>
            <div class="message-box">
                ${parsedContent}
            </div>
        </div>
    `;

    messageContainer.innerHTML = messageHTML;
    chatbox.appendChild(messageContainer);
    
    // Εγγύηση scroll στο κάτω μέρος
    chatbox.scrollTop = chatbox.scrollHeight;
}

// --- SOCKET IO & DOM LISTENERS ---
document.addEventListener('DOMContentLoaded', () => {
    // 🚨 ΔΙΟΡΘΩΣΗ: ΧΡΗΣΗ transports ΓΙΑ ΣΥΜΒΑΤΟΤΗΤΑ ΜΕ PROXY/RENDER
    const socket = io({ transports: ['websocket', 'polling'] }); 
    
    // 🚨 ΔΙΟΡΘΩΣΗ: ΧΡΗΣΗ ΤΟΥ ΣΩΣΤΟΥ ID: chat-messages
    const chatbox = document.getElementById('chat-messages'); 
    
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

    const boldButton = document.getElementById('bold-button');
    const italicButton = document.getElementById('italic-button');
    const underlineButton = document.getElementById('underline-button');
    const emoticonButton = document.getElementById('emoticon-button');
    const emoticonSelector = document.getElementById('emoticon-selector');
    const colorPickerButton = document.getElementById('color-picker-button');
    const colorInput = document.getElementById('color-input');
    const notificationButton = document.getElementById('notification-volume-button');
    const gifButton = document.getElementById('gif-button'); 
    
    // selectedColor παίρνει τιμή από το input color
    let selectedColor = colorInput ? colorInput.value : '#FF0066'; 

    // --- SOCKET LISTENERS ---
    socket.on('connect', () => {
        console.log('Connected to server');
        socket.emit('join'); 
    });

    // Λήψη ιστορικού
    socket.on('history', function(messages) {
        if (chatbox) chatbox.innerHTML = ''; // Καθαρισμός
        messages.forEach(appendMessage); 
        if (chatbox) chatbox.scrollTop = chatbox.scrollHeight;
    });

    // Λήψη νέου μηνύματος
    socket.on('message', function(msg) {
        appendMessage(msg); 
        playNotificationSound();
    });
    
    // Λήψη status messages (π.χ., user joined/left)
    socket.on('status_message', function(data) {
        appendMessage({...data, system: true}); 
    });

    // Ενημέρωση λίστας online χρηστών
    const onlineUsersList = document.getElementById('online-users-list');
    socket.on('update_online_users', function(data) {
        if (!onlineUsersList) return;

        onlineUsersList.innerHTML = '<h4>Online Users (<span id="online-users-count">' + data.count + '</span>)</h4>';
        
        const ul = document.createElement('ul');
        ul.style.listStyle = 'none';
        ul.style.padding = '0';
        ul.style.margin = '0';

        data.users.forEach(user => {
            const li = document.createElement('li');
            li.style.color = user.color || '#AAAAAA'; 
            li.style.marginBottom = '5px';
            const role_class = user.role === 'owner' ? 'owner-text' : (user.role === 'admin' ? 'admin-text' : '');
            // Προσθήκη στυλ για να φαίνονται τα εικονίδια
            const color_style = user.role === 'owner' ? 'style="color: var(--primary-color);"' : 
                                (user.role === 'admin' ? 'style="color: var(--secondary-color);"' : '');

            li.innerHTML = `<i class="fas fa-circle ${role_class}" ${color_style} style="font-size: 0.7em; margin-right: 5px;"></i>${user.display_name} (${user.role})`;
            ul.appendChild(li);
        });
        
        onlineUsersList.appendChild(ul);
        document.getElementById('online-users-count').textContent = data.count; 
    });
    
    // --- ΣΥΝΑΡΤΗΣΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ (ΚΡΙΣΙΜΗ ΓΙΑ ΤΗ ΛΕΙΤΟΥΡΓΙΑ) ---
    function sendMessage() {
        const msg = messageInput.value.trim();
        if (msg) {
            // Εκπέμπουμε το μήνυμα στον server μαζί με το επιλεγμένο χρώμα
            socket.emit('message', { 
                msg: msg,
                color: selectedColor 
            });
            messageInput.value = ''; // Καθαρισμός του input
            messageInput.style.height = 'auto'; // Επαναφορά ύψους
        }
    }

    // --- DOM EVENT LISTENERS (Κουμπιά & Input) ---

    // 1. Send Button & Enter Key
    sendButton.addEventListener('click', sendMessage);
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
    
    // 2. Formatting Buttons Helper
    function wrapText(tag) {
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        const selectedText = messageInput.value.substring(start, end);
        
        const newText = `[${tag}]${selectedText}[/${tag}]`;
        
        messageInput.value = messageInput.value.substring(0, start) + newText + messageInput.value.substring(end);
        
        // Τοποθέτηση του cursor μετά το κλειστό tag
        const newCursorPos = start + newText.length;
        messageInput.setSelectionRange(newCursorPos, newCursorPos);
        messageInput.focus();
    }
    
    boldButton.addEventListener('click', () => wrapText('b'));
    italicButton.addEventListener('click', () => wrapText('i'));
    underlineButton.addEventListener('click', () => wrapText('u'));
    
    // 3. Color Picker
    colorPickerButton.addEventListener('click', () => {
        colorInput.click();
    });
    colorInput.addEventListener('input', (e) => {
        selectedColor = e.target.value; // Ενημέρωση του selectedColor
        colorPickerButton.style.color = selectedColor; 
    });

    // 4. Emoticon Button (Toggle Display)
    if (emoticonButton && emoticonSelector) {
        emoticonButton.addEventListener('click', () => {
            emoticonSelector.style.display = emoticonSelector.style.display === 'block' ? 'none' : 'block';
        });
        
        // Κλείσιμο selector αν κλικάρουμε εκτός
        document.addEventListener('click', (event) => {
            if (!emoticonButton.contains(event.target) && !emoticonSelector.contains(event.target)) {
                emoticonSelector.style.display = 'none';
            }
        });

        // ΛΟΓΙΚΗ ΕΙΣΑΓΩΓΗΣ EMOTICON
        const emoticonGrid = emoticonSelector.querySelector('.emoticon-grid');
        if (emoticonGrid) { 
            emoticonGrid.addEventListener('click', (event) => {
                if (event.target.tagName === 'IMG' && event.target.dataset.code) { 
                    const code = event.target.dataset.code; 
                    
                    messageInput.value += (messageInput.value.length > 0 ? ' ' : '') + code + ' ';
                    messageInput.focus();
                    
                    messageInput.style.height = 'auto';
                    messageInput.style.height = (messageInput.scrollHeight) + 'px';
                    
                    emoticonSelector.style.display = 'none';
                }
            });
        }
    }

    // 5. Notification Button (Volume)
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
    
    // 6. GIF Button
    if(gifButton){
        gifButton.addEventListener('click', () => {
            const imageUrl = prompt("Please paste the full image/GIF URL here:");
            if (imageUrl) {
                const imgTag = `[img]${imageUrl}[/img]`;
                messageInput.value += imgTag;
                messageInput.focus();
            }
        });
    }

});