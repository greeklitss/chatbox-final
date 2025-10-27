// static/main.js - ΟΡΙΣΤΙΚΗ & ΠΛΗΡΩΣ ΔΙΟΡΘΩΜΕΝΗ ΕΚΔΟΣΗ
// Περιλαμβάνει: Scroll Fix, BBCode Logic (χωρίς εμφάνιση tags), Color to Text, Role Display.

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
    text = text.replace(/\[size=(\d+)\](.*?)\[\/size\]/gs, '<span style="font-size:$1px;">$2</span>');
    
    // ΔΙΟΡΘΩΣΗ: [color] tag
    text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color:$1;">$2</span>');
    
    text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>'); 
    text = text.replace(/\[img\](.*?)\[\/img\]/gsi, '<img src="$1" alt="User Image" style="max-width:100%; height:auto; display: block; margin-top: 5px;">');
    
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
    
    // ΑΥΤΟΜΑΤΗ URL/LINK ΑΝΙΧΝΕΥΣΗ 
    const urlRegex = /(?<!href="|src=")(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    text = text.replace(urlRegex, (match) => {
        return `<a href="${match}" target="_blank">${match}</a>`;
    });

    return text;
}

// 3. ΣΥΝΑΡΤΗΣΗ ΠΡΟΣΘΗΚΗΣ ΜΗΝΥΜΑΤΟΣ 
function appendMessage(msg) { 
    
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
        date = new Date(msg.timestamp);
    } else {
        date = new Date();
    }
    const timeString = date.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit' });

    // Κανονικό μήνυμα χρήστη
    // Καθορισμός χρώματος username βάσει ρόλου για εμφάνιση
    let usernameColor = msg.color || 'var(--default-user-color, #FFFFFF)'; 
    if (msg.role === 'owner') {
         usernameColor = 'var(--primary-color, #ff3399)'; 
    } else if (msg.role === 'admin') {
         usernameColor = 'var(--secondary-color, #00e6e6)'; 
    }
    
    const avatarUrl = msg.avatar_url || '/static/default_avatar.png'; 
    const parsedContent = parseBBCode(msg.msg);
    const roleIcon = msg.role === 'owner' ? '<i class="fas fa-crown owner-icon" title="Owner"></i>' : 
                     (msg.role === 'admin' ? '<i class="fas fa-shield-alt admin-icon" title="Admin"></i>' : '');

    const messageContainer = document.createElement('div');
    messageContainer.classList.add('message-container');
    
    const messageHTML = `
        <img src="${avatarUrl}" alt="Avatar" class="avatar">
        <div class="message-content">
            <div class="message-header">
                <span class="username" style="color: ${usernameColor};">${msg.username} ${roleIcon}</span>
                <span class="timestamp">${timeString}</span>
            </div>
            <div class="message-box">
                ${parsedContent}
            </div>
        </div>
    `;

    messageContainer.innerHTML = messageHTML;
    chatbox.appendChild(messageContainer);
    
    // 🚨 ΚΡΙΣΙΜΟ: Εγγύηση scroll στο κάτω μέρος
    chatbox.scrollTop = chatbox.scrollHeight;
}

// --- SOCKET IO & DOM LISTENERS ---
document.addEventListener('DOMContentLoaded', () => {
    
    const socket = io({ transports: ['websocket', 'polling'] }); 
    const chatbox = document.getElementById('chat-messages'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');

    const boldButton = document.getElementById('bold-button');
    const italicButton = document.getElementById('italic-button');
    const underlineButton = document.getElementById('underline-button');
    const sizeButton = document.getElementById('size-button');
    const emoticonButton = document.getElementById('emoticon-button');
    const emoticonSelector = document.getElementById('emoticon-selector');
    const colorPickerButton = document.getElementById('color-picker-button');
    const colorInput = document.getElementById('color-input');
    const notificationButton = document.getElementById('notification-volume-button');
    const gifButton = document.getElementById('gif-button'); 
    
    let selectedColor = colorInput ? colorInput.value : '#FF0066'; 

    // --- SOCKET LISTENERS ---
    socket.on('connect', () => {
        console.log('Connected to server');
        socket.emit('join'); 
    });

    // Λήψη ιστορικού
    socket.on('history', function(messages) {
        if (chatbox) chatbox.innerHTML = ''; 
        messages.forEach(appendMessage); 
        if (chatbox) chatbox.scrollTop = chatbox.scrollHeight;
    });

    // Λήψη νέου μηνύματος
    socket.on('message', function(msg) {
        appendMessage(msg); 
        playNotificationSound();
    });
    
    // Λήψη status messages 
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
            
            // Ορισμός class βάσει ρόλου για το CSS styling
            const role_class = user.role === 'owner' ? 'owner-text' : (user.role === 'admin' ? 'admin-text' : 'user-text');
            
            li.innerHTML = `<i class="fas fa-circle ${role_class}" style="font-size: 0.7em; margin-right: 5px;"></i>${user.display_name} (${user.role})`;
            ul.appendChild(li);
        });
        
        onlineUsersList.appendChild(ul);
        document.getElementById('online-users-count').textContent = data.count; 
    });
    
    // --- ΣΥΝΑΡΤΗΣΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ ---
    function sendMessage() {
        const msg = messageInput.value.trim();
        if (msg) {
            socket.emit('message', { 
                msg: msg
            });
            messageInput.value = ''; 
            messageInput.style.height = 'auto'; 
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
    
// ... (Τέλος του messageInput.addEventListener('input', ...)
    
// 2. Formatting Buttons Helper (BBCode Logic)
// 🚨 ΔΙΟΡΘΩΣΗ: Η λογική που δεν εμφανίζει tags όταν δεν υπάρχει επιλογή κειμένου.
function applyFormat(tag, value = null) { // Αφαιρέθηκε η παράμετρος isColorOrSize
    const start = messageInput.selectionStart;
    const end = messageInput.selectionEnd;
    const selectedText = messageInput.value.substring(start, end);
    
    // Κατασκευή των tags. value χρησιμοποιείται για color=#HEX ή size=N
    const tagsOpen = `[${tag}${value !== null ? '=' + value : ''}]`;
    const tagsClose = `[/${tag}]`;
    
    if (selectedText.length > 0) {
        // Περίπτωση 1: Υπάρχει επιλεγμένο κείμενο
        const newText = tagsOpen + selectedText + tagsClose;
        
        messageInput.value = messageInput.value.substring(0, start) + newText + messageInput.value.substring(end);
        
        // Τοποθέτηση του cursor μετά το κλειστό tag
        const newCursorPos = start + newText.length;
        messageInput.setSelectionRange(newCursorPos, newCursorPos);
    } else {
        // Περίπτωση 2: ΔΕΝ υπάρχει επιλεγμένο κείμενο (Εισαγωγή μόνο των tags με τον κέρσο μέσα)
        const tags = tagsOpen + tagsClose;
        messageInput.value = messageInput.value.substring(0, start) + tags + messageInput.value.substring(end);
        // Τοποθετούμε τον κέρσο μέσα στα tags
        messageInput.setSelectionRange(start + tagsOpen.length, start + tagsOpen.length);
    }
    messageInput.focus();
}

boldButton.addEventListener('click', () => applyFormat('b'));
italicButton.addEventListener('click', () => applyFormat('i'));
underlineButton.addEventListener('click', () => applyFormat('u'));

// 🚨 ΔΙΟΡΘΩΜΕΝΗ ΛΟΓΙΚΗ: Size Button (Χρησιμοποιεί την applyFormat)
if (sizeButton) {
    sizeButton.addEventListener('click', () => {
        const sizeValue = prompt("Enter text size in pixels (e.g., 16, 20, 24):");
        
        if (sizeValue && !isNaN(parseInt(sizeValue)) && parseInt(sizeValue) > 0) {
            applyFormat('size', parseInt(sizeValue));
        } else if (sizeValue !== null) {
            alert("Invalid size. Please enter a positive number.");
        }
    });
}

// 3. Color Picker (Τώρα χρησιμοποιεί την ίδια λογική για εισαγωγή tags)
colorPickerButton.addEventListener('click', () => {
    colorInput.click();
});

colorInput.addEventListener('input', (e) => {
    selectedColor = e.target.value; 
    colorPickerButton.style.color = selectedColor; 
    
    // Εφαρμόζουμε το [color] tag στο επιλεγμένο κείμενο
    applyFormat('color', selectedColor);
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