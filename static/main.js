// static/main.js - ΟΛΟΚΛΗΡΩΜΕΝΗ & ΤΕΛΙΚΗ ΕΚΔΟΣΗ
// Περιλαμβάνει: Notification Sound, Scroll Logic, BBCode/Emoticon Parser (με globalSettings), 
// appendMessage, Feature Toggles, Emoticon Selector Initialization, SocketIO Listeners & DOM Listeners.

// 🚨 ΥΠΟΘΕΤΟΥΜΕ ΟΤΙ ΟΙ globalSettings και globalEmoticons ΕΧΟΥΝ ΟΡΙΣΤΕΙ ΣΤΟ chat.html
// const globalSettings = { "feature_bold": "True", "feature_italic": "True", ... };
// let globalEmoticons = { ":smile:": "/url/smile.gif", ... };

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

// 2. Message Scroller (Αποτρέπει το scroll αν ο χρήστης διαβάζει παλαιότερα μηνύματα)
function scrollChatToBottom(chatbox, force = false) {
    const isNearBottom = chatbox.scrollHeight - chatbox.clientHeight <= chatbox.scrollTop + 50;
    
    if (force || isNearBottom) {
        chatbox.scrollTop = chatbox.scrollHeight;
    }
}

// 3. BBCode & Emoticon Parser
function parseBBCode(text) {
    if (!text) return '';
    
    // Εφαρμογή των settings για τα BBCode
    if (typeof globalSettings !== 'undefined' && globalSettings.feature_bold === 'True') {
        text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<strong>$1</strong>');
    }
    if (typeof globalSettings !== 'undefined' && globalSettings.feature_italic === 'True') {
        text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<em>$1</em>');
    }
    if (typeof globalSettings !== 'undefined' && globalSettings.feature_underline === 'True') {
        text = text.replace(/\[u\](.*?)\[\/u\]/gs, '<u>$1</u>');
    }
    if (typeof globalSettings !== 'undefined' && globalSettings.feature_size === 'True') {
        text = text.replace(/\[size=(\d+)\](.*?)\[\/size\]/gs, (match, size, content) => {
            const sizeInt = parseInt(size, 10);
            if (sizeInt >= 8 && sizeInt <= 36) { // Όριο μεγέθους
                return `<span style="font-size: ${sizeInt}px;">${content}</span>`;
            }
            return content; 
        });
    }
    if (typeof globalSettings !== 'undefined' && globalSettings.feature_color === 'True') {
        text = text.replace(/\[color=(#[0-9a-fA-F]{3,6})\](.*?)\[\/color\]/gs, '<span style="color: $1;">$2</span>');
    }
    if (typeof globalSettings !== 'undefined' && globalSettings.feature_url === 'True') {
        text = text.replace(/\[url=(.*?)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank" rel="noopener noreferrer">$2</a>');
        text = text.replace(/\[url\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>');
    }
    if (typeof globalSettings !== 'undefined' && globalSettings.feature_img === 'True') {
        text = text.replace(/\[img\](.*?)\[\/img\]/gs, '<img src="$1" alt="image" loading="lazy" class="embedded-image" onclick="window.open(\'$1\', \'_blank\');">');
    }
    
    // Emoticon replacement
    if (typeof globalEmoticons !== 'undefined') {
        for (const tag in globalEmoticons) {
            const url = globalEmoticons[tag];
            const imgTag = `<img src="${url}" alt="${tag}" class="emoticon-img">`;
            // Αντικατάσταση μόνο ολόκληρων λέξεων
            const regex = new RegExp(`(?<=^|\\s)${tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?=$|\\s)`, 'g');
            text = text.replace(regex, imgTag);
        }
    }
    
    // ΑΥΤΟΜΑΤΗ URL/LINK ΑΝΙΧΝΕΥΣΗ (τελευταία)
    const urlRegex = /(?<!href="|src=")(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    text = text.replace(urlRegex, (match) => {
        // Ελέγχουμε αν είναι ήδη μέσα σε [url] tag
        if (text.match(/\[url\](.*?)\[\/url\]/gs) || text.match(/\[url=(.*?)\](.*?)\[\/url\]/gs)) {
             return match; 
        }
        return `<a href="${match}" target="_blank" rel="noopener noreferrer">${match}</a>`;
    });

    return text;
}


// 4. ΣΥΝΑΡΤΗΣΗ ΠΡΟΣΘΗΚΗΣ ΜΗΝΥΜΑΤΟΣ
function appendMessage(msg, chatbox) { 
    if (!chatbox) {
        console.error("Chatbox element not found (ID: chat-box)"); 
        return; 
    } 

    if (!msg.msg && !msg.system) return;

    // Μηνύματα συστήματος
    if (msg.system) {
        const date = new Date(msg.timestamp || Date.now());
        const timeString = date.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit' });

        const systemElement = document.createElement('div');
        systemElement.classList.add('message', 'system-message');
        systemElement.innerHTML = `<span class="timestamp">${timeString}</span> <span class="system-text">${msg.msg}</span>`;
        chatbox.appendChild(systemElement);
        
        scrollChatToBottom(chatbox, true); 
        return;
    }
    
    // Κανονικό μήνυμα χρήστη
    const date = msg.timestamp ? new Date(msg.timestamp) : new Date();
    const timeString = date.toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit' });

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
    
    scrollChatToBottom(chatbox);
}


// 5. INITIALIZATION OF EMOTICON SELECTOR
function initializeEmoticonSelector(emoticons) {
    const emoticonSelector = document.getElementById('emoticon-selector');
    if (!emoticonSelector) return;
    
    emoticonSelector.innerHTML = ''; // Clear previous content
    
    // Δημιουργία των emoticons στο selector
    for (const tag in emoticons) {
        const url = emoticons[tag];
        const emoteButton = document.createElement('button');
        emoteButton.classList.add('emoticon-option');
        emoteButton.setAttribute('title', tag);
        emoteButton.innerHTML = `<img src="${url}" alt="${tag}" class="emoticon-img">`;
        
        emoteButton.addEventListener('click', () => {
            const messageInput = document.getElementById('message-input');
            messageInput.value += ` ${tag} `; // Προσθήκη του tag στο input
            messageInput.focus();
            emoticonSelector.style.display = 'none'; // Κλείσιμο του selector
            // Autoresize 
            messageInput.style.height = 'auto';
            messageInput.style.height = (messageInput.scrollHeight) + 'px';
        });
        
        emoticonSelector.appendChild(emoteButton);
    }
}


// 6. BBCode Button Toggles (ΝΕΟ)
function applyFeatureToggles() {
    if (typeof globalSettings === 'undefined') return;

    // Βρίσκουμε τα κουμπιά
    const boldButton = document.getElementById('bold-button');
    const italicButton = document.getElementById('italic-button');
    const underlineButton = document.getElementById('underline-button');
    const linkButton = document.getElementById('link-button');
    const gifButton = document.getElementById('gif-button');
    const sizeButton = document.getElementById('size-button');
    const colorButton = document.getElementById('color-picker-button');
    const emoticonButton = document.getElementById('emoticon-button');
    const colorInput = document.getElementById('color-input'); // Χρειάζεται για απόκρυψη

    // Λογική απόκρυψης/εμφάνισης
    if (boldButton) boldButton.style.display = globalSettings.feature_bold === 'False' ? 'none' : 'inline-block';
    if (italicButton) italicButton.style.display = globalSettings.feature_italic === 'False' ? 'none' : 'inline-block';
    if (underlineButton) underlineButton.style.display = globalSettings.feature_underline === 'False' ? 'none' : 'inline-block';
    if (linkButton) linkButton.style.display = globalSettings.feature_url === 'False' ? 'none' : 'inline-block';
    if (gifButton) gifButton.style.display = globalSettings.feature_img === 'False' ? 'none' : 'inline-block';
    if (sizeButton) sizeButton.style.display = globalSettings.feature_size === 'False' ? 'none' : 'inline-block';
    if (colorButton) colorButton.style.display = globalSettings.feature_color === 'False' ? 'none' : 'inline-block';
    if (emoticonButton) emoticonButton.style.display = globalSettings.feature_emoticons === 'False' ? 'none' : 'inline-block';
    
    if (colorInput && globalSettings.feature_color === 'False') {
        colorInput.style.display = 'none';
    }
    
    // Αρχικοποίηση Emoticon Selector (χρησιμοποιώντας τα globalEmoticons)
    if (typeof globalEmoticons !== 'undefined') {
        initializeEmoticonSelector(globalEmoticons);
    }
}


// --- SOCKETIO & DOM LISTENERS ---

// 7. Δήλωση socket (Χρειάζεται να είναι προσβάσιμο από τους listeners)
const socket = io({ transports: ['websocket', 'polling'] }); 


// --- SOCKETIO EVENT LISTENERS ---

socket.on('connect', () => {
    console.log('Connected to server');
    socket.emit('join'); 
});

socket.on('message', function(msg) {
    const chatbox = document.getElementById('chat-box');
    appendMessage(msg, chatbox); 
    playNotificationSound();
});

socket.on('history', function(messages) {
    const chatbox = document.getElementById('chat-box');
    if (chatbox) chatbox.innerHTML = ''; 
    messages.forEach(m => appendMessage(m, chatbox)); 
    // Scroll με force=true για αρχικό φόρτωμα
    if (chatbox) scrollChatToBottom(chatbox, true); 
});

socket.on('status_message', function(data) {
    const chatbox = document.getElementById('chat-box');
    appendMessage({...data, system: true}, chatbox); 
});

socket.on('update_online_users', function(data) {
    const onlineUsersListContainer = document.getElementById('online-users-list');
    if (!onlineUsersListContainer) return;

    onlineUsersListContainer.innerHTML = ''; 

    const h4 = document.createElement('h4');
    h4.innerHTML = `Online Users (<span id="online-users-count">${data.count}</span>)`;
    onlineUsersListContainer.appendChild(h4);
    
    const ul = document.createElement('ul');
    ul.style.listStyle = 'none';
    ul.style.padding = '0';
    ul.style.margin = '0';

    data.users.forEach(user => {
        const li = document.createElement('li');
        
        const role_class = user.role === 'owner' ? 'owner-text' : (user.role === 'admin' ? 'admin-text' : 'user-text');
        const role_icon = user.role === 'owner' ? '<i class="fas fa-crown"></i> ' : (user.role === 'admin' ? '<i class="fas fa-shield-alt"></i> ' : '');
        
        li.innerHTML = `<i class="fas fa-circle ${role_class}" style="font-size: 0.7em; margin-right: 5px;"></i> ${role_icon} <span class="${role_class}" style="color: ${user.color};">${user.display_name}</span>`;
        ul.appendChild(li);
    });
    
    onlineUsersListContainer.appendChild(ul);
});

socket.on('radio_metadata_update', function(data) {
    const radioMetadataDisplay = document.getElementById('radio-metadata');
    if (radioMetadataDisplay) {
        radioMetadataDisplay.textContent = data.title || 'Live Stream';
    }
});

socket.on('emoticon_updated', async (data) => {
    // Ενημέρωση του globalEmoticons
    try {
        const response = await fetch('/api/emoticons/enabled');
        if (response.ok) {
            window.globalEmoticons = await response.json(); // Ενημέρωση της καθολικής μεταβλητής
            initializeEmoticonSelector(globalEmoticons); 
        }
    } catch (e) {
        console.error('Failed to fetch updated emoticons:', e);
    }
    console.log(data.message); 
});

socket.on('setting_updated', (data) => {
    // Ενημέρωση του globalSettings
    if (typeof globalSettings !== 'undefined') {
        globalSettings[data.key] = data.value;
        applyFeatureToggles(); // Εφαρμογή των αλλαγών στα κουμπιά
    }
});


// 8. DOM CONTENT LOADED
document.addEventListener('DOMContentLoaded', () => {
    
    // --- ΤΟΠΙΚΟΙ ΟΡΙΣΜΟΙ DOM ELEMENTS ---
    const chatbox = document.getElementById('chat-box'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const audioStream = document.getElementById('audio-stream');
    const radioToggleButton = document.getElementById('radio-toggle-button');
    const colorInput = document.getElementById('color-input');
    const colorPickerButton = document.getElementById('color-picker-button');
    const emoticonButton = document.getElementById('emoticon-button');
    const emoticonSelector = document.getElementById('emoticon-selector');
    const notificationButton = document.getElementById('notification-volume-button');
    const gifButton = document.getElementById('gif-button');
    const boldButton = document.getElementById('bold-button');
    const italicButton = document.getElementById('italic-button');
    const underlineButton = document.getElementById('underline-button');
    const sizeButton = document.getElementById('size-button');
    const linkButton = document.getElementById('link-button'); 

    let selectedColor = colorInput ? colorInput.value : '#FF0066'; 

    // 🚨 1. ΕΦΑΡΜΟΓΗ FEATURE TOGGLES & ΑΡΧΙΚΟΠΟΙΗΣΗ EMOTICONS
    // Καλούμε την applyFeatureToggles για να ρυθμίσουμε τα κουμπιά
    if (typeof applyFeatureToggles === 'function') {
        applyFeatureToggles();
    }

    // 2. ΣΥΝΑΡΤΗΣΗ ΑΠΟΣΤΟΛΗΣ ΜΗΝΥΜΑΤΟΣ
    function sendMessage() {
        const msg = messageInput.value.trim();
        if (msg) {
            socket.emit('message', { 
                msg: msg,
                color: selectedColor 
            });
            messageInput.value = ''; 
            messageInput.style.height = 'auto'; // Reset autoresize
        }
    }

    // 3. Formatting Buttons Helper (BBCode Logic)
    function applyFormat(tag, value = null, linkText = 'link text') {
        const start = messageInput.selectionStart;
        const end = messageInput.selectionEnd;
        let selectedText = messageInput.value.substring(start, end);
        
        let tagsOpen = `[${tag}${value !== null ? '=' + value : ''}]`;
        let tagsClose = `[/${tag}]`;

        // Ειδικός χειρισμός για το [url]
        if (tag === 'url' && value !== null) {
            if (selectedText.length === 0) {
                selectedText = linkText; 
            }
            tagsOpen = `[url=${value}]`;
        }
        
        if (selectedText.length > 0) {
            const newText = tagsOpen + selectedText + tagsClose;
            
            messageInput.value = messageInput.value.substring(0, start) + newText + messageInput.value.substring(end);
            
            // Τοποθέτηση cursor μετά το κλείσιμο του tag
            const newCursorPos = start + newText.length;
            messageInput.setSelectionRange(newCursorPos, newCursorPos);
        } else {
            // Χειρισμός για tags χωρίς επιλεγμένο κείμενο
            if (tag === 'url' && value !== null) {
                const tags = tagsOpen + linkText + tagsClose;
                messageInput.value = messageInput.value.substring(0, start) + tags + messageInput.value.substring(end);
                // Τοποθέτηση cursor στην αρχή του default κειμένου
                messageInput.setSelectionRange(start + tagsOpen.length, start + tagsOpen.length + linkText.length);
            } else {
                const tags = tagsOpen + tagsClose;
                messageInput.value = messageInput.value.substring(0, start) + tags + messageInput.value.substring(end);
                // Τοποθέτηση cursor ανάμεσα στα tags
                messageInput.setSelectionRange(start + tagsOpen.length, start + tagsOpen.length);
            }
        }
        messageInput.focus();
    }


    // --- DOM EVENT LISTENERS (Κουμπιά & Input) ---

    // 4. Send Button & Enter Key
    if (sendButton && messageInput) {
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
    }

    // 5. BBCode Button Listeners (Bold, Italic, Underline, Link)
    if (boldButton) boldButton.addEventListener('click', () => applyFormat('b'));
    if (italicButton) italicButton.addEventListener('click', () => applyFormat('i'));
    if (underlineButton) underlineButton.addEventListener('click', () => applyFormat('u'));

    if (linkButton) {
        linkButton.addEventListener('click', () => {
            const urlValue = prompt("Enter the URL:");
            if (urlValue) {
                applyFormat('url', urlValue, 'Link Text'); 
            }
        });
    }

    // 6. Size Button (Εφαρμόζει [size=N])
    if (sizeButton) {
        sizeButton.addEventListener('click', () => {
            const sizeValue = prompt("Enter text size in pixels (8-36):");
            const sizeInt = parseInt(sizeValue);
            if (sizeValue && !isNaN(sizeInt) && sizeInt >= 8 && sizeInt <= 36) {
                applyFormat('size', sizeInt);
            } else if (sizeValue !== null) {
                alert("Invalid size. Please enter a number between 8 and 36.");
            }
        });
    }

    // 7. Color Picker (Εφαρμόζει [color=#HEX])
    if (colorPickerButton && colorInput) {
        colorPickerButton.addEventListener('click', () => {
            colorInput.click();
        });

        colorInput.addEventListener('input', (e) => {
            selectedColor = e.target.value; 
            colorPickerButton.style.color = selectedColor; 
            
            applyFormat('color', selectedColor); 
        });
    }

    // 8. Emoticon Button (Toggle Display & Logic)
    if (emoticonButton && emoticonSelector && messageInput) {
        emoticonButton.addEventListener('click', (e) => {
            e.stopPropagation(); 
            emoticonSelector.style.display = emoticonSelector.style.display === 'block' ? 'none' : 'block';
        });
        
        // Κλείνει το πλαίσιο αν κάνουμε κλικ αλλού
        document.addEventListener('click', (event) => {
            if (emoticonButton && emoticonSelector && !emoticonButton.contains(event.target) && !emoticonSelector.contains(event.target)) {
                emoticonSelector.style.display = 'none';
            }
        });
    }

    // 9. Notification Button (Volume)
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
        // Αρχική ρύθμιση icon
        notificationButton.querySelector('i').classList.add(isNotificationSoundEnabled ? 'fa-bell' : 'fa-bell-slash');
    }
    
    // 10. GIF Button
    if(gifButton && messageInput){
        gifButton.addEventListener('click', () => {
            const imageUrl = prompt("Please paste the full image/GIF URL here:");
            if (imageUrl) {
                const imgTag = `[img]${imageUrl}[/img]`;
                messageInput.value += imgTag;
                messageInput.focus();
            }
        });
    }

    // 11. ΡΑΔΙΟΦΩΝΟ LOGIC
    if (radioToggleButton && audioStream) {
        audioStream.volume = 0.3; 
        
        radioToggleButton.addEventListener('click', () => {
            if (audioStream.paused) {
                audioStream.play().then(() => {
                    radioToggleButton.classList.replace('radio-off', 'radio-on');
                }).catch(e => {
                    console.error("Audio playback blocked by browser:", e);
                    alert("Playback blocked. Please check browser settings.");
                });
            } else {
                audioStream.pause();
                radioToggleButton.classList.replace('radio-on', 'radio-off');
            }
        });
    }
});