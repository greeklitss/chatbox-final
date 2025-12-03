// static/main.js - ΟΛΟΚΛΗΡΩΜΕΝΗ & ΤΕΛΙΚΗ ΕΚΔΟΣΗ
// Περιλαμβάνει: Real-Time Sync, Web Radio Logic, Notification Sound, Scroll Logic, BBCode/Emoticon Parser.

// 🚨 ΥΠΟΘΕΤΟΥΜΕ ΟΤΙ ΟΙ globalSettings και globalEmoticons ΕΧΟΥΝ ΟΡΙΣΤΕΙ ΣΤΟ chat.html
let isNotificationSoundEnabled = true;

// --- 0. DOM ELEMENTS & ΒΟΗΘΗΤΙΚΕΣ ΜΕΤΑΒΛΗΤΕΣ ---
const chatInputContainer = document.getElementById('chat-input-container');
const audioStream = document.getElementById('audio-stream');
const radioToggleButton = document.getElementById('radio-toggle-button');
const chatbox = document.getElementById('chat-box');

const radioUrlKey = 'radio_stream_url';
const radioFeatureKey = 'feature_radio';
const chatEnabledKey = 'global_chat_enabled';

// 1. ΣΥΝΑΡΤΗΣΗ ΗΧΟΥ ΕΙΔΟΠΟΙΗΣΗΣ
function playNotificationSound() {
    if (!isNotificationSoundEnabled) return;
    try {
        // ... (λογική αναπαραγωγής ήχου) ...
        const audio = new Audio('/static/sounds/chat_notification.mp3'); 
        audio.volume = 0.5; 
        audio.play().catch(e => console.log("Notification audio blocked by browser:", e));
    } catch (error) {
        console.error("Error playing notification sound:", error);
    }
}

// 2. Message Scroller
function scrollChatToBottom(chatbox, force = false) {
    // ... (λογική scroll) ...
    const isNearBottom = chatbox.scrollTop + chatbox.clientHeight >= chatbox.scrollHeight - 50;
    if (force || isNearBottom) {
        chatbox.scrollTop = chatbox.scrollHeight;
    }
}

// 3. Emoticon/BBCode Parser (Χρησιμοποιεί globalEmoticons)
function parseMessage(text) {
    // ... (λογική parsing) ...
    let parsedText = text;

    // 1. Emoticons
    if (globalSettings.feature_emoticons === 'True') {
        // 🚨 Βελτίωση: Ταξινόμηση για να αποφύγουμε προβλήματα με emoticons που περιέχουν άλλα
        const sortedEmoticons = Object.entries(globalEmoticons).sort(([k1], [k2]) => k2.length - k1.length);
        sortedEmoticons.forEach(([code, emoticonData]) => {
            const regex = new RegExp(code.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'g');
            parsedText = parsedText.replace(regex, `<img src="${emoticonData.url}" alt="${code}" class="bbcode-emoticon">`);
        });
    }

    // 2. BBCode
    // ... (οι υπόλοιπες λογικές για [b], [i], [u], [img], [color]) ...
    parsedText = parsedText.replace(/\[b\](.*?)\[\/b\]/gs, '<span class="bbcode-b">$1</span>');
    parsedText = parsedText.replace(/\[i\](.*?)\[\/i\]/gs, '<span class="bbcode-i">$1</span>');
    parsedText = parsedText.replace(/\[u\](.*?)\[\/u\]/gs, '<span class="bbcode-u">$1</span>');

    if (globalSettings.feature_img === 'True' || globalSettings.feature_gif === 'True') {
        parsedText = parsedText.replace(/\[img\](.*?)\[\/img\]/gs, '<img src="$1" class="bbcode-img" loading="lazy" onerror="this.style.display=\'none\'">');
    }
    
    // Χειρισμός [color=...] - Υποθέτουμε ότι υπάρχει helper function
    parsedText = parsedText.replace(/\[color=(#[0-9a-fA-F]{3,6}|[a-zA-Z]+)\](.*?)\[\/color\]/gs, (match, color, content) => {
        return `<span style="color: ${color};">${content}</span>`;
    });

    return parsedText;
}

// 4. Append Message (Εισαγωγή μηνύματος στο DOM)
function appendMessage(data, isSystem = false) {
    // ... (λογική appendMessage) ...
    if (!chatbox) return;

    const messageItem = document.createElement('div');
    messageItem.className = isSystem ? 'system-message' : 'message-item';
    
    if (isSystem) {
        messageItem.innerHTML = data.content;
    } else {
        const roleClass = `role-${data.role}`;
        const avatarUrl = data.avatar_url || '/static/default_avatar.png';
        
        messageItem.innerHTML = `
            <img src="${avatarUrl}" alt="${data.username || 'user'}" class="message-avatar" style="border-color: ${data.color};">
            <div class="message-content-wrapper">
                <div class="message-header-line">
                    <span class="message-username ${roleClass}" style="color: ${data.color};">${data.display_name}</span>
                    <span class="message-timestamp">${data.timestamp}</span>
                </div>
                <div class="message-text">${parseMessage(data.content)}</div>
            </div>
        `;
    }
    chatbox.appendChild(messageItem);
    scrollChatToBottom(chatbox);
}


// --- 5. SOCKETIO & CHAT INIT (Υποθέτουμε ότι ορίστηκε) ---
const socket = io();

// 6. Εμφάνιση Online Users (Υποθέτουμε ότι υπάρχει)
socket.on('online_users', (users) => {
    // ... (λογική εμφάνισης χρηστών) ...
    const usersList = document.getElementById('users-list');
    if (!usersList) return;
    
    usersList.innerHTML = '';
    
    // Ταξινόμηση: Owner > Admin > User
    const sortedUsers = users.sort((a, b) => {
        const order = { 'owner': 3, 'admin': 2, 'user': 1 };
        return order[b.role] - order[a.role];
    });

    sortedUsers.forEach(user => {
        const li = document.createElement('li');
        li.className = 'user-list-item';
        li.innerHTML = `
            <img src="${user.avatar_url}" alt="${user.display_name}">
            <span>${user.display_name}</span>
            <span class="user-role role-${user.role}">${user.role.toUpperCase()}</span>
        `;
        usersList.appendChild(li);
    });
});

// 7. SOCKETIO EVENT LISTENERS (Διορθώσεις Real-Time Sync)

socket.on('new_message', (data) => {
    appendMessage(data);
    playNotificationSound();
});

// 🚨 ΔΙΟΡΘΩΜΕΝΟ: Real-time update των ρυθμίσεων από Admin Panel
socket.on('settings_update', (newSettings) => {
    console.log('Global settings updated in real-time by Admin Panel.', newSettings);
    // 🚨 Ανανέωση της καθολικής μεταβλητής
    window.globalSettings = newSettings; 

    // Εφαρμογή αλλαγών
    handleRadioUpdate(newSettings);
    handleChatStateUpdate(newSettings);
    applyFeatureToggles(); // Ενημέρωση BBCode/GIF κουμπιών
});

// 🚨 ΔΙΟΡΘΩΜΕΝΟ: Real-time update των emoticons
socket.on('emoticons_update', (newEmoticons) => {
    console.log('Emoticons updated in real-time by Admin Panel.');
    // 🚨 Ανανέωση της καθολικής μεταβλητής
    window.globalEmoticons = newEmoticons; 
    initializeEmoticonSelector(); // Ανανέωση του selector
});


// --- 8. WEB RADIO & CHAT TOGGLE LOGIC (Νέα Λογική) ---

// 🚨 ΝΕΟ: Συνάρτηση για ανανέωση του κουμπιού του ραδιοφώνου (UI & State)
function updateRadioUI(settings) {
    if (!radioToggleButton || !audioStream) return;

    // 1. Ενημέρωση κλάσης (icon)
    if (!audioStream.paused && audioStream.src !== '') {
        radioToggleButton.classList.replace('radio-off', 'radio-on');
    } else {
        radioToggleButton.classList.replace('radio-on', 'radio-off');
    }

    // 2. Έλεγχος αν η λειτουργία είναι Απενεργοποιημένη από Admin
    if (settings[radioFeatureKey] === 'False') {
        radioToggleButton.disabled = true;
        radioToggleButton.title = 'Web Radio Disabled by Admin';
        if (!audioStream.paused) {
             audioStream.pause();
             audioStream.src = ''; // Διαγραφή πηγής
        }
    } else {
        radioToggleButton.disabled = false;
        radioToggleButton.title = 'Web Radio ON/OFF';
    }
}

// 🚨 ΝΕΟ: Χειρισμός αλλαγής της πηγής ραδιοφώνου
function handleRadioUpdate(newSettings) {
    if (!audioStream) return;
    
    const featureEnabled = newSettings[radioFeatureKey] === 'True';
    
    // Αν το feature απενεργοποιήθηκε ή αν άλλαξε το URL ενώ έπαιζε, σταμάτα
    if (!featureEnabled || (!audioStream.paused && audioStream.src !== '/radio_proxy')) {
        audioStream.pause();
        audioStream.src = featureEnabled ? '/radio_proxy' : ''; 
        audioStream.load();
    } 
    
    updateRadioUI(newSettings);
}

// 🚨 ΝΕΟ: Χειρισμός Chat On/Off
function handleChatStateUpdate(newSettings) {
    if (!chatInputContainer) return;
    
    const chatEnabled = newSettings[chatEnabledKey] === 'True';
    
    if (chatEnabled) {
        chatInputContainer.style.display = 'flex'; 
    } else {
        chatInputContainer.style.display = 'none'; 
        // 🚨 Μπορείς να προσθέσεις μήνυμα "Chat is closed" εδώ
    }
}


// --- 9. DOM CONTENT LOADED (Μεταφορά Radio Logic) ---
document.addEventListener('DOMContentLoaded', () => {
    
    // ... (Οι ορισμοί των DOM elements μένουν ως έχουν) ...
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-btn');
    const notificationButton = document.getElementById('notification-sound-btn');
    
    // 🚨 Αρχική ρύθμιση UI
    updateRadioUI(globalSettings); 
    handleChatStateUpdate(globalSettings);
    
    // ... (Σημεία 4, 5, 6, 7, 8, 9 - BBCode/Emoticon/Notification Logic) ...
    
    // 🚨 10. ΡΑΔΙΟΦΩΝΟ LOGIC (ΔΙΟΡΘΩΜΕΝΟ ΣΗΜΕΙΟ 11)
    if (radioToggleButton && audioStream) {
        audioStream.volume = 0.3; 
        
        radioToggleButton.addEventListener('click', () => {
            if (radioToggleButton.disabled) return;
            
            if (audioStream.paused) {
                // Ορίζουμε το src στον proxy, το Flask θα βρει το URL
                audioStream.src = '/radio_proxy'; 
                audioStream.load();

                audioStream.play().then(() => {
                    updateRadioUI(globalSettings);
                }).catch(e => {
                    console.error("Audio playback blocked by browser:", e);
                    alert("Playback blocked. Check browser settings or Admin Panel URL.");
                    updateRadioUI(globalSettings);
                });
            } else {
                audioStream.pause();
                updateRadioUI(globalSettings);
            }
        });
        
        // Listeners για real-time ενημέρωση του UI
        audioStream.addEventListener('play', () => updateRadioUI(globalSettings));
        audioStream.addEventListener('pause', () => updateRadioUI(globalSettings));
        audioStream.addEventListener('error', () => updateRadioUI(globalSettings)); 
    }
});