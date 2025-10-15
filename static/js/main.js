// static/js/main.js

document.addEventListener('DOMContentLoaded', () => {
    
    // --- 1. Μεταβλητές & Αρχικοποίηση ---
    const socket = io();
    const messageContainer = document.getElementById('message-container'); 
    const messageInput = document.getElementById('message-input');
    const sendButton = document.getElementById('send-button');
    const colorInput = document.getElementById('color-input');
    const toggleSound = document.getElementById('toggle-sound');
    const onlineList = document.getElementById('online-list');
    const onlineCount = document.getElementById('online-count');
    const myDisplayNameElement = document.getElementById('my-display-name');
    const myAvatarElement = document.getElementById('my-avatar');
    
    // 🚨 ΝΕΕΣ ΜΕΤΑΒΛΗΤΕΣ ΓΙΑ ΤΟ RADIO
    const audioStream = document.getElementById('audio-stream');
    const toggleAudioButton = document.getElementById('toggle-audio-stream'); 
    let isPlaying = false; 

    // ΗΧΟΣ ΜΗΝΥΜΑΤΟΣ 
    const notificationSound = new Audio('/static/sounds/notification.mp3'); // ΥΠΟΘΕΣΗ: Έχετε το αρχείο
    notificationSound.volume = 0.5;
    let soundOn = true;

    // Λίστα online χρηστών (Global State στο Frontend)
    const onlineUsers = new Map();

    // Μεταφέρει τον scrollbar στο τέλος του chatbox κατά τη φόρτωση
    if(messageContainer) {
        messageContainer.scrollTop = messageContainer.scrollHeight;
    }

    // --- 2. Βοηθητικές Συναρτήσεις ---

    function scrollToBottom() {
         if(messageContainer) {
            messageContainer.scrollTop = messageContainer.scrollHeight;
        }
    }
    
    // Συνάρτηση για Parsing BBCode σε HTML
    function parseBBCode(text) {
        // Αρχικά αντικαθιστούμε τα emoticons (χρειάζεται fetch από το server)
        // Εδώ η λογική είναι απλή, τα emoticons θα πρέπει να έχουν αντικατασταθεί 
        // είτε στον server είτε μέσω μιας λίστας που έχουμε λάβει.
        
        // ⚠️ Επειδή δεν έχουμε κάνει fetch τη λίστα emoticons εδώ, θα αφήσουμε
        // την απλοϊκή αντικατάσταση. Θα πρέπει να βάλετε μια κλήση fetch('/settings/emoticons') 
        // για να πάρετε τη λίστα και να κάνετε σωστή αντικατάσταση.
        
        // [b]bold[/b], [i]italic[/i], [u]underline[/u]
        text = text.replace(/\[b\](.*?)\[\/b\]/gs, '<b>$1</b>');
        text = text.replace(/\[i\](.*?)\[\/i\]/gs, '<i>$1</i>');
        text = text.replace(/\[u\](.*?)\[\/u\]/gs, '<u>$1</u>');
        
        // [color=#HEX]text[/color]
        text = text.replace(/\[color=([^\]]+)\](.*?)\[\/color\]/gs, '<font style="color: $1;">$2</font>');

        // [url=http://...]link[/url]
        text = text.replace(/\[url=([^\]]+)\](.*?)\[\/url\]/gs, '<a href="$1" target="_blank">$2</a>');
        
        // [gif]url[/gif]
        text = text.replace(/\[gif\](.*?)\[\/gif\]/gs, '<img src="$1" class="message-image" alt="User GIF">');

        // Προστατεύουμε τις νέες γραμμές
        text = text.replace(/\n/g, '<br>');
        
        return text;
    }
    
    function appendMessage(data, isSelf = false) {
        const messageBox = document.createElement('div');
        messageBox.className = `message-box ${isSelf ? 'message-self' : 'message-other'}`;
        
        // Βρίσκουμε τον Avatar URL
        const user = onlineUsers.get(data.id) || { avatar_url: myAvatarElement.src, display_name: data.username, role: data.role };
        
        const avatarUrl = user.avatar_url;
        
        const avatar = document.createElement('img');
        avatar.className = 'avatar';
        avatar.src = avatarUrl;
        avatar.alt = 'Avatar';
        
        const content = document.createElement('div');
        content.className = 'message-content';
        
        const info = document.createElement('div');
        info.className = 'message-info';
        
        const usernameSpan = document.createElement('span');
        usernameSpan.className = `username user-role-${data.role}`;
        usernameSpan.textContent = data.username;
        
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'timestamp';
        timestampSpan.textContent = data.timestamp;
        
        info.appendChild(usernameSpan);
        info.appendChild(timestampSpan);
        
        const text = document.createElement('div');
        text.className = 'message-text';
        text.innerHTML = parseBBCode(data.message);
        
        content.appendChild(info);
        content.appendChild(text);
        
        messageBox.appendChild(avatar);
        messageBox.appendChild(content);
        
        messageContainer.appendChild(messageBox);
        scrollToBottom();
        
        // Παίξιμο ήχου μόνο για μηνύματα άλλων
        if (!isSelf && soundOn) {
            notificationSound.play().catch(e => console.log('Sound playback prevented:', e));
        }
    }
    
    function updateOnlineList() {
        onlineList.innerHTML = '';
        const usersArray = Array.from(onlineUsers.values());
        
        // Ταξινόμηση: Owner, Admin, User, Guest
        usersArray.sort((a, b) => {
            const roleOrder = { 'owner': 4, 'admin': 3, 'user': 2, 'guest': 1 };
            return roleOrder[b.role] - roleOrder[a.role];
        });
        
        usersArray.forEach(user => {
            const li = document.createElement('li');
            li.className = 'online';
            li.id = `user-${user.id}`;
            
            const avatar = document.createElement('img');
            avatar.className = 'user-avatar';
            avatar.src = user.avatar_url;
            avatar.alt = 'Avatar';
            
            const nameSpan = document.createElement('span');
            nameSpan.textContent = user.display_name;
            nameSpan.className = `user-role-${user.role}`;
            
            li.appendChild(avatar);
            li.appendChild(nameSpan);
            onlineList.appendChild(li);
        });
        
        onlineCount.textContent = usersArray.length;
    }
    
    function applyFormatting(tag, placeholder) {
        const input = messageInput;
        const start = input.selectionStart;
        const end = input.selectionEnd;
        const selectedText = input.value.substring(start, end);
        
        let openTag = `[${tag}]`;
        let closeTag = `[/${tag.split('=')[0]}]`;
        let newText = selectedText || placeholder;
        
        const fullTag = openTag + newText + closeTag;
        
        // Αντικατάσταση του επιλεγμένου κειμένου με τη μορφοποιημένη έκδοση
        input.value = input.value.substring(0, start) + fullTag + input.value.substring(end);
        
        // Τοποθέτηση cursor
        let cursorPosition = start + openTag.length;
        if (!selectedText) {
             cursorPosition = start + openTag.length + placeholder.length;
        }
        
        input.selectionStart = cursorPosition; 
        input.selectionEnd = cursorPosition;
        
        input.focus();
    }


    // --- 3. Event Listeners ---
    
    // Formatting buttons
    document.getElementById('bold-button').onclick = () => applyFormatting('b', 'bold text');
    document.getElementById('italic-button').onclick = () => applyFormatting('i', 'italic text');
    document.getElementById('underline-button').onclick = () => applyFormatting('u', 'underlined text');
    document.getElementById('url-button').onclick = () => applyFormatting('url=http://example.com', 'link text');
    document.getElementById('gif-button').onclick = () => applyFormatting('gif', 'https://example.com/image.gif');
    
    document.getElementById('color-picker-button').onclick = () => {
        colorInput.click();
    };

    colorInput.onchange = () => {
        applyFormatting(`color=${colorInput.value.toUpperCase()}`, 'colored text');
    };
    
    // 🚨 ΝΕΟ: Emoticons Button - Προσθήκη placeholder για εύκολη χρήση
    document.getElementById('emoticon-button').onclick = async () => {
        applyFormatting(':smile:', ':smile:'); // Απλό placeholder
        
        // ⚠️ ΠΡΑΓΜΑΤΙΚΗ ΛΥΣΗ: Εδώ θα πρέπει να ανοίξει ένα modal με τα emoticons
        // και να τρέξει μια fetch('/settings/emoticons') για να τα εμφανίσει.
    };

    // ΛΕΙΤΟΥΡΓΙΑ ΑΠΟΣΤΟΛΗΣ (Send Button)
    sendButton.addEventListener('click', () => {
        const msg = messageInput.value.trim();
        if (msg) {
            socket.emit('send_message', { message: msg });
            messageInput.value = '';
            messageInput.style.height = 'auto'; // Reset height after sending
        }
    });