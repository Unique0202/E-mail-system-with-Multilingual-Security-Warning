let currentUser = null;

// --- Multilingual Dictionary (Ported) ---
const translations = {
    'phishing_warning': {
            'en': 'Warning: This email may be a phishing attempt',
            'hi': 'चेतावनी: यह ईमेल फ़िशिंग का प्रयास हो सकता है',
            'bn': 'সতর্কতা: এই ইমেলটি ফিশিং প্রচেষ্টা হতে পারে',
            'te': 'హెచ్చరిక: ఈ ఇమెయిల్ ఫిషింగ్ ప్రయత్నం కావచ్చు',
            'mr': 'चेतावणी: हा ईमेल फिशिंग प्रयत्न असू शकतो',
            'ta': 'எச்சரிக்கை: இந்த மின்னஞ்சல் ஃபிஷிங் முயற்சியாக இருக்கலாம்',
            'gu': 'ચેતવણી: આ ઈમેલ ફિશિંગ પ્રયાસ હોઈ શકે છે',
            'kn': 'ಎಚ್ಚರಿಕೆ: ಈ ಇಮೇಲ್ ಫಿಶಿಂಗ್ ಪ್ರಯತ್ನವಾಗಿರಬಹುದು',
            'ml': 'മുന്നറിയിപ്പ്: ഈ ഇമെയിൽ ഫിഷിംഗ് ശ്രമമാകാം',
            'pa': 'ਚੇਤਾਵਨੀ: ਇਹ ਈਮੇਲ ਫਿਸ਼ਿੰਗ ਦੀ ਕੋਸ਼ਿਸ਼ ਹੋ ਸਕਦੀ ਹੈ',
            'or': 'ସତର୍କତା: ଏହି ଇମେଲ୍ ଫିସିଂ ପ୍ରୟାସ ହୋଇପାରେ',
            'as': 'সতৰ্কবাণী: এই ইমেইলটো ফিছিং প্ৰয়াস হ\'ব পাৰে',
            'ur': 'انتباہ: یہ ای میل فشنگ کی کوشش ہو سکتی ہے',
    },
    'safe_sender': {
            'en': 'Verified Safe Sender',
            'hi': 'सत्यापित सुरक्षित प्रेषक',
            'bn': 'যাচাইকৃত নিরাপদ প্রেরক',
            'te': 'ధృవీకరించబడిన సురక్షిత పంపినవారు',
            'mr': 'सत्यापित सुरक्षित प्रेषक',
            'ta': 'சரிபார்க்கப்பட்ட பாதுகாப்பான அனுப்புநர்',
            'gu': 'ચકાસાયેલ સલામત પ્રેષક',
            'kn': 'ಪರಿಶೀಲಿಸಿದ ಸುರಕ್ಷಿತ ಕಳುಹಿಸುವವರು',
            'ml': 'പരിശോധിച്ച സുരക്ഷിത അയച്ചയാൾ',
            'pa': 'ਪ੍ਰਮਾਣਿਤ ਸੁਰੱਖਿਅਤ ਭੇਜਣ ਵਾਲਾ',
            'or': 'ଯାଚାଇ ହୋଇଥିବା ସୁରକ୍ଷିତ ପ୍ରେରକ',
            'as': 'সত্যাপিত সুৰক্ষিত প্ৰেৰক',
            'ur': 'تصدیق شدہ محفوظ بھیجنے والا',
    }
};

function getTranslation(key, userLangs) {
    const lang = userLangs[0] || 'en';
    return translations[key]?.[lang] || translations[key]?.['en'] || key;
}

document.addEventListener('DOMContentLoaded', () => {
    // Attach click events via JS instead of HTML
    const btnLogin = document.getElementById('btn-login');
    const btnRegister = document.getElementById('btn-register');

    if (btnLogin && btnRegister) {
        btnLogin.addEventListener('click', () => showAuthTab('login'));
        btnRegister.addEventListener('click', () => showAuthTab('register'));
    }
});

function showAuthTab(tab) {
    // Toggle Form Visibility
    document.getElementById('login-tab').classList.toggle('hidden', tab !== 'login');
    document.getElementById('register-tab').classList.toggle('hidden', tab !== 'register');

    // Toggle Button Active State
    document.getElementById('btn-login').classList.toggle('active', tab === 'login');
    document.getElementById('btn-register').classList.toggle('active', tab === 'register');
    
    // Clear errors when switching
    document.getElementById('login-error').innerText = "";
    document.getElementById('reg-error').innerText = "";
}

async function handleRegister() {
    const email = document.getElementById('reg-email').value;
    const pass = document.getElementById('reg-pass').value;
    const l1 = document.getElementById('reg-lang1').value;
    const l2 = document.getElementById('reg-lang2').value;

    const res = await window.api.register({ email, password: pass, lang1: l1, lang2: l2 });
    
    if (res.success) {
        document.getElementById('qr-image').src = res.qrCode;
        document.getElementById('qr-container').classList.remove('hidden');
        document.getElementById('reg-error').innerText = "";
    } else {
        document.getElementById('reg-error').innerText = res.error;
    }
}

async function handleLogin() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-pass').value;
    const totp = document.getElementById('login-totp').value;

    const res = await window.api.login({ email, password, totp });

    if (res.success) {
        currentUser = res.user;
        document.getElementById('auth-screen').classList.add('hidden');
        document.getElementById('app-screen').classList.remove('hidden');
        document.getElementById('user-display').innerText = currentUser.email;
        loadInbox();
    } else {
        document.getElementById('login-error').innerText = res.error;
    }
}

function logout() {
    location.reload();
}

// --- Email Functions ---
function showView(viewId) {
    ['email-list-view', 'compose-view', 'read-view'].forEach(id => {
        document.getElementById(id).classList.add('hidden');
    });
    document.getElementById(viewId).classList.remove('hidden');
}

async function loadInbox() {
    showView('email-list-view');
    document.getElementById('folder-title').innerText = "Inbox";
    const emails = await window.api.getInbox(currentUser.id);
    renderList(emails, true);
}

async function loadSent() {
    showView('email-list-view');
    document.getElementById('folder-title').innerText = "Sent";
    const emails = await window.api.getSent(currentUser.id);
    renderList(emails, false);
}

function renderList(emails, isInbox) {
    const list = document.getElementById('email-list');
    list.innerHTML = '';

    emails.forEach(email => {
        const el = document.createElement('div');
        // Determine Badge color from DB or Default
        const badgeColor = email.badge_color || 'green';
        el.className = `email-list-item badge-${badgeColor}`;
        
        let securityTag = '';
        if (isInbox) {
            const score = email.safe_score || 50;
            let tagClass = 'tag-safe';
            let tagText = 'SAFE';
            
            if(badgeColor === 'red') { tagClass = 'tag-danger'; tagText = 'DANGER'; }
            else if(badgeColor === 'yellow') { tagClass = 'tag-caution'; tagText = 'CAUTION'; }
            
            securityTag = `<span class="security-tag ${tagClass}">${tagText}</span>`;
        }

        el.innerHTML = `
            <div style="display:flex; justify-content:space-between;">
                <strong>${isInbox ? email.sender_email : email.recipient_email}</strong>
                <small>${new Date(email.sent_at).toLocaleDateString()}</small>
            </div>
            <div>${email.subject} ${securityTag}</div>
        `;
        el.onclick = () => openEmail(email);
        list.appendChild(el);
    });
}

function showCompose() {
    showView('compose-view');
    document.getElementById('comp-to').value = '';
    document.getElementById('comp-subject').value = '';
    document.getElementById('comp-body').value = '';
    document.getElementById('comp-status').innerText = '';
}

async function sendEmail() {
    const data = {
        from: currentUser.email,
        to: document.getElementById('comp-to').value,
        subject: document.getElementById('comp-subject').value,
        body: document.getElementById('comp-body').value
    };

    const res = await window.api.sendEmail(data);
    if (res.success) {
        alert("Email Sent Successfully!");
        loadSent();
    } else {
        document.getElementById('comp-status').innerText = "Error: " + res.error;
        document.getElementById('comp-status').style.color = "red";
    }
}

function openEmail(email) {
    showView('read-view');
    document.getElementById('read-subject').innerText = email.subject;
    document.getElementById('read-from').innerText = email.sender_email;
    document.getElementById('read-date').innerText = new Date(email.sent_at).toLocaleString();
    document.getElementById('read-body').innerText = email.body; // Safe text only

    // Security Analysis Visualization
    const badge = document.getElementById('security-badge');
    const warnings = document.getElementById('read-warnings');
    warnings.classList.add('hidden');

    if (email.badge_color === 'red') {
        badge.className = "badge tag-danger";
        badge.innerText = getTranslation('phishing_warning', currentUser.languages);
        warnings.innerHTML = `<strong>${getTranslation('phishing_warning', currentUser.languages)}</strong>`;
        warnings.classList.remove('hidden');
    } else {
        badge.className = "badge tag-safe";
        badge.innerText = getTranslation('safe_sender', currentUser.languages);
    }
}

function backToList() {
    showView('email-list-view');
}