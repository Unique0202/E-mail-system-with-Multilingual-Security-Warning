document.addEventListener('DOMContentLoaded', () => {
    // Tabs
    document.getElementById('btn-login').addEventListener('click', () => toggleTab('login'));
    document.getElementById('btn-register').addEventListener('click', () => toggleTab('register'));

    // Submit Handlers
    document.getElementById('submit-login').addEventListener('click', handleLogin);
    document.getElementById('submit-register').addEventListener('click', handleRegister);
});

function toggleTab(tab) {
    document.getElementById('login-tab').classList.toggle('hidden', tab !== 'login');
    document.getElementById('register-tab').classList.toggle('hidden', tab !== 'register');
    document.getElementById('btn-login').classList.toggle('active', tab === 'login');
    document.getElementById('btn-register').classList.toggle('active', tab === 'register');
}

async function handleLogin() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-pass').value;
    const totp = document.getElementById('login-totp').value;

    const res = await window.api.login({ email, password, totp });

    if (res.success) {
        // Tell Main Process to switch files
        window.api.changePage('dashboard');
    } else {
        document.getElementById('login-error').innerText = res.error;
    }
}

async function handleRegister() {
    // Get values and trim whitespace from email
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-pass').value;
    const lang1 = document.getElementById('reg-lang1').value;
    const lang2 = document.getElementById('reg-lang2').value;
    
    const errorText = document.getElementById('reg-error');

    // --- 1. Frontend Validation: Check for empty fields ---
    if (!email || !password) {
        errorText.innerText = "Warning: Please fill in all fields first.";
        errorText.style.color = "#ff9800"; // Orange for warning
        return; // Stop execution here
    }

    // Optional: Check password length locally to save a trip to the backend
    if (password.length < 12) {
        errorText.innerText = "Warning: Password must be at least 12 characters.";
        errorText.style.color = "#ff9800";
        return;
    }

    // --- 2. Send to Backend ---
    const res = await window.api.register({ email, password, lang1, lang2 });

    if (res.success) {
        document.getElementById('qr-image').src = res.qrCode;
        document.getElementById('qr-container').classList.remove('hidden');
        errorText.innerText = ""; // Clear errors
        
        // Optional: Hide the form inputs so they don't register again
        document.getElementById('reg-email').disabled = true;
        document.getElementById('reg-pass').disabled = true;
    } else {
        // Show the error returned from main.js
        errorText.innerText = res.error;
        errorText.style.color = "#f44336"; // Red for error
    }
}