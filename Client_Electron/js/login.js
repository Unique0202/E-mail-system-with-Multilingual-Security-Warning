document.addEventListener('DOMContentLoaded', () => {
    // Tabs
    document.getElementById('btn-login').addEventListener('click', () => toggleTab('login'));
    document.getElementById('btn-register').addEventListener('click', () => toggleTab('register'));

    // Submit Handlers
    document.getElementById('submit-login').addEventListener('click', handleLogin);
    document.getElementById('submit-register').addEventListener('click', handleRegister);

    // Real-time validation for registration form
    setupRealTimeValidation();
});

function toggleTab(tab) {
    document.getElementById('login-tab').classList.toggle('hidden', tab !== 'login');
    document.getElementById('register-tab').classList.toggle('hidden', tab !== 'register');
    document.getElementById('btn-login').classList.toggle('active', tab === 'login');
    document.getElementById('btn-register').classList.toggle('active', tab === 'register');
    
    // Clear errors when switching tabs
    document.getElementById('login-error').innerText = "";
    document.getElementById('reg-error').innerText = "";
}

function setupRealTimeValidation() {
    const passwordInput = document.getElementById('reg-pass');
    const lang1Select = document.getElementById('reg-lang1');
    const lang2Select = document.getElementById('reg-lang2');
    const langHint = document.getElementById('lang-hint');

    // Real-time password validation
    passwordInput.addEventListener('input', function() {
        validatePasswordRealTime(this.value);
    });

    // Real-time language validation
    [lang1Select, lang2Select].forEach(select => {
        select.addEventListener('change', function() {
            validateLanguagesRealTime(lang1Select.value, lang2Select.value);
        });
    });
}

function validatePasswordRealTime(password) {
    const requirements = {
        length: document.getElementById('req-length'),
        upper: document.getElementById('req-upper'),
        lower: document.getElementById('req-lower'),
        digit: document.getElementById('req-digit'),
        special: document.getElementById('req-special')
    };

    // Check each requirement
    const hasLength = password.length >= 12;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    // Update requirement indicators
    requirements.length.className = hasLength ? 'requirement-met' : 'requirement-unmet';
    requirements.upper.className = hasUpper ? 'requirement-met' : 'requirement-unmet';
    requirements.lower.className = hasLower ? 'requirement-met' : 'requirement-unmet';
    requirements.digit.className = hasDigit ? 'requirement-met' : 'requirement-unmet';
    requirements.special.className = hasSpecial ? 'requirement-met' : 'requirement-unmet';

    return hasLength && hasUpper && hasLower && hasDigit && hasSpecial;
}

function validateLanguagesRealTime(lang1, lang2) {
    const langHint = document.getElementById('lang-hint');
    
    if (!lang1 || !lang2) {
        langHint.textContent = "Please select both languages";
        langHint.className = "input-hint warning";
        return false;
    }
    
    if (lang1 === lang2) {
        langHint.textContent = "Primary and secondary languages must be different";
        langHint.className = "input-hint error";
        return false;
    }
    
    langHint.textContent = "Languages selected correctly";
    langHint.className = "input-hint success";
    return true;
}

async function handleLogin() {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-pass').value;
    const totp = document.getElementById('login-totp').value.trim();

    // Basic frontend validation
    if (!email || !password || !totp) {
        document.getElementById('login-error').innerText = "Please fill in all fields";
        return;
    }

    if (!email.includes('@')) {
        document.getElementById('login-error').innerText = "Email must contain @ symbol";
        return;
    }

    if (totp.length !== 6 || !/^\d+$/.test(totp)) {
        document.getElementById('login-error').innerText = "2FA code must be 6 digits";
        return;
    }

    const res = await window.api.login({ email, password, totp });

    if (res.success) {
        // --- THE FIX: Save the user to LocalStorage ---
        window.localStorage.setItem('currentUser', JSON.stringify(res.user));
        
        window.api.changePage('dashboard');
    } else {
        document.getElementById('login-error').innerText = res.error;
    }
}

async function handleRegister() {
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-pass').value;
    const lang1 = document.getElementById('reg-lang1').value;
    const lang2 = document.getElementById('reg-lang2').value;

    const errorText = document.getElementById('reg-error');

    // Frontend validation
    if (!email || !password || !lang1 || !lang2) {
        errorText.innerText = "Please fill in all fields";
        errorText.style.color = "#ff9800";
        return;
    }

    if (!email.includes('@')) {
        errorText.innerText = "Email must contain @ symbol";
        errorText.style.color = "#f44336";
        return;
    }

    // Check password requirements
    if (!validatePasswordRealTime(password)) {
        errorText.innerText = "Password does not meet all requirements";
        errorText.style.color = "#f44336";
        return;
    }

    // Check language selection
    if (!validateLanguagesRealTime(lang1, lang2)) {
        errorText.innerText = "Please select two different languages";
        errorText.style.color = "#f44336";
        return;
    }

    // Show loading state
    const registerBtn = document.getElementById('submit-register');
    registerBtn.textContent = "Creating Secure Account...";
    registerBtn.disabled = true;

    try {
        const res = await window.api.register({ email, password, lang1, lang2 });

        if (res.success) {
            document.getElementById('qr-image').src = res.qrCode;
            document.getElementById('qr-container').classList.remove('hidden');
            errorText.innerText = "";
            
            // Disable form after successful registration
            document.getElementById('reg-email').disabled = true;
            document.getElementById('reg-pass').disabled = true;
            document.getElementById('reg-lang1').disabled = true;
            document.getElementById('reg-lang2').disabled = true;
            
            registerBtn.textContent = "Account Created Successfully!";
        } else {
            errorText.innerText = res.error;
            errorText.style.color = "#f44336";
            registerBtn.textContent = "Generate Security Keys & Register";
            registerBtn.disabled = false;
        }
    } catch (error) {
        errorText.innerText = "An unexpected error occurred: " + error.message;
        errorText.style.color = "#f44336";
        registerBtn.textContent = "Generate Security Keys & Register";
        registerBtn.disabled = false;
    }
}