document.addEventListener('DOMContentLoaded', function() {
    const loginBtn = document.getElementById('loginBtn');
    const createAccountLink = document.getElementById('createAccount');
    
    if (loginBtn) {
        loginBtn.addEventListener('click', handleLogin);
    }
    
    if (createAccountLink) {
        createAccountLink.addEventListener('click', showCreateAccount);
    }
});

async function handleLogin() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const language = document.getElementById('language').value;
    
    if (!email || !password) {
        showNotification('Please fill in all fields', 'error');
        return;
    }
    
    try {
        const result = await window.electronAPI.login({
            email,
            password,
            language
        });
        
        if (result.success) {
            // Redirect to dashboard
            window.location.href = 'dashboard.html';
        } else {
            showNotification('Login failed. Please check your credentials.', 'error');
        }
    } catch (error) {
        showNotification('Login error: ' + error.message, 'error');
    }
}

function showCreateAccount() {
    // Simulate create account flow
    const email = prompt('Enter your email address:');
    if (email) {
        showNotification('Account creation instructions sent to ' + email, 'success');
    }
}

function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        z-index: 1000;
        transition: all 0.3s;
    `;
    
    if (type === 'error') {
        notification.style.background = '#dc3545';
    } else if (type === 'success') {
        notification.style.background = '#28a745';
    } else {
        notification.style.background = '#17a2b8';
    }
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}