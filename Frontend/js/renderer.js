document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard
    initializeDashboard();
    
    // Set up event listeners
    setupEventListeners();
});

function initializeDashboard() {
    // Load inbox by default
    emailManager.loadEmails('inbox');
}

function setupEventListeners() {
    // Navigation
    const navLinks = document.querySelectorAll('.sidebar-nav a[data-folder]');
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const folder = e.target.getAttribute('data-folder');
            
            // Update active state
            navLinks.forEach(l => l.classList.remove('active'));
            e.target.classList.add('active');
            
            // Load emails for selected folder
            emailManager.loadEmails(folder);
        });
    });

    // Language selection
    const langButtons = document.querySelectorAll('.lang-btn');
    langButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            langButtons.forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            
            const lang = e.target.textContent.toLowerCase();
            emailManager.setLanguage(lang);
        });
    });

    // Bulk actions
    document.getElementById('markSpamBtn').addEventListener('click', markAsSpam);
    document.getElementById('logoutBtn').addEventListener('click', logout);
}

async function markAsSpam() {
    // Implementation for marking emails as spam
    showNotification('Selected emails marked as spam', 'success');
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        window.location.href = 'login.html';
    }
}

// Utility function to show notifications
function showNotification(message, type) {
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
        background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#17a2b8'};
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}