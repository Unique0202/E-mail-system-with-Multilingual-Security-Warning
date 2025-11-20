let currentUser = null;
let currentEmails = [];
let currentDetailEmail = null;
let currentDetailIndex = null;

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Get Session from Backend
    currentUser = await window.api.getCurrentUser();
    
    if (!currentUser) {
        window.api.changePage('login');
        return;
    }
    
    document.getElementById('user-display').innerText = currentUser.email;

    // 2. Attach Listeners
    document.getElementById('nav-inbox').addEventListener('click', loadInbox);
    document.getElementById('nav-sent').addEventListener('click', loadSent);
    document.getElementById('nav-compose').addEventListener('click', showCompose);
    document.getElementById('nav-security').addEventListener('click', showSecurityReport);
    document.getElementById('nav-logout').addEventListener('click', () => window.api.changePage('login'));
    
    document.getElementById('btn-send').addEventListener('click', sendEmail);
    document.getElementById('btn-scan-links').addEventListener('click', scanLinksForThreats);
    document.getElementById('btn-back').addEventListener('click', backToList);
    document.getElementById('btn-flag-sender').addEventListener('click', flagCurrentSender);
    document.getElementById('btn-mark-safe').addEventListener('click', markCurrentSenderSafe);

    document.getElementById('nav-spam').addEventListener('click', loadSpam);
    document.getElementById('nav-trash').addEventListener('click', loadTrash);
    document.getElementById('nav-subscriptions').addEventListener('click', loadSubscriptions);

    // 3. Initial Load
    loadInbox();
    // Setup email actions
    setupEmailActions();
    
    // Load stats
    loadEmailStats();
    
    // Refresh stats periodically
    setInterval(loadEmailStats, 30000); // Every 30 seconds
});

function switchView(viewName) {
    ['view-list', 'view-compose', 'view-security', 'view-email-detail'].forEach(id => {
        document.getElementById(id).classList.toggle('hidden', viewName !== id);
    });
}

async function loadInbox() {
    switchView('view-list');
    document.getElementById('folder-title').innerText = "Inbox";
    const emails = await window.api.getInbox();
    currentEmails = emails;
    renderList(emails, true);
}

async function loadSent() {
    switchView('view-list');
    document.getElementById('folder-title').innerText = "Sent";
    const emails = await window.api.getSent();
    currentEmails = emails;
    renderList(emails, false);
}

function renderList(emails, isInbox) {
    const container = document.getElementById('email-list');
    container.innerHTML = '';
    
    if(emails.length === 0) {
        container.innerHTML = '<p>No emails found.</p>';
        return;
    }

    emails.forEach((email, index) => {
        const div = document.createElement('div');
        const security = email.security_analysis || { badge: { color: 'green' } };
        const badgeColor = security.badge.color || 'green';
        
        div.className = `email-item badge-${badgeColor}`;
        div.innerHTML = `
            <div style="display:flex; justify-content:space-between">
                <strong>${isInbox ? email.sender_email : email.recipient_email}</strong>
                <small>${new Date(email.sent_at).toLocaleDateString()}</small>
            </div>
            <div>${email.subject}</div>
            <div class="security-info">
                <span class="security-score">Score: ${security.safe_score || 50}</span>
                ${security.warnings && security.warnings.length > 0 ? 
                 `<span class="security-warning">⚠ ${security.warnings.length} warnings</span>` : ''}
            </div>
        `;
        
        div.onclick = () => openEmailDetail(index);
        container.appendChild(div);
    });
}

function showCompose() {
    switchView('view-compose');
    document.getElementById('comp-to').value = '';
    document.getElementById('comp-subject').value = '';
    document.getElementById('comp-body').value = '';
    document.getElementById('link-warnings').classList.add('hidden');
}

async function scanLinksForThreats() {
    const body = document.getElementById('comp-body').value;
    const urlRegex = /https?:\/\/[^\s]+/g;
    const urls = body.match(urlRegex);
    
    if (!urls || urls.length === 0) {
        alert('No links found in the email body.');
        return;
    }

    const warningsContainer = document.getElementById('link-warnings');
    warningsContainer.innerHTML = '<h4>Link Security Scan:</h4>';
    warningsContainer.classList.remove('hidden');

    for (const url of urls) {
        const result = await window.api.verifyLink(url);
        if (result.success) {
            const warningDiv = document.createElement('div');
            warningDiv.className = `link-warning ${result.result.risk_level}`;
            warningDiv.innerHTML = `
                <strong>${url}</strong> - ${result.result.risk_level.toUpperCase()}
                ${result.result.warnings.length > 0 ? 
                 `<br><small>${result.result.warnings.join(', ')}</small>` : ''}
            `;
            warningsContainer.appendChild(warningDiv);
        }
    }
}

async function sendEmail() {
    const to = document.getElementById('comp-to').value;
    const subject = document.getElementById('comp-subject').value;
    const body = document.getElementById('comp-body').value;
    const from = currentUser.email;

    const res = await window.api.sendEmail({ from, to, subject, body });

    if (res.success) {
        alert('Email sent securely!');
        loadSent();
    } else {
        alert('Error: ' + res.error);
    }
}

function openEmailDetail(index) {
    const email = currentEmails[index];
    currentDetailEmail = email;
    currentDetailIndex = index;
    switchView('view-email-detail');

    document.getElementById('detail-subject').innerText = email.subject || 'No Subject';
    document.getElementById('detail-from').innerText = email.sender_email || 'Unknown';
    document.getElementById('detail-to').innerText = email.recipient_email || 'Unknown';
    document.getElementById('detail-date').innerText = email.sent_at ? new Date(email.sent_at).toLocaleString() : 'Unknown';
    document.getElementById('detail-body').innerText = email.body || '';

    // Display security information
    const security = email.security_analysis || {};
    const badgeData = security.badge || { color: 'green', icon: '✓', title_primary: 'Safe', title_secondary: '' };
    const badge = document.getElementById('security-badge');
    const warnings = document.getElementById('security-warnings');

    warnings.classList.add('hidden');
    warnings.innerHTML = '';

    badge.className = `badge badge-${badgeData.color || 'green'}`;
    badge.innerHTML = `
        ${badgeData.icon || '✓'} ${badgeData.title_primary || 'Safe'}
        <br><small>${badgeData.title_secondary || ''}</small>
    `;

    if (security.warnings && security.warnings.length > 0) {
        warnings.classList.remove('hidden');
        security.warnings.forEach(warning => {
            const warningDiv = document.createElement('div');
            warningDiv.className = `warning-${warning.severity || 'medium'}`;
            const title = warning.title ? (warning.title.primary || '') : '';
            const details = warning.details ? (warning.details.primary || '') : '';
            warningDiv.innerHTML = `
                <strong>${title}</strong>
                <br><small>${details}</small>
            `;
            warnings.appendChild(warningDiv);
        });
    }
}

async function flagCurrentSender() {
    const email = document.getElementById('detail-from').innerText;
    // const reason = prompt("Why are you flagging this sender? (phishing, spam, malware, etc.)");
    const reason = "Manual Flag";
    
    if (reason) {
        const result = await window.api.flagSender(email, reason);
        if (result.success) {
            alert('Sender flagged successfully!');
            loadInbox(); // Refresh to show updated reputation
        } else {
            alert('Error: ' + result.error);
        }
    }
}

async function markCurrentSenderSafe() {
    const email = document.getElementById('detail-from').innerText;
    const result = await window.api.markSenderSafe(email);

    if (result.success) {
        alert('Sender marked as safe!');
        loadInbox();
    } else {
        alert('Error: ' + result.error);
    }
}

async function showSecurityReport() {
    switchView('view-security');
    const report = await window.api.getSecurityReport();
    const container = document.getElementById('security-report');
    
    if (report.success) {
        container.innerHTML = '<h3>Recent Security Events</h3>';
        report.logs.forEach(log => {
            const logDiv = document.createElement('div');
            logDiv.className = `security-log ${log.severity}`;
            logDiv.innerHTML = `
                <strong>${log.event_type}</strong> - ${new Date(log.created_at).toLocaleString()}
                <br><small>${log.details ? JSON.parse(log.details).reason || '' : ''}</small>
            `;
            container.appendChild(logDiv);
        });
    } else {
        container.innerHTML = '<p>Error loading security report.</p>';
    }
}

function backToList() {
    switchView('view-list');
}

// Load email statistics
async function loadEmailStats() {
    const stats = await window.api.getEmailStats();
    if (stats.success) {
        document.getElementById('stat-inbox').textContent = stats.stats.inbox || 0;
        document.getElementById('stat-unread').textContent = (stats.stats.inbox - stats.stats.read) || 0;
        document.getElementById('stat-flagged').textContent = stats.stats.flagged || 0;
    }
}

// Spam management
async function loadSpam() {
    switchView('view-list');
    document.getElementById('folder-title').innerText = "Spam";
    const emails = await window.api.getSpam();
    currentEmails = emails;
    renderList(emails, true);
    
    // Update active nav
    setActiveNav('nav-spam');
}
// Trash management
async function loadTrash() {
    switchView('view-list');
    document.getElementById('folder-title').innerText = "Trash";
    // You'll need to implement getTrash method
    const emails = await window.api.getTrash();
    currentEmails = emails;
    renderList(emails, true);
    
    setActiveNav('nav-trash');
}

// Subscription management
async function loadSubscriptions() {
    switchView('view-subscriptions');
    const result = await window.api.getSubscriptions();
    
    if (result.success) {
        const container = document.getElementById('subscriptions-list');
        container.innerHTML = '';
        
        if (result.subscriptions.length === 0) {
            container.innerHTML = '<p>No active subscriptions found.</p>';
            return;
        }
        
        result.subscriptions.forEach(sub => {
            const div = document.createElement('div');
            div.className = 'subscription-item';
            div.innerHTML = `
                <div class="subscription-info">
                    <strong>${sub.sender_email}</strong>
                    ${sub.subscription_name ? `<br><small>${sub.subscription_name}</small>` : ''}
                    <br><small>Subscribed: ${new Date(sub.created_at).toLocaleDateString()}</small>
                </div>
                <div class="subscription-actions">
                    <button class="unsubscribe-btn" data-token="${sub.unsubscribe_token}">
                        Unsubscribe
                    </button>
                </div>
            `;
            container.appendChild(div);
        });
        
        // Add unsubscribe event listeners
        document.querySelectorAll('.unsubscribe-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const token = e.target.getAttribute('data-token');
                const result = await window.api.unsubscribe(token);
                if (result.success) {
                    alert('Successfully unsubscribed!');
                    loadSubscriptions();
                } else {
                    alert('Error: ' + result.error);
                }
            });
        });
    }
    
    setActiveNav('nav-subscriptions');
}
// Enhanced email actions
function setupEmailActions() {
    document.getElementById('btn-mark-spam').addEventListener('click', markCurrentAsSpam);
    document.getElementById('btn-delete-email').addEventListener('click', deleteCurrentEmail);
}
async function markCurrentAsSpam() {
    if (!currentDetailEmail) return;
    
    // const reason = prompt("Why are you marking this as spam?");
    const reason = "User Marked Spam";
    if (reason) {
        const result = await window.api.markAsSpam(currentDetailEmail.id, reason);
        if (result.success) {
            alert('Email marked as spam!');
            backToList();
        } else {
            alert('Error: ' + result.error);
        }
    }
}

async function deleteCurrentEmail() {
    if (!currentDetailEmail) return;
    
    if (confirm('Are you sure you want to delete this email?')) {
        const result = await window.api.deleteEmail(currentDetailEmail.id);
        if (result.success) {
            alert('Email moved to trash!');
            backToList();
        } else {
            alert('Error: ' + result.error);
        }
    }
}

async function flagCurrentEmail() {
    if (!currentDetailEmail) return;
    
    // const reason = prompt("Why are you flagging this email? (phishing, suspicious, inappropriate, etc.)");
    // if (reason) {
    //     const severity = prompt("Severity (low, medium, high):", "medium");
    //     const result = await window.api.flagEmail(currentDetailEmail.id, reason, severity);
    //     if (result.success) {
    //         alert('Email flagged successfully!');
    //         // Refresh the email detail to show updated status
    //         openEmailDetail(currentDetailIndex);
    //     } else {
    //         alert('Error: ' + result.error);
    //     }
    // }
    const defaultReason = "Manual Flag"; 
    const defaultSeverity = "medium"; 

    // 2. Call the API directly without asking the user
    const result = await window.api.flagEmail(
        currentDetailEmail.id, 
        defaultReason, 
        defaultSeverity
    );

    // 3. Handle the result
    if (result.success) {
        alert('Email flagged successfully!');
        // Refresh the email detail to show updated status
        openEmailDetail(currentDetailIndex);
    } else {
        alert('Error: ' + result.error);
    }
}

// Update navigation
function setActiveNav(navId) {
    // Remove active class from all nav buttons
    document.querySelectorAll('.sidebar button').forEach(btn => {
        btn.classList.remove('active', 'folder-active');
    });
    
    // Add active class to current nav
    const activeBtn = document.getElementById(navId);
    if (activeBtn) {
        activeBtn.classList.add('active', 'folder-active');
    }
}