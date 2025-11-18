let currentUser = null;
let currentEmails = [];

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

    // 3. Initial Load
    loadInbox();
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

    const res = await window.api.sendEmail({ to, subject, body });
    
    if (res.success) {
        alert('Email sent securely!');
        loadSent();
    } else {
        alert('Error: ' + res.error);
    }
}

function openEmailDetail(index) {
    const email = currentEmails[index];
    switchView('view-email-detail');
    
    document.getElementById('detail-subject').innerText = email.subject;
    document.getElementById('detail-from').innerText = email.sender_email;
    document.getElementById('detail-to').innerText = email.recipient_email;
    document.getElementById('detail-date').innerText = new Date(email.sent_at).toLocaleString();
    document.getElementById('detail-body').innerText = email.body;

    // Display security information
    const security = email.security_analysis;
    const badge = document.getElementById('security-badge');
    const warnings = document.getElementById('security-warnings');
    
    warnings.classList.add('hidden');
    warnings.innerHTML = '';

    if (security) {
        badge.className = `badge badge-${security.badge.color}`;
        badge.innerHTML = `
            ${security.badge.icon} ${security.badge.title_primary}
            <br><small>${security.badge.title_secondary}</small>
        `;

        if (security.warnings && security.warnings.length > 0) {
            warnings.classList.remove('hidden');
            security.warnings.forEach(warning => {
                const warningDiv = document.createElement('div');
                warningDiv.className = `warning-${warning.severity}`;
                warningDiv.innerHTML = `
                    <strong>${warning.title.primary}</strong>
                    <br><small>${warning.details.primary}</small>
                `;
                warnings.appendChild(warningDiv);
            });
        }
    }
}

async function flagCurrentSender() {
    const email = document.getElementById('detail-from').innerText;
    const reason = prompt("Why are you flagging this sender? (phishing, spam, malware, etc.)");
    
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
    const result = await window.api.flagSender(email, "marked_safe");
    
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