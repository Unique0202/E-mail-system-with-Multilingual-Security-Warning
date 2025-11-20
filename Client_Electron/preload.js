const { contextBridge, ipcRenderer } = require('electron');

// Helper to call main process -> python
async function pythonCall(endpoint, method, body = null) {
    return await ipcRenderer.invoke('api-request', { endpoint, method, body });
}

contextBridge.exposeInMainWorld('api', {
    changePage: (page) => {
        if(page === 'dashboard') window.location.href = '../html/dashboard.html';
        if(page === 'login') window.location.href = '../html/login.html';
    },

    // Auth
    login: (data) => pythonCall('/api/auth/login', 'POST', data),
    register: (data) => pythonCall('/api/auth/register', 'POST', data),
    getCurrentUser: () => {
        const userStr = window.localStorage.getItem('currentUser');
        return userStr ? JSON.parse(userStr) : null;
    },

    // Email
    getInbox: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/email/inbox?email=${user.email}`, 'GET');
    },
    getSent: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/email/sent?email=${user.email}`, 'GET');
    },
    sendEmail: (data) => pythonCall('/api/email/send', 'POST', data),

    // Email Actions
    markAsSpam: (emailId, reason) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/email/mark_spam', 'POST', { email_id: emailId, reason, user_email: user.email });
    },
    deleteEmail: (emailId) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/email/delete', 'POST', { email_id: emailId, user_email: user.email });
    },
    getSpam: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/email/spam?email=${user.email}`, 'GET');
    },
    getTrash: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/email/trash?email=${user.email}`, 'GET');
    },
    markNotSpam: (emailId) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/email/not_spam', 'POST', { email_id: emailId, user_email: user.email });
    },
    restoreEmail: (emailId) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/email/restore', 'POST', { email_id: emailId, user_email: user.email });
    },
    deletePermanently: (emailId) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/email/delete_permanent', 'POST', { email_id: emailId, user_email: user.email });
    },
    blockSender: (senderEmail) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/sender/block', 'POST', { sender_email: senderEmail, user_email: user.email });
    },
    unblockSender: (senderEmail) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/sender/unblock', 'POST', { sender_email: senderEmail, user_email: user.email });
    },
    isBlocked: (senderEmail) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/sender/is_blocked?sender_email=${senderEmail}&user_email=${user.email}`, 'GET');
    },
    markAsRead: (emailId) => {
        return pythonCall('/api/email/mark_read', 'POST', { email_id: emailId });
    },

    // Sender Reputation
    flagSender: (senderEmail, reason) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/reputation/flag', 'POST', { sender_email: senderEmail, reason, user_email: user.email });
    },
    markSenderSafe: (senderEmail) => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall('/api/reputation/mark_safe', 'POST', { sender_email: senderEmail, user_email: user.email });
    },

    // Security
    getSecurityReport: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/security/report?email=${user.email}`, 'GET');
    },
    getEmailStats: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/email/stats?email=${user.email}`, 'GET');
    },
    verifyLink: (url) => {
        return pythonCall('/api/security/verify_link', 'POST', { url });
    },

    // Subscriptions
    getSubscriptions: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return pythonCall(`/api/subscriptions?email=${user.email}`, 'GET');
    },
    unsubscribe: (token) => {
        return pythonCall('/api/unsubscribe', 'POST', { token });
    },

    // Extras (Client-side generation for QR to avoid server deps)
    generateQR: async (text) => {
        // You might need a lightweight JS QR lib here or handle it in renderer
        return "QR_CODE_DATA_URL";
    }
});