const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
    // Navigation
    changePage: (page) => ipcRenderer.send('change-page', page),
    
    // Auth
    getCurrentUser: () => ipcRenderer.invoke('get-current-user'),
    register: (data) => ipcRenderer.invoke('register', data),
    login: (data) => ipcRenderer.invoke('login', data),
    
    // Email
    getInbox: () => ipcRenderer.invoke('get-inbox'),
    getSent: () => ipcRenderer.invoke('get-sent'),
    sendEmail: (data) => ipcRenderer.invoke('send-email', data),
    
    // Security Features
    flagSender: (senderEmail, reason) => ipcRenderer.invoke('flag-sender', senderEmail, reason),
    verifyLink: (url) => ipcRenderer.invoke('verify-link', url),
    getSecurityReport: () => ipcRenderer.invoke('get-security-report'),

    // New email management methods
    getEmailStats: () => ipcRenderer.invoke('get-email-stats'),
    markAsSpam: (emailId, reason) => ipcRenderer.invoke('mark-as-spam', emailId, reason),
    getSpam: () => ipcRenderer.invoke('get-spam'),
    deleteEmail: (emailId) => ipcRenderer.invoke('delete-email', emailId),
    permanentDeleteEmail: (emailId) => ipcRenderer.invoke('permanent-delete-email', emailId),
    emptyTrash: () => ipcRenderer.invoke('empty-trash'),
    flagEmail: (emailId, reason, severity) => ipcRenderer.invoke('flag-email', emailId, reason, severity),
    
    // Subscription management
    getSubscriptions: () => ipcRenderer.invoke('get-subscriptions'),
    unsubscribe: (unsubscribeToken) => ipcRenderer.invoke('unsubscribe', unsubscribeToken)
});