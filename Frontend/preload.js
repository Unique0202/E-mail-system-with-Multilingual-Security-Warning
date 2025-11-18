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
    getSecurityReport: () => ipcRenderer.invoke('get-security-report')
});