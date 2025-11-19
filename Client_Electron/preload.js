const { contextBridge, ipcRenderer } = require('electron');

const REMOTE_SERVER = 'http://192.168.1.XXX:3000'; // CHANGE THIS TO CAMPUS MACHINE IP

async function apiCall(endpoint, method, body = null) {
    try {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (body) options.body = JSON.stringify(body);
        
        const res = await fetch(`${REMOTE_SERVER}${endpoint}`, options);
        return await res.json();
    } catch (error) {
        return { success: false, error: "Server Connection Failed" };
    }
}

contextBridge.exposeInMainWorld('api', {
    changePage: (page) => {
        // Simple client-side redirection
        if(page === 'dashboard') window.location.href = '../html/dashboard.html';
        if(page === 'login') window.location.href = '../html/login.html';
    },

    // Auth
    login: (data) => apiCall('/api/auth/login', 'POST', data),
    register: (data) => apiCall('/api/auth/register', 'POST', data),
    getCurrentUser: () => {
        // In a real app, you'd fetch this from server session or local storage token
        // For this prototype, we rely on the response from login stored in window
        const userStr = window.localStorage.getItem('currentUser');
        return userStr ? JSON.parse(userStr) : null;
    },

    // Email
    getInbox: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return apiCall(`/api/email/inbox?email=${user.email}`, 'GET');
    },
    getSent: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return apiCall(`/api/email/sent?email=${user.email}`, 'GET');
    },
    sendEmail: (data) => apiCall('/api/email/send', 'POST', data),

    // Security
    flagSender: (sender, reason) => apiCall('/api/security/flag', 'POST', { sender, reason }),
    verifyLink: (url) => apiCall('/api/security/verify-link', 'POST', { url }),
    
    // Extras
    getEmailStats: () => {
        const user = JSON.parse(window.localStorage.getItem('currentUser'));
        return apiCall(`/api/email/stats?email=${user.email}`, 'GET');
    }
});