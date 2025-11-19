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

    // Extras (Client-side generation for QR to avoid server deps)
    generateQR: async (text) => {
        // You might need a lightweight JS QR lib here or handle it in renderer
        return "QR_CODE_DATA_URL"; 
    }
});