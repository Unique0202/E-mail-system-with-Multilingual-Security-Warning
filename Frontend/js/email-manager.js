class EmailManager {
    constructor() {
        this.currentFolder = 'inbox';
        this.selectedEmails = new Set();
        this.userLanguage = 'en';
        this.securityMessages = {
            en: {
                suspicious: '⚠️ Security Warning: This email appears suspicious',
                phishing: '🚨 Phishing Alert: Potential phishing attempt detected',
                unsafeLink: '🔗 Warning: This link may be unsafe',
                flagged: '🚩 This sender has been flagged by multiple users'
            },
            es: {
                suspicious: '⚠️ Advertencia de seguridad: Este correo parece sospechoso',
                phishing: '🚨 Alerta de phishing: Posible intento de phishing detectado',
                unsafeLink: '🔗 Advertencia: Este enlace puede ser inseguro',
                flagged: '🚩 Este remitente ha sido marcado por múltiples usuarios'
            },
            fr: {
                suspicious: '⚠️ Avertissement de sécurité: Cet email semble suspect',
                phishing: '🚨 Alerte de hameçonnage: Tentative de phishing détectée',
                unsafeLink: '🔗 Attention: Ce lien peut être dangereux',
                flagged: '🚩 Cet expéditeur a été signalé par plusieurs utilisateurs'
            }
        };
    }

    async loadEmails(folder) {
        this.currentFolder = folder;
        try {
            const emails = await window.electronAPI.getEmails(folder);
            this.displayEmails(emails);
        } catch (error) {
            console.error('Error loading emails:', error);
        }
    }

    displayEmails(emails) {
        const emailList = document.getElementById('emailList');
        emailList.innerHTML = '';

        emails.forEach(email => {
            const emailElement = this.createEmailElement(email);
            emailList.appendChild(emailElement);
        });
    }

    createEmailElement(email) {
        const div = document.createElement('div');
        div.className = `email-item ${this.getSafetyClass(email.safetyScore)}`;
        
        const safetyLevel = this.getSafetyLevel(email.safetyScore);
        const safetyText = this.getSafetyText(safetyLevel);
        
        div.innerHTML = `
            <div class="email-header">
                <span class="email-sender">${email.from}</span>
                <span class="email-safety safety-${safetyLevel}">${safetyText}</span>
            </div>
            <div class="email-subject">${email.subject}</div>
            <div class="email-preview">${email.body.substring(0, 100)}...</div>
            <div class="email-timestamp">${email.timestamp}</div>
            ${this.createSecurityWarning(email)}
            <div class="email-actions">
                <button class="btn-secondary flag-btn" data-sender="${email.from}">🚩 Flag</button>
                ${this.currentFolder === 'spam' ? '<button class="btn-secondary">✅ Not Spam</button>' : ''}
                ${this.currentFolder === 'subscriptions' ? '<button class="btn-secondary">📪 Unsubscribe</button>' : ''}
            </div>
        `;

        // Add event listeners
        const flagBtn = div.querySelector('.flag-btn');
        flagBtn.addEventListener('click', () => this.flagSender(email.from));

        return div;
    }

    createSecurityWarning(email) {
        if (email.safetyScore < 40) {
            return `
                <div class="security-warning">
                    <span class="warning-icon">⚠️</span>
                    <span>${this.getSecurityMessage('suspicious')}</span>
                </div>
            `;
        } else if (email.safetyScore < 70) {
            return `
                <div class="security-warning">
                    <span class="warning-icon">🔍</span>
                    <span>${this.getSecurityMessage('flagged')}</span>
                </div>
            `;
        }
        return '';
    }

    getSafetyClass(score) {
        if (score >= 70) return 'safe';
        if (score >= 40) return 'warning';
        return 'suspicious';
    }

    getSafetyLevel(score) {
        if (score >= 70) return 'high';
        if (score >= 40) return 'medium';
        return 'low';
    }

    getSafetyText(level) {
        const texts = {
            high: 'Safe',
            medium: 'Caution',
            low: 'Dangerous'
        };
        return texts[level];
    }

    getSecurityMessage(type) {
        return this.securityMessages[this.userLanguage][type] || 
               this.securityMessages.en[type];
    }

    async flagSender(sender) {
        try {
            const result = await window.electronAPI.flagSender(sender);
            showNotification('Sender flagged successfully', 'success');
        } catch (error) {
            showNotification('Error flagging sender', 'error');
        }
    }

    setLanguage(lang) {
        this.userLanguage = lang;
        // Reload current emails to update warnings
        this.loadEmails(this.currentFolder);
    }
}

// Initialize email manager
const emailManager = new EmailManager();