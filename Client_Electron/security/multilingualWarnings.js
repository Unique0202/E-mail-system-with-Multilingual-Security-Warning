/**
 * Multilingual Security Warning System - 15 LANGUAGES
 * Equivalent of multilingual_warnings.py
 */

class SecurityWarningTranslations {
    static TRANSLATIONS = {
        'phishing_warning': {
            'en': 'Warning: This email may be a phishing attempt',
            'hi': 'चेतावनी: यह ईमेल फ़िशिंग का प्रयास हो सकता है',
            'bn': 'সতর্কতা: এই ইমেলটি ফিশিং প্রচেষ্টা হতে পারে',
            'te': 'హెచ్చరిక: ఈ ఇమెయిల్ ఫిషింగ్ ప్రయత్నం కావచ్చు',
            'mr': 'चेतावणी: हा ईमेल फिशिंग प्रयत्न असू शकतो',
            'ta': 'எச்சரிக்கை: இந்த மின்னஞ்சல் ஃபிஷிங் முயற்சியாக இருக்கலாம்',
            'gu': 'ચેતવણી: આ ઈમેલ ફિશિંગ પ્રયાસ હોઈ શકે છે',
            'kn': 'ಎಚ್ಚರಿಕೆ: ಈ ಇಮೇಲ್ ಫಿಶಿಂಗ್ ಪ್ರಯತ್ನವಾಗಿರಬಹುದು',
            'ml': 'മുന്നറിയിപ്പ്: ഈ ഇമെയിൽ ഫിഷിംഗ് ശ്രമമാകാം',
            'pa': 'ਚੇਤਾਵਨੀ: ਇਹ ਈਮੇਲ ਫਿਸ਼ਿੰਗ ਦੀ ਕੋਸ਼ਿਸ਼ ਹੋ ਸਕਦੀ ਹੈ',
            'or': 'ସତର୍କତା: ଏହି ଇମେଲ୍ ଫିସିଂ ପ୍ରୟାସ ହୋଇପାରେ',
            'as': 'সতৰ্কবাণী: এই ইমেইলটো ফিছিং প্ৰয়াস হ\'ব পাৰে',
            'ur': 'انتباہ: یہ ای میل فشنگ کی کوشش ہو سکتی ہے',
            'es': 'Advertencia: Este correo puede ser un intento de phishing',
            'fr': 'Avertissement: Cet email peut être une tentative de phishing'
        },
        
        'phishing_details': {
            'en': 'This sender has been flagged {count} times for suspicious activity',
            'hi': 'इस प्रेषक को संदिग्ध गतिविधि के लिए {count} बार चिह्नित किया गया है',
            'bn': 'এই প্রেরককে সন্দেহজনক কার্যকলাপের জন্য {count} বার ফ্ল্যাগ করা হয়েছে',
            'te': 'ఈ పంపినవారు అనుమానాస్పద కార్యకలాపాల కోసం {count} సార్లు ఫ్లాగ్ చేయబడ్డారు',
            'mr': 'या प्रेषकास संशयास्पद क्रियाकलापांसाठी {count} वेळा ध्वजांकित केले गेले आहे',
            'ta': 'இந்த அனுப்புநர் சந்தேகத்திற்குரிய செயல்பாட்டிற்காக {count} முறை கொடியிடப்பட்டுள்ளார்',
            'gu': 'આ પ્રેષકને શંકાસ્પદ પ્રવૃત્તિ માટે {count} વખત ફ્લેગ કરવામાં આવ્યો છે',
            'kn': 'ಈ ಕಳುಹಿಸುವವರು ಅನುಮಾನಾಸ್ಪದ ಚಟುವಟಿಕೆಗಾಗಿ {count} ಬಾರಿ ಫ್ಲ್ಯಾಗ್ ಮಾಡಲಾಗಿದೆ',
            'ml': 'ഈ അയച്ചയാളെ സംശയാസ്പദമായ പ്രവർത്തനത്തിന് {count} തവണ ഫ്ലാഗ് ചെയ്തിട്ടുണ്ട്',
            'pa': 'ਇਸ ਭੇਜਣ ਵਾਲੇ ਨੂੰ ਸ਼ੱਕੀ ਗਤੀਵਿਧੀ ਲਈ {count} ਵਾਰ ਫਲੈਗ ਕੀਤਾ ਗਿਆ ਹੈ',
            'or': 'ଏହି ପ୍ରେରକଙ୍କୁ ସନ୍ଦେହଜନକ କାର୍ଯ୍ୟକଳାପ ପାଇଁ {count} ଥର ଫ୍ଲାଗ୍ କରାଯାଇଛି',
            'as': 'এই প্ৰেৰকক সন্দেহজনক কাৰ্যকলাপৰ বাবে {count} বাৰ ফ্লেগ কৰা হৈছে',
            'ur': 'اس مرسل کو مشکوک سرگرمی کے لیے {count} بار نشان زد کیا گیا ہے',
            'es': 'Este remitente ha sido marcado {count} veces por actividad sospechosa',
            'fr': 'Cet expéditeur a été signalé {count} fois pour activité suspecte'
        },
        
        'unsafe_link_warning': {
            'en': 'Dangerous Link Detected',
            'hi': 'खतरनाक लिंक पाया गया',
            'bn': 'বিপজ্জনক লিঙ্ক সনাক্ত করা হয়েছে',
            'te': 'ప్రమాదకరమైన లింక్ కనుగొనబడింది',
            'mr': 'धोकादायक दुवा आढळला',
            'ta': 'ஆபத்தான இணைப்பு கண்டறியப்பட்டது',
            'gu': 'જોખમી લિંક શોધાઈ',
            'kn': 'ಅಪಾಯಕಾರಿ ಲಿಂಕ್ ಪತ್ತೆಯಾಗಿದೆ',
            'ml': 'അപകടകരമായ ലിങ്ക് കണ്ടെത്തി',
            'pa': 'ਖਤਰਨਾਕ ਲਿੰਕ ਮਿਲਿਆ',
            'or': 'ବିପଜ୍ଜନକ ଲିଙ୍କ ଚିହ୍ନଟ ହୋଇଛି',
            'as': 'বিপজ্জনক লিংক ধৰা পৰিছে',
            'ur': 'خطرناک لنک ملا',
            'es': 'Enlace Peligroso Detectado',
            'fr': 'Lien Dangereux Détecté'
        },
        
        'unsafe_link_details': {
            'en': 'This link has been identified as potentially harmful. Do not click.',
            'hi': 'इस लिंक को संभावित रूप से हानिकारक के रूप में पहचाना गया है। क्लिक न करें।',
            'bn': 'এই লিঙ্কটি সম্ভাব্য ক্ষতিকারক হিসাবে চিহ্নিত করা হয়েছে। ক্লিক করবেন না।',
            'te': 'ఈ లింక్ హానికరంగా గుర్తించబడింది. క్లిక్ చేయవద్దు.',
            'mr': 'हा दुवा संभाव्य हानिकारक म्हणून ओळखला गेला आहे. क्लिक करू नका.',
            'ta': 'இந்த இணைப்பு தீங்கு விளைவிக்கக்கூடியது என அடையாளம் காணப்பட்டுள்ளது. கிளிக் செய்ய வேண்டாம்.',
            'gu': 'આ લિંક સંભવિત હાનિકારક તરીકે ઓળખવામાં આવી છે. ક્લિક કરશો નહીં.',
            'kn': 'ಈ ಲಿಂಕ್ ಹಾನಿಕಾರಕವೆಂದು ಗುರುತಿಸಲಾಗಿದೆ. ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ.',
            'ml': 'ഈ ലിങ്ക് അപകടകരമായി തിരിച്ചറിഞ്ഞിട്ടുണ്ട്. ക്ലിക്ക് ചെയ്യരുത്.',
            'pa': 'ਇਸ ਲਿੰਕ ਨੂੰ ਸੰਭਾਵੀ ਤੌਰ \'ਤੇ ਨੁਕਸਾਨਦੇਹ ਵਜੋਂ ਪਛਾਣਿਆ ਗਿਆ ਹੈ। ਕਲਿੱਕ ਨਾ ਕਰੋ।',
            'or': 'ଏହି ଲିଙ୍କ ସମ୍ଭାବ୍ୟ କ୍ଷତିକାରକ ଭାବରେ ଚିହ୍ନଟ ହୋଇଛି। କ୍ଲିକ୍ କରନ୍ତୁ ନାହିଁ।',
            'as': 'এই লিংকটো সম্ভাব্য ক্ষতিকাৰক বুলি চিনাক্ত কৰা হৈছে। ক্লিক নকৰিব।',
            'ur': 'اس لنک کو ممکنہ طور پر نقصان دہ کے طور پر شناخت کیا گیا ہے۔ کلک نہ کریں۔',
            'es': 'Este enlace ha sido identificado como potencialmente dañino. No haga clic.',
            'fr': 'Ce lien a été identifié comme potentiellement dangereux. Ne cliquez pas.'
        },
        
        'spam_warning': {
            'en': 'Possible Spam',
            'hi': 'संभावित स्पैम',
            'bn': 'সম্ভাব্য স্প্যাম',
            'te': 'స్పామ్ కావచ్చు',
            'mr': 'संभाव्य स्पॅम',
            'ta': 'ஸ்பேம் இருக்கலாம்',
            'gu': 'સંભવિત સ્પામ',
            'kn': 'ಸ್ಪ್ಯಾಮ್ ಆಗಿರಬಹುದು',
            'ml': 'സ്പാം ആകാം',
            'pa': 'ਸੰਭਾਵਿਤ ਸਪੈਮ',
            'or': 'ସମ୍ଭାବ୍ୟ ସ୍ପାମ୍',
            'as': 'সম্ভাৱ্য স্পাম',
            'ur': 'ممکنہ اسپیم',
            'es': 'Posible Spam',
            'fr': 'Spam Possible'
        },
        
        'suspicious_sender': {
            'en': 'Suspicious Sender',
            'hi': 'संदिग्ध प्रेषक',
            'bn': 'সন্দেহজনক প্রেরক',
            'te': 'అనుమానాస్పద పంపినవారు',
            'mr': 'संशयास्पद प्रेषक',
            'ta': 'சந்தேகத்திற்குரிய அனுப்புநர்',
            'gu': 'શંકાસ્પદ પ્રેષક',
            'kn': 'ಅನುಮಾನಾಸ್ಪದ ಕಳುಹಿಸುವವರು',
            'ml': 'സംശയാസ്പദമായ അയച്ചയാൾ',
            'pa': 'ਸ਼ੱਕੀ ਭੇਜਣ ਵਾਲਾ',
            'or': 'ସନ୍ଦେହଜନକ ପ୍ରେରକ',
            'as': 'সন্দেহজনক প্ৰেৰক',
            'ur': 'مشکوک مرسل',
            'es': 'Remitente Sospechoso',
            'fr': 'Expéditeur Suspect'
        },
        
        'safe_sender': {
            'en': 'Verified Safe Sender',
            'hi': 'सत्यापित सुरक्षित प्रेषक',
            'bn': 'যাচাইকৃত নিরাপদ প্রেরক',
            'te': 'ధృవీకరించబడిన సురక్షిత పంపినవారు',
            'mr': 'सत्यापित सुरक्षित प्रेषक',
            'ta': 'சரிபார்க்கப்பட்ட பாதுகாப்பான அனுப்புநர்',
            'gu': 'ચકાસાયેલ સલામત પ્રેષક',
            'kn': 'ಪರಿಶೀಲಿಸಿದ ಸುರಕ್ಷಿತ ಕಳುಹಿಸುವವರು',
            'ml': 'പരിശോധിച്ച സുരക്ഷിത അയച്ചയാൾ',
            'pa': 'ਪ੍ਰਮਾਣਿਤ ਸੁਰੱਖਿਅਤ ਭੇਜਣ ਵਾਲਾ',
            'or': 'ଯାଚାଇ ହୋଇଥିବା ସୁରକ୍ଷିତ ପ୍ରେରକ',
            'as': 'সত্যাপিত সুৰক্ষিত প্ৰেৰক',
            'ur': 'تصدیق شدہ محفوظ بھیجنے والا',
            'es': 'Remitente Seguro Verificado',
            'fr': 'Expéditeur Sûr Vérifié'
        }
    };

    static getTranslation(key, language, params = {}) {
        const translations = this.TRANSLATIONS[key] || {};
        let text = translations[language] || translations['en'] || key;
        
        // Replace parameters
        Object.entries(params).forEach(([param, value]) => {
            text = text.replace(new RegExp(`{${param}}`, 'g'), value);
        });
        
        return text;
    }

    static getDualLanguageWarning(key, languages = [], params = {}) {
        if (!languages || languages.length === 0) {
            languages = ['en', 'en'];
        } else if (languages.length === 1) {
            languages = [languages[0], 'en'];
        }
        
        const primaryLang = languages[0];
        const secondaryLang = languages[1];
        
        return {
            primary: this.getTranslation(key, primaryLang, params),
            secondary: this.getTranslation(key, secondaryLang, params),
            primaryLang: primaryLang,
            secondaryLang: secondaryLang
        };
    }
}

class SecurityBadge {
    static getBadge(safeScore, flagsCount) {
        if (safeScore >= 70 && flagsCount < 2) {
            return {
                color: 'green',
                label: 'Safe',
                score: safeScore,
                icon: '✓',
                cssClass: 'badge-safe'
            };
        } else if (safeScore >= 40 || flagsCount < 5) {
            return {
                color: 'yellow',
                label: 'Caution',
                score: safeScore,
                icon: '⚠',
                cssClass: 'badge-caution'
            };
        } else {
            return {
                color: 'red',
                label: 'Dangerous',
                score: safeScore,
                icon: '✗',
                cssClass: 'badge-danger'
            };
        }
    }

    static getBadgeWithTranslations(safeScore, flagsCount, languages = []) {
        const badge = this.getBadge(safeScore, flagsCount);
        
        let translations;
        if (badge.color === 'green') {
            translations = SecurityWarningTranslations.getDualLanguageWarning('safe_sender', languages);
        } else if (badge.color === 'yellow') {
            translations = SecurityWarningTranslations.getDualLanguageWarning('suspicious_sender', languages);
        } else {
            translations = SecurityWarningTranslations.getDualLanguageWarning('phishing_warning', languages);
        }
        
        badge.title_primary = translations.primary;
        badge.title_secondary = translations.secondary;
        
        return badge;
    }
}

class EmailSecurityAnalyzer {
    static analyzeEmail(emailData, senderReputation, userLanguages = []) {
        const warnings = [];
        
        const safeScore = senderReputation?.safe_score || 50;
        const flags = senderReputation?.total_flags || 0;
        
        const badge = SecurityBadge.getBadgeWithTranslations(safeScore, flags, userLanguages);
        
        if (flags >= 5) {
            const warning = SecurityWarningTranslations.getDualLanguageWarning('phishing_warning', userLanguages);
            const details = SecurityWarningTranslations.getDualLanguageWarning('phishing_details', userLanguages, { count: flags });
            
            warnings.push({
                type: 'phishing',
                severity: 'high',
                title: warning,
                details: details
            });
        }
        
        let securityLevel = 'safe';
        if (warnings.some(w => w.severity === 'high')) {
            securityLevel = 'danger';
        } else if (warnings.length > 0) {
            securityLevel = 'caution';
        }
        
        return {
            security_level: securityLevel,
            badge: badge,
            warnings: warnings,
            safe_score: safeScore,
            flags_count: flags
        };
    }
}

module.exports = {
    SecurityWarningTranslations,
    SecurityBadge,
    EmailSecurityAnalyzer
};