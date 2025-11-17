"""
Multilingual Security Warning System - 15 LANGUAGES
Save as: multilingual_warnings.py
Dual-language warnings for all security features
"""

from typing import List, Dict
from collections import defaultdict


class SecurityWarningTranslations:
    """Security warning translations in 15 languages"""
    
    TRANSLATIONS = {
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
        },
        
        'flag_reason_phishing': {
            'en': 'Phishing attempt',
            'hi': 'फ़िशिंग प्रयास',
            'bn': 'ফিশিং প্রচেষ্টা',
            'te': 'ఫిషింగ్ ప్రయత్నం',
            'mr': 'फिशिंग प्रयत्न',
            'ta': 'ஃபிஷிங் முயற்சி',
            'gu': 'ફિશિંગ પ્રયાસ',
            'kn': 'ಫಿಶಿಂಗ್ ಪ್ರಯತ್ನ',
            'ml': 'ഫിഷിംഗ് ശ്രമം',
            'pa': 'ਫਿਸ਼ਿੰਗ ਕੋਸ਼ਿਸ਼',
            'or': 'ଫିସିଂ ପ୍ରୟାସ',
            'as': 'ফিছিং প্ৰয়াস',
        },
        
        'flag_reason_spam': {
            'en': 'Spam email',
            'hi': 'स्पैम ईमेल',
            'bn': 'স্প্যাম ইমেল',
            'te': 'స్పామ్ ఇమెయిల్',
            'mr': 'स्पॅम ईमेल',
            'ta': 'ஸ்பாம் மின்னஞ்சல்',
            'gu': 'સ્પામ ઈમેલ',
            'kn': 'ಸ್ಪ್ಯಾಮ್ ಇಮೇಲ್',
            'ml': 'സ്പാം ഇമെയിൽ',
            'pa': 'ਸਪੈਮ ਈਮੇਲ',
            'or': 'ସ୍ପାମ୍ ଇମେଲ୍',
            'as': 'স্পাম ইমেইল',
        },
        
        'flag_reason_malware': {
            'en': 'Contains malware',
            'hi': 'मैलवेयर शामिल है',
            'bn': 'ম্যালওয়্যার রয়েছে',
            'te': 'మాల్వేర్ ఉంది',
            'mr': 'मालवेअर आहे',
            'ta': 'மால்வேர் உள்ளது',
            'gu': 'માલવેર છે',
            'kn': 'ಮಾಲ್ವೇರ್ ಇದೆ',
            'ml': 'മാൽവെയർ ഉണ്ട്',
            'pa': 'ਮਾਲਵੇਅਰ ਹੈ',
            'or': 'ମାଲୱେର୍ ଅଛି',
            'as': 'মেলৱেৰ আছে',
        },
        
        'flag_reason_impersonation': {
            'en': 'Impersonation attempt',
            'hi': 'प्रतिरूपण प्रयास',
            'bn': 'ছদ্মবেশ প্রচেষ্টা',
            'te': 'వేషధారణ ప్రయత్నం',
            'mr': 'प्रतिरूपण प्रयत्न',
            'ta': 'ஆள்மாறாட்ட முயற்சி',
            'gu': 'છળકપટનો પ્રયાસ',
            'kn': 'ಪ್ರತಿರೂಪಣೆ ಪ್ರಯತ್ನ',
            'ml': 'ആൾമാറാട്ട ശ്രമം',
            'pa': 'ਨਕਲ ਕਰਨ ਦੀ ਕੋਸ਼ਿਸ਼',
            'or': 'ଛଦ୍ମବେଶ ପ୍ରୟାସ',
            'as': 'নকল কৰাৰ প্ৰয়াস',
        },
        
        'flag_reason_scam': {
            'en': 'Financial scam',
            'hi': 'वित्तीय घोटाला',
            'bn': 'আর্থিক প্রতারণা',
            'te': 'ఆర్థిక మోసం',
            'mr': 'आर्थिक घोटाळा',
            'ta': 'நிதி மோசடி',
            'gu': 'નાણાકીય કૌભાંડ',
            'kn': 'ಹಣಕಾಸು ವಂಚನೆ',
            'ml': 'സാമ്പത്തിക തട്ടിപ്പ്',
            'pa': 'ਵਿੱਤੀ ਘੋਟਾਲਾ',
            'or': 'ଆର୍ଥିକ ପ୍ରତାରଣା',
            'as': 'আৰ্থিক প্ৰতাৰণা',
        },
    }
    
    @staticmethod
    def get_translation(key: str, language: str, **kwargs) -> str:
        """Get translation for a key in specified language"""
        translations = SecurityWarningTranslations.TRANSLATIONS.get(key, {})
        text = translations.get(language, translations.get('en', key))
        
        try:
            return text.format(**kwargs)
        except KeyError:
            return text
    
    @staticmethod
    def get_dual_language_warning(key: str, languages: List[str], **kwargs) -> Dict[str, str]:
        """Get warning in two languages"""
        if not languages or len(languages) == 0:
            languages = ['en', 'en']
        elif len(languages) == 1:
            languages = [languages[0], 'en']
        
        primary_lang = languages[0]
        secondary_lang = languages[1] if len(languages) > 1 else 'en'
        
        return {
            'primary': SecurityWarningTranslations.get_translation(key, primary_lang, **kwargs),
            'secondary': SecurityWarningTranslations.get_translation(key, secondary_lang, **kwargs),
            'primary_lang': primary_lang,
            'secondary_lang': secondary_lang
        }


class SecurityBadge:
    """Color-coded security badges (Green/Yellow/Red)"""
    
    @staticmethod
    def get_badge(safe_score: int, flags_count: int) -> Dict:
        """Generate security badge"""
        if safe_score >= 70 and flags_count < 2:
            return {
                'color': 'green',
                'label': 'Safe',
                'score': safe_score,
                'icon': '✓',
                'css_class': 'badge-safe'
            }
        elif safe_score >= 40 or flags_count < 5:
            return {
                'color': 'yellow',
                'label': 'Caution',
                'score': safe_score,
                'icon': '⚠',
                'css_class': 'badge-caution'
            }
        else:
            return {
                'color': 'red',
                'label': 'Dangerous',
                'score': safe_score,
                'icon': '✗',
                'css_class': 'badge-danger'
            }
    
    @staticmethod
    def get_badge_with_translations(safe_score: int, flags_count: int, languages: List[str]) -> Dict:
        """Get badge with multilingual descriptions"""
        badge = SecurityBadge.get_badge(safe_score, flags_count)
        
        if badge['color'] == 'green':
            translations = SecurityWarningTranslations.get_dual_language_warning('safe_sender', languages)
        elif badge['color'] == 'yellow':
            translations = SecurityWarningTranslations.get_dual_language_warning('suspicious_sender', languages)
        else:
            translations = SecurityWarningTranslations.get_dual_language_warning('phishing_warning', languages)
        
        badge['title_primary'] = translations['primary']
        badge['title_secondary'] = translations['secondary']
        
        return badge


class EmailSecurityAnalyzer:
    """Analyze email and generate security warnings"""
    
    @staticmethod
    def analyze_email(email_data: Dict, sender_reputation: Dict, user_languages: List[str]) -> Dict:
        """Complete email security analysis with multilingual warnings"""
        warnings = []
        
        safe_score = sender_reputation.get('safe_score', 50)
        flags = sender_reputation.get('total_flags', 0)
        
        badge = SecurityBadge.get_badge_with_translations(safe_score, flags, user_languages)
        
        if flags >= 5:
            warning = SecurityWarningTranslations.get_dual_language_warning(
                'phishing_warning', user_languages
            )
            details = SecurityWarningTranslations.get_dual_language_warning(
                'phishing_details', user_languages, count=flags
            )
            
            warnings.append({
                'type': 'phishing',
                'severity': 'high',
                'title': warning,
                'details': details
            })
        
        if len([w for w in warnings if w['severity'] == 'high']) > 0:
            security_level = 'danger'
        elif len(warnings) > 0:
            security_level = 'caution'
        else:
            security_level = 'safe'
        
        return {
            'security_level': security_level,
            'badge': badge,
            'warnings': warnings,
            'safe_score': safe_score,
            'flags_count': flags
        }


class SenderFlaggingSystem:
    """Sender flagging with multilingual support"""
    
    FLAG_REASONS = [
        'flag_reason_phishing',
        'flag_reason_spam',
        'flag_reason_malware',
        'flag_reason_impersonation',
        'flag_reason_scam'
    ]
    
    @staticmethod
    def get_flag_reasons(languages: List[str]) -> List[Dict]:
        """Get available flag reasons in user's languages"""
        reasons = []
        
        for reason_key in SenderFlaggingSystem.FLAG_REASONS:
            translations = SecurityWarningTranslations.get_dual_language_warning(reason_key, languages)
            simple_key = reason_key.replace('flag_reason_', '')
            
            reasons.append({
                'key': simple_key,
                'label_primary': translations['primary'],
                'label_secondary': translations['secondary']
            })
        
        return reasons
    
    @staticmethod
    def create_flag_report(sender_email: str, reason: str, languages: List[str]) -> Dict:
        """Create a flag report with multilingual information"""
        translations = SecurityWarningTranslations.get_dual_language_warning(
            f'flag_reason_{reason}', languages
        )
        
        return {
            'sender': sender_email,
            'reason': reason,
            'reason_text_primary': translations['primary'],
            'reason_text_secondary': translations['secondary']
        }
