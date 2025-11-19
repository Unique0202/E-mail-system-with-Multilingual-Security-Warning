import sys
import json
import re

def scan_email(data):
    body = data.get('body', '').lower()
    subject = data.get('subject', '').lower()
    
    score = 50
    warnings = []
    
    # 1. Phishing Keywords
    keywords = ['verify', 'bank', 'urgent', 'suspended', 'password', 'update account']
    found_keys = [k for k in keywords if k in body or k in subject]
    
    if found_keys:
        score += len(found_keys) * 10
        warnings.append(f"Suspicious keywords found: {', '.join(found_keys)}")

    # 2. Link Analysis (Regex)
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    if urls:
        score += 10
        for url in urls:
            if '@' in url: # Obfuscation
                score += 30
                warnings.append("URL uses obfuscation (@ symbol)")
            if len(url) > 100:
                score += 10
                warnings.append("Unusually long URL detected")

    # Determine Badge
    badge_color = 'green'
    if score > 80: badge_color = 'red'
    elif score > 60: badge_color = 'yellow'

    return {
        "safe_score": 100 - min(score, 100),
        "badge_color": badge_color,
        "warnings": warnings
    }

if __name__ == "__main__":
    try:
        input_data = json.loads(sys.stdin.read())
        result = scan_email(input_data)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))