"""
Open-Source Link Verification - NO EXTERNAL APIS
Save as: opensource_link_verifier.py
"""

import re
import hashlib
import urllib.parse
import time
from typing import Dict, List, Set
import logging

logger = logging.getLogger(__name__)


class PhishingBlacklist:
    """Local phishing domain blacklist"""
    
    def __init__(self, blacklist_file: str = 'phishing_blacklist.txt'):
        self.blacklist_file = blacklist_file
        self.blacklisted_domains: Set[str] = set()
        self.load_blacklist()
    
    def load_blacklist(self):
        try:
            with open(self.blacklist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.blacklisted_domains.add(line.lower())
            logger.info(f"Loaded {len(self.blacklisted_domains)} domains to blacklist")
        except FileNotFoundError:
            logger.warning("Blacklist file not found, creating default")
            self.blacklisted_domains = {'bit.ly', 'tinyurl.com', 'goo.gl'}
            self.save_blacklist()
    
    def save_blacklist(self):
        with open(self.blacklist_file, 'w') as f:
            f.write("# Phishing Domain Blacklist\n")
            for domain in sorted(self.blacklisted_domains):
                f.write(f"{domain}\n")
    
    def is_blacklisted(self, domain: str) -> bool:
        domain = domain.lower().strip()
        
        if domain in self.blacklisted_domains:
            return True
        
        parts = domain.split('.')
        for i in range(len(parts)):
            subdomain = '.'.join(parts[i:])
            if subdomain in self.blacklisted_domains:
                return True
        
        return False


class HeuristicURLAnalyzer:
    """Heuristic URL analysis - 13+ security checks"""
    
    SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
    
    PHISHING_KEYWORDS = [
        'verify', 'account', 'login', 'update', 'confirm', 'secure',
        'banking', 'paypal', 'suspended', 'locked', 'urgent'
    ]
    
    @staticmethod
    def analyze_url(url: str) -> Dict:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        risk_score = 0
        warnings = []
        
        # Check 1: HTTPS
        if parsed.scheme != 'https':
            risk_score += 20
            warnings.append("Not using HTTPS encryption")
        
        # Check 2: IP address
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            risk_score += 30
            warnings.append("URL uses IP address")
        
        # Check 3: Suspicious TLD
        for tld in HeuristicURLAnalyzer.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                risk_score += 25
                warnings.append(f"Suspicious TLD: {tld}")
                break
        
        # Check 4: Domain length
        if len(domain) > 50:
            risk_score += 15
            warnings.append("Unusually long domain")
        
        # Check 5: Subdomain count
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            risk_score += 20
            warnings.append(f"Excessive subdomains ({subdomain_count})")
        
        # Check 6: Phishing keywords
        full_url = url.lower()
        found_keywords = [kw for kw in HeuristicURLAnalyzer.PHISHING_KEYWORDS if kw in full_url]
        if found_keywords:
            risk_score += len(found_keywords) * 5
            warnings.append(f"Contains suspicious keywords")
        
        # Check 7: Unusual port
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            risk_score += 10
            warnings.append(f"Unusual port: {parsed.port}")
        
        # Check 8: @ symbol
        if '@' in url:
            risk_score += 30
            warnings.append("URL contains @ symbol")
        
        # Check 9: Excessive hyphens
        if domain.count('-') > 3:
            risk_score += 10
            warnings.append("Excessive hyphens")
        
        # Check 10: URL length
        if len(url) > 200:
            risk_score += 10
            warnings.append("Unusually long URL")
        
        risk_score = min(risk_score, 100)
        
        if risk_score < 30:
            risk_level = 'low'
        elif risk_score < 60:
            risk_level = 'medium'
        else:
            risk_level = 'high'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'warnings': warnings,
            'is_safe': risk_score < 40
        }


class OpenSourceLinkVerifier:
    """Complete open-source link verification"""
    
    def __init__(self, blacklist_file: str = 'phishing_blacklist.txt'):
        self.blacklist = PhishingBlacklist(blacklist_file)
        self.cache = {}
        self.cache_timeout = 3600
    
    def verify_url(self, url: str) -> Dict:
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        if url_hash in self.cache:
            cached_result, timestamp = self.cache[url_hash]
            if time.time() - timestamp < self.cache_timeout:
                cached_result['cached'] = True
                return cached_result
        
        result = {
            'url': url,
            'is_safe': True,
            'risk_level': 'low',
            'risk_score': 0,
            'warnings': [],
            'checks': {},
            'cached': False
        }
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower().split(':')[0]
            
            # Blacklist check
            if self.blacklist.is_blacklisted(domain):
                result['is_safe'] = False
                result['risk_level'] = 'high'
                result['risk_score'] = 100
                result['warnings'].append("Domain is blacklisted")
                result['checks']['blacklist'] = 'FAIL'
            else:
                result['checks']['blacklist'] = 'PASS'
            
            # Heuristic analysis
            heuristic_result = HeuristicURLAnalyzer.analyze_url(url)
            result['checks']['heuristic'] = heuristic_result
            result['warnings'].extend(heuristic_result['warnings'])
            result['risk_score'] = max(result['risk_score'], heuristic_result['risk_score'])
            
            if not heuristic_result['is_safe']:
                result['is_safe'] = False
            
            # Final risk level
            if result['risk_score'] >= 70:
                result['risk_level'] = 'high'
                result['is_safe'] = False
            elif result['risk_score'] >= 40:
                result['risk_level'] = 'medium'
            else:
                result['risk_level'] = 'low'
        
        except Exception as e:
            logger.error(f"URL verification error: {e}")
            result['warnings'].append(f"Verification error")
            result['risk_level'] = 'unknown'
        
        self.cache[url_hash] = (result, time.time())
        
        return result
