/**
 * Open-Source Link Verification - NO EXTERNAL APIS
 * Equivalent of opensource_link_verifier.py
 */

const crypto = require('crypto');
const url = require('url');

class PhishingBlacklist {
    constructor(blacklistFile = 'phishing_blacklist.txt') {
        this.blacklistFile = blacklistFile;
        this.blacklistedDomains = new Set();
        this.loadBlacklist();
    }

    loadBlacklist() {
        try {
            const fs = require('fs');
            if (fs.existsSync(this.blacklistFile)) {
                const data = fs.readFileSync(this.blacklistFile, 'utf8');
                data.split('\n').forEach(line => {
                    const trimmed = line.trim();
                    if (trimmed && !trimmed.startsWith('#')) {
                        this.blacklistedDomains.add(trimmed.toLowerCase());
                    }
                });
                console.log(`Loaded ${this.blacklistedDomains.size} domains to blacklist`);
            } else {
                // Default blacklist
                this.blacklistedDomains = new Set(['bit.ly', 'tinyurl.com', 'goo.gl']);
                this.saveBlacklist();
            }
        } catch (error) {
            console.warn('Blacklist file not found, creating default');
            this.blacklistedDomains = new Set(['bit.ly', 'tinyurl.com', 'goo.gl']);
        }
    }

    saveBlacklist() {
        const fs = require('fs');
        const content = "# Phishing Domain Blacklist\n" + 
                       Array.from(this.blacklistedDomains).sort().join('\n');
        fs.writeFileSync(this.blacklistFile, content);
    }

    isBlacklisted(domain) {
        domain = domain.toLowerCase().trim();
        
        if (this.blacklistedDomains.has(domain)) {
            return true;
        }

        const parts = domain.split('.');
        for (let i = 0; i < parts.length; i++) {
            const subdomain = parts.slice(i).join('.');
            if (this.blacklistedDomains.has(subdomain)) {
                return true;
            }
        }

        return false;
    }
}

class HeuristicURLAnalyzer {
    static SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
    static PHISHING_KEYWORDS = [
        'verify', 'account', 'login', 'update', 'confirm', 'secure',
        'banking', 'paypal', 'suspended', 'locked', 'urgent'
    ];

    static analyzeURL(urlString) {
        const parsed = new URL(urlString);
        const domain = parsed.hostname.toLowerCase();
        
        let riskScore = 0;
        const warnings = [];

        // Check 1: HTTPS
        if (parsed.protocol !== 'https:') {
            riskScore += 20;
            warnings.push("Not using HTTPS encryption");
        }

        // Check 2: IP address
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
            riskScore += 30;
            warnings.push("URL uses IP address");
        }

        // Check 3: Suspicious TLD
        for (const tld of this.SUSPICIOUS_TLDS) {
            if (domain.endsWith(tld)) {
                riskScore += 25;
                warnings.push(`Suspicious TLD: ${tld}`);
                break;
            }
        }

        // Check 4: Domain length
        if (domain.length > 50) {
            riskScore += 15;
            warnings.push("Unusually long domain");
        }

        // Check 5: Subdomain count
        const subdomainCount = domain.split('.').length - 1;
        if (subdomainCount > 3) {
            riskScore += 20;
            warnings.push(`Excessive subdomains (${subdomainCount})`);
        }

        // Check 6: Phishing keywords
        const fullURL = urlString.toLowerCase();
        const foundKeywords = this.PHISHING_KEYWORDS.filter(keyword => 
            fullURL.includes(keyword)
        );
        if (foundKeywords.length > 0) {
            riskScore += foundKeywords.length * 5;
            warnings.push("Contains suspicious keywords");
        }

        // Check 7: Unusual port
        if (parsed.port && ![80, 443, 8080, 8443].includes(parseInt(parsed.port))) {
            riskScore += 10;
            warnings.push(`Unusual port: ${parsed.port}`);
        }

        // Check 8: @ symbol
        if (urlString.includes('@')) {
            riskScore += 30;
            warnings.push("URL contains @ symbol");
        }

        // Check 9: Excessive hyphens
        if ((domain.match(/-/g) || []).length > 3) {
            riskScore += 10;
            warnings.push("Excessive hyphens");
        }

        // Check 10: URL length
        if (urlString.length > 200) {
            riskScore += 10;
            warnings.push("Unusually long URL");
        }

        riskScore = Math.min(riskScore, 100);

        let riskLevel = 'low';
        if (riskScore >= 70) riskLevel = 'high';
        else if (riskScore >= 40) riskLevel = 'medium';

        return {
            risk_score: riskScore,
            risk_level: riskLevel,
            warnings: warnings,
            is_safe: riskScore < 40
        };
    }
}

class OpenSourceLinkVerifier {
    constructor(blacklistFile = 'phishing_blacklist.txt') {
        this.blacklist = new PhishingBlacklist(blacklistFile);
        this.cache = new Map();
        this.cacheTimeout = 3600000; // 1 hour in milliseconds
    }

    verifyURL(urlString) {
        const urlHash = crypto.createHash('sha256').update(urlString).digest('hex');
        const now = Date.now();

        if (this.cache.has(urlHash)) {
            const { result, timestamp } = this.cache.get(urlHash);
            if (now - timestamp < this.cacheTimeout) {
                return { ...result, cached: true };
            }
        }

        const result = {
            url: urlString,
            is_safe: true,
            risk_level: 'low',
            risk_score: 0,
            warnings: [],
            checks: {},
            cached: false
        };

        try {
            const parsed = new URL(urlString);
            const domain = parsed.hostname.toLowerCase();

            // Blacklist check
            if (this.blacklist.isBlacklisted(domain)) {
                result.is_safe = false;
                result.risk_level = 'high';
                result.risk_score = 100;
                result.warnings.push("Domain is blacklisted");
                result.checks.blacklist = 'FAIL';
            } else {
                result.checks.blacklist = 'PASS';
            }

            // Heuristic analysis
            const heuristicResult = HeuristicURLAnalyzer.analyzeURL(urlString);
            result.checks.heuristic = heuristicResult;
            result.warnings.push(...heuristicResult.warnings);
            result.risk_score = Math.max(result.risk_score, heuristicResult.risk_score);

            if (!heuristicResult.is_safe) {
                result.is_safe = false;
            }

            // Final risk level
            if (result.risk_score >= 70) {
                result.risk_level = 'high';
                result.is_safe = false;
            } else if (result.risk_score >= 40) {
                result.risk_level = 'medium';
            } else {
                result.risk_level = 'low';
            }

        } catch (error) {
            console.error(`URL verification error: ${error}`);
            result.warnings.push("Verification error");
            result.risk_level = 'unknown';
        }

        this.cache.set(urlHash, { result, timestamp: now });
        return result;
    }
}

module.exports = {
    PhishingBlacklist,
    HeuristicURLAnalyzer,
    OpenSourceLinkVerifier
};