import re
import sys
import os
import time
import json
import argparse
import logging
from typing import Dict, List, Tuple, Any, Set, Optional
from difflib import SequenceMatcher
from urllib.parse import urlparse
import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('phishing_detector')

# Constants
# Move these to the top of the file for easy configuration
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cache')
URL_CACHE_PATH = os.path.join(CACHE_DIR, 'url_reputation_cache.json')
CACHE_EXPIRY_DAYS = 7
CACHE_EXPIRY_SECONDS = CACHE_EXPIRY_DAYS * 24 * 60 * 60

#put your google api key here
API_KEY = None

# Commonly spoofed business domains
COMMON_DOMAINS = {
    'microsoft.com', 'apple.com', 'amazon.com', 'google.com', 
    'paypal.com', 'facebook.com', 'netflix.com', 'linkedin.com',
    'twitter.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    'citi.com', 'amex.com', 'irs.gov', 'usps.com', 'fedex.com', 'dhl.com',
    'ups.com', 'zoom.us', 'outlook.com', 'gmail.com', 'yahoo.com', 'dropbox.com',
    'instagram.com', 'spotify.com', 'uber.com', 'airbnb.com', 'shopify.com',
    'slack.com', 'ebay.com', 'walmart.com', 'target.com', 'costco.com'
}

# Suspicious TLDs often associated with free domains and phishing
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 
    'info', 'online', 'site', 'club', 'stream', 'win', 'bid'
}

# Phishing-related keywords often found in domain names
SUSPICIOUS_KEYWORDS = {
    'secure', 'login', 'signin', 'verify', 'verification', 'authenticate', 
    'account', 'update', 'confirm', 'safe', 'alert', 'limited', 'billing'
}

# Risky file extensions
RISKY_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'msi', 'vbs', 'js', 'wsf', 'ps1', 'jar', 'scr', 'hta'
}

# Compressed file extensions
COMPRESSED_EXTENSIONS = {
    'zip', 'rar', '7z', 'gz', 'tar', 'iso'
}

# Language patterns for phishing detection
URGENCY_PATTERNS = [
    'urgent', 'immediately', 'action required', 'alert', 'attention', 
    'important update', 'expire', 'suspended', 'verify', 'confirm identity',
    'security alert', 'unauthorized', 'suspicious activity', 'limited time',
    'your account', 'password', 'locked', 'access denied', 'update your',
    'validate your', 'problem with your', 'last warning', 'final notice',
    'time sensitive', 'act now', 'deadline', '24 hours', '48 hours',
    'within hours', 'promptly', 'as soon as possible', 'asap', 'quick action'
]

THREAT_PATTERNS = [
    'will be terminated', 'will be suspended', 'will be closed', 
    'will be locked', 'legal action', 'reported to', 'consequences',
    'failure to', 'if you fail', 'unless you', 'required by law',
    'permanently disabled', 'lose access', 'deletion', 'removed',
    'financial loss', 'penalty', 'fee', 'charge', 'money will be',
    'funds will be', 'transferred', 'withdrawn', 'police', 'fbi',
    'investigation', 'fraud', 'lawsuit', 'identity theft'
]

REWARD_PATTERNS = [
    'free', 'bonus', 'gift', 'won', 'congratulations', 'selected',
    'exclusive offer', 'limited offer', 'special offer', 'discount',
    'prize', 'award', 'reward', 'claim your', 'redeem', 'coupon',
    'promotion', 'deal', 'save', 'special rate', 'earn', 'extra'
]


def read_email_file(file_path: str) -> str:
    """
    Read the contents of an email file with encoding fallbacks.
    
    Args:
        file_path: Path to the email text file
        
    Returns:
        The email content as a string
    """
    try:
        # First attempt to read with UTF-8 encoding (most common)
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
        
    except UnicodeDecodeError:
        # Fallback to Latin-1 encoding if UTF-8 fails
        with open(file_path, 'r', encoding='latin-1') as file:
            return file.read()
        
    except FileNotFoundError:
        logger.error(f"File '{file_path}' not found.")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        sys.exit(1)


def parse_email(content: str) -> Dict[str, str]:
    """
    Parse the email content into its components.
    
    Args:
        content: Raw email content
        
    Returns:
        Dictionary with email parts (sender, subject, body)
    """
    # Split headers and body - email format typically separates these with a blank line
    parts = content.split("\n\n", 1)
    headers = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    
    # Extract sender information
    from_match = re.search(r"From:\s*(.*)", headers, re.IGNORECASE)
    sender = from_match.group(1).strip() if from_match else ""
    
    # Extract sender email address
    email_regex = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    sender_email_matches = email_regex.findall(sender)
    sender_email = sender_email_matches[0] if sender_email_matches else ""
    
    # Extract subject line
    subject_match = re.search(r"Subject:\s*(.*)", headers, re.IGNORECASE)
    subject = subject_match.group(1).strip() if subject_match else ""
    
    # Extract attachment filenames
    attachment_pattern = r'Content-Disposition:\s*(attachment|inline);\s*filename=["\']?([^"\';\r\n]+)'
    attachments = re.findall(attachment_pattern, content, re.IGNORECASE)
    attachment_names = [match[1] for match in attachments]
    
    return {
        'sender': sender,
        'sender_email': sender_email,
        'subject': subject,
        'body': body,
        'headers': headers,
        'full_content': content,
        'attachments': attachment_names
    }


def extract_urls(text: str) -> List[str]:
    """
    Extract and normalize URLs from text content.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of normalized URLs found in the text
    """
    # Comprehensive regex pattern for URLs
    url_pattern = re.compile(
        r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?',
        re.IGNORECASE
    )
    
    # Find all URLs and normalize them
    urls = []
    for url in url_pattern.findall(text):
        normalized_url = url
        if url.startswith('www.'):
            normalized_url = 'http://' + url
        urls.append(normalized_url)
    
    return list(set(urls))  # Remove duplicates


def check_suspicious_links(urls: List[str]) -> List[Dict]:
    """
    Analyze URLs for suspicious patterns.
    
    Args:
        urls: List of URLs to analyze
        
    Returns:
        List of dictionaries with suspicious URL details
    """
    suspicious_urls = []
    
    for url in urls:
        reasons = []
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Check for IP address instead of domain name
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        if ip_pattern.search(url):
            reasons.append("URL contains IP address instead of domain name")
        
        # Check if URL uses a suspicious TLD
        tld_match = re.search(r'\.([^.]+)$', domain)
        if tld_match:
            tld = tld_match.group(1).lower()
            if tld in SUSPICIOUS_TLDS:
                reasons.append(f"URL uses suspicious top-level domain (.{tld})")
        
        # Check for suspicious keywords in domain
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in domain and not any(legitimate in domain for legitimate in ['google', 'microsoft', 'amazon', 'apple']):
                reasons.append(f"Domain contains suspicious keyword '{keyword}'")
                break
        
        # Check for unusually long URLs
        if len(url) > 100:
            reasons.append(f"Unusually long URL ({len(url)} characters)")
        
        # Check for redirect parameters
        redirect_patterns = ['redirect', 'url=', 'link=', 'goto', 'redir', 'return', 'returnurl']
        if any(pattern in url.lower() for pattern in redirect_patterns):
            reasons.append(f"URL contains possible redirection pattern")
        
        # Check for encoded characters
        if '%' in url and any(c in url for c in ['%3A', '%2F', '%3D', '%3F']):
            reasons.append("URL contains encoded characters that may obscure its destination")
        
        # Check for excessive subdomains
        domain_parts = domain.split('.')
        if len(domain_parts) >= 4:
            reasons.append(f"URL has an unusual number of subdomains ({len(domain_parts) - 2})")
        
        # If any suspicious patterns found, add URL and reasons to results
        if reasons:
            suspicious_urls.append({
                'url': url,
                'reasons': reasons
            })
    
    return suspicious_urls


def ensure_cache_exists():
    """Ensure the cache directory and file exist."""
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)
    
    if not os.path.exists(URL_CACHE_PATH):
        with open(URL_CACHE_PATH, 'w') as f:
            json.dump({}, f)


def load_url_cache() -> Dict:
    """Load URL reputation cache from disk."""
    ensure_cache_exists()
    try:
        with open(URL_CACHE_PATH, 'r') as cache_file:
            return json.load(cache_file)
    except Exception as e:
        logger.warning(f"Could not load URL cache: {e}")
        return {}


def save_url_cache(cache: Dict) -> None:
    """Save URL reputation cache to disk."""
    ensure_cache_exists()
    try:
        with open(URL_CACHE_PATH, 'w') as cache_file:
            json.dump(cache, cache_file)
    except Exception as e:
        logger.warning(f"Could not save URL cache: {e}")


def check_url_reputation(urls: List[str]) -> Dict[str, Dict]:
    """
    Check URLs against Google Safe Browsing API to identify known malicious ones.
    
    Args:
        urls: List of URLs to check
        
    Returns:
        Dictionary with URL reputation results, keyed by URL
    """
    if not urls:
        return {}
        
    # Initialize results and load cache
    results = {}
    url_cache = load_url_cache()
    uncached_urls = []
    
    # Check cache first
    for url in urls:
        parsed_url = urlparse(url)
        cache_key = parsed_url.netloc.lower()
        
        # Check if URL is in cache and not expired
        if (cache_key in url_cache and 
            url_cache[cache_key]['timestamp'] > time.time() - CACHE_EXPIRY_SECONDS):
            results[url] = url_cache[cache_key]['result']
        else:
            uncached_urls.append(url)
    
    # If all URLs were in cache or no API key, return results
    if not uncached_urls or not API_KEY:
        if not API_KEY:
            logger.warning("No Google Safe Browsing API key provided. Skipping reputation check.")
        return results
    
    # Prepare API request for uncached URLs
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", 
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in uncached_urls]
        }
    }
    
    try:
        # Make the API request
        response = requests.post(api_url, json=payload)
        response.raise_for_status()
        findings = response.json()
        
        # Mark all uncached URLs as safe by default
        threat_mapping = {
            'MALWARE': 'MALWARE',
            'SOCIAL_ENGINEERING': 'PHISHING',
            'UNWANTED_SOFTWARE': 'UNWANTED',
            'POTENTIALLY_HARMFUL_APPLICATION': 'HARMFUL'
        }
        
        # First mark all as safe
        for url in uncached_urls:
            parsed_url = urlparse(url)
            cache_key = parsed_url.netloc.lower()
            
            result = {
                'is_malicious': False,
                'threat_type': None,
                'confidence': None,
                'source': 'Google Safe Browsing'
            }
            
            # Update cache and results
            url_cache[cache_key] = {
                'result': result,
                'timestamp': time.time()
            }
            results[url] = result
        
        # Then update any that are found in the threats
        if 'matches' in findings and findings['matches']:
            for match in findings['matches']:
                matched_url = match.get('threat', {}).get('url', '')
                
                if matched_url in uncached_urls:
                    parsed_url = urlparse(matched_url)
                    cache_key = parsed_url.netloc.lower()
                    
                    threat_type = match.get('threatType', 'UNKNOWN')
                    
                    # Create result for this URL
                    result = {
                        'is_malicious': True,
                        'threat_type': threat_mapping.get(threat_type, threat_type),
                        'confidence': 'HIGH',  # Google doesn't provide confidence levels
                        'source': 'Google Safe Browsing'
                    }
                    
                    # Update cache and results
                    url_cache[cache_key] = {
                        'result': result,
                        'timestamp': time.time()
                    }
                    results[matched_url] = result
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error with Google Safe Browsing API: {e}")
    
    # Save updated cache
    save_url_cache(url_cache)
    
    return results


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate the Levenshtein distance between two strings.
    This measures how many single-character edits are needed to change one string into another.
    
    Args:
        s1: First string
        s2: Second string
        
    Returns:
        Integer distance value (smaller means more similar strings)
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def find_suspicious_domain_matches(domain: str) -> Tuple[bool, List[str]]:
    """
    Check if a domain is suspiciously similar to common legitimate domains.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Tuple of (is_suspicious, reasons)
    """
    is_suspicious = False
    reasons = []
    
    for legitimate_domain in COMMON_DOMAINS:
        # Skip if exact match (legitimate domain)
        if domain == legitimate_domain:
            continue
        
        # Check lookalike strategies
        if domain.replace('-', '') == legitimate_domain or \
            domain.replace('.', '') == legitimate_domain or \
            (legitimate_domain in domain and domain != legitimate_domain):
            is_suspicious = True
            reasons.append(
                f"Sender domain '{domain}' looks suspiciously similar to '{legitimate_domain}'"
            )
            break
            
        # Only continue with more checks if no match found yet
        if not is_suspicious:
            # Calculate similarity ratio
            similarity = SequenceMatcher(None, domain, legitimate_domain).ratio()
            
            # Flag domains with very high similarity but not exact match
            if similarity > 0.8 and similarity < 1.0:
                is_suspicious = True
                reasons.append(
                    f"Sender domain '{domain}' is suspiciously similar to '{legitimate_domain}' ({int(similarity*100)}% match)"
                )
                break
            
            # Check for digit substitution (e.g., paypa1.com)
            digit_replace_pattern = re.sub(r'\d', '', domain)
            legitimate_replace_pattern = re.sub(r'\d', '', legitimate_domain)
            if digit_replace_pattern == legitimate_replace_pattern and domain != legitimate_domain:
                is_suspicious = True
                reasons.append(
                    f"Sender domain '{domain}' uses number substitution to imitate '{legitimate_domain}'"
                )
                break
            
            # Check using Levenshtein distance for close matches
            if len(legitimate_domain) > 5:
                lev_distance = levenshtein_distance(domain, legitimate_domain)
                max_allowed_distance = max(1, len(legitimate_domain) // 10)
                
                if 0 < lev_distance <= max_allowed_distance:
                    is_suspicious = True
                    reasons.append(
                        f"Sender domain '{domain}' differs from '{legitimate_domain}' by only {lev_distance} character(s)"
                    )
                    break
    
    return is_suspicious, reasons


def check_spoofed_sender(email_parts: Dict) -> Dict:
    """
    Check for signs of spoofed sender address using multiple detection techniques.
    
    Args:
        email_parts: Dictionary with parsed email components
        
    Returns:
        Dictionary with spoofing analysis results
    """
    sender_email = email_parts.get('sender_email', '')
    sender_display = email_parts.get('sender', '')
    
    result = {
        'is_spoofed': False,
        'reasons': []
    }
    
    # If no sender email found, that's immediately suspicious
    if not sender_email:
        result['is_spoofed'] = True
        result['reasons'].append("No valid sender email address found")
        return result
    
    # Extract domain from sender email
    domain_match = re.search(r'@([^@]+)$', sender_email)
    if domain_match:
        domain = domain_match.group(1).lower()
        is_suspicious, reasons = find_suspicious_domain_matches(domain)
        
        if is_suspicious:
            result['is_spoofed'] = True
            result['reasons'].extend(reasons)
    
    # Check for mismatch between display name and email domain
    if not result['is_spoofed']:  # Only check if not already flagged
        for business_domain in COMMON_DOMAINS:
            business_name = business_domain.split('.')[0].lower()
            
            # If display name contains business name but email isn't from that domain
            if business_name in sender_display.lower() and not sender_email.lower().endswith('@' + business_domain):
                result['is_spoofed'] = True
                result['reasons'].append(
                    f"Display name contains '{business_name}' but email is not from {business_domain}"
                )
                break
    
    return result


def check_language_patterns(content: str, patterns: List[str]) -> List[str]:
    """
    Check text content for specific language patterns.
    
    Args:
        content: Text to analyze
        patterns: List of patterns to look for
        
    Returns:
        List of matched patterns
    """
    return [pattern for pattern in patterns if pattern in content]


def check_urgent_language(email_parts: Dict) -> Dict:
    """
    Check for urgent or threatening language in email content.
    
    Args:
        email_parts: Dictionary with parsed email components
        
    Returns:
        Dictionary with urgent language analysis results
    """
    subject = email_parts.get('subject', '').lower()
    body = email_parts.get('body', '').lower()
    content = subject + " " + body
    
    # Check for different types of patterns
    found_urgency = check_language_patterns(content, URGENCY_PATTERNS)
    found_threats = check_language_patterns(content, THREAT_PATTERNS)
    found_rewards = check_language_patterns(content, REWARD_PATTERNS)
    
    return {
        'has_urgent_language': bool(found_urgency or found_threats),
        'has_reward_language': bool(found_rewards),
        'urgency_phrases': found_urgency,
        'threat_phrases': found_threats,
        'reward_phrases': found_rewards
    }


def check_attachment_risks(email_parts: Dict) -> Dict:
    """
    Analyze email attachments for potential risks.
    
    Args:
        email_parts: Dictionary with parsed email components
        
    Returns:
        Dictionary with attachment analysis results
    """
    content = email_parts.get('full_content', '')
    attachments = email_parts.get('attachments', [])
    
    result = {
        'has_risky_attachments': False,
        'attachment_risks': []
    }
    
    # Process attachments
    for attachment in attachments:
        if not attachment:
            continue
            
        # Get file extension
        ext = attachment.split('.')[-1].lower() if '.' in attachment else ''
        
        # Check for directly executable files
        if ext in RISKY_EXTENSIONS:
            result['has_risky_attachments'] = True
            result['attachment_risks'].append(
                f"Dangerous file type: {attachment} - Could contain malware"
            )
        
        # Check for compressed files
        elif ext in COMPRESSED_EXTENSIONS:
            result['has_risky_attachments'] = True
            result['attachment_risks'].append(
                f"Compressed file: {attachment} - May contain hidden malicious files"
            )
                
    # Check for double extensions (e.g., document.pdf.exe)
    double_extension_pattern = r'[^/\\]*\.[^/\\.]+\.(exe|js|vbs|bat|cmd|msi|ps1)'
    double_extensions = re.findall(double_extension_pattern, content, re.IGNORECASE)
    
    if double_extensions:
        result['has_risky_attachments'] = True
        result['attachment_risks'].append(
            f"Detected potential double extension (e.g., file.pdf.exe) - Common phishing tactic"
        )
    
    return result


def calculate_phishing_score(analysis_components: Dict) -> Tuple[int, List[str], str]:
    """
    Calculate phishing score and generate phishing indicators.
    
    Args:
        analysis_components: Dictionary with all analysis results
        
    Returns:
        Tuple of (phishing_score, phishing_indicators, phishing_likelihood)
    """
    phishing_score = 0
    phishing_indicators = []
    
    # Unpack analysis components
    suspicious_links = analysis_components['suspicious_links']
    url_reputation = analysis_components['url_reputation']
    spoofed_sender = analysis_components['spoofed_sender']
    urgent_language = analysis_components['urgent_language']
    attachment_risks = analysis_components['attachment_risks']
    
    # Score based on suspicious links (max 40 points)
    if suspicious_links:
        phishing_score += min(40, len(suspicious_links) * 8)
        phishing_indicators.append(f"Found {len(suspicious_links)} suspicious link(s)")
    
    # Score based on URL reputation (max 45 points)
    malicious_urls = [url for url, result in url_reputation.items() if result['is_malicious']]
    if malicious_urls:
        high_confidence_urls = [url for url in malicious_urls 
                              if url_reputation[url]['confidence'] == 'HIGH']
        
        if high_confidence_urls:
            phishing_score += min(45, len(high_confidence_urls) * 22)
            phishing_indicators.append(
                f"Found {len(high_confidence_urls)} URL(s) flagged as malicious by reputation services"
            )
        else:
            phishing_score += min(30, len(malicious_urls) * 15)
            phishing_indicators.append(
                f"Found {len(malicious_urls)} URL(s) flagged as suspicious by reputation services"
            )
    
    # Score based on spoofed sender (45 points)
    if spoofed_sender['is_spoofed']:
        phishing_score += 45
        phishing_indicators.extend(spoofed_sender['reasons'])
    
    # Score based on urgent language (max 40 points total)
    if urgent_language['has_urgent_language'] or urgent_language['has_reward_language']:
        # Process urgency phrases
        urgency_count = len(urgent_language['urgency_phrases'])
        if urgency_count > 0:
            phishing_score += min(20, urgency_count * 4)
            phishing_indicators.append(f"Found {urgency_count} urgency phrase(s)")
        
        # Process threat phrases
        threat_count = len(urgent_language['threat_phrases'])
        if threat_count > 0:
            phishing_score += min(24, threat_count * 6)
            phishing_indicators.append(f"Found {threat_count} threatening phrase(s)")
            
        # Process reward phrases
        reward_count = len(urgent_language['reward_phrases'])
        if reward_count > 0:
            phishing_score += min(15, reward_count * 3)
            phishing_indicators.append(f"Found {reward_count} reward/enticement phrase(s)")
    
    # Score based on attachment risks (max 45 points)
    if attachment_risks['has_risky_attachments']:
        risk_count = len(attachment_risks['attachment_risks'])
        phishing_score += min(45, risk_count * 15)
        phishing_indicators.append(f"Found {risk_count} risky attachment(s)")
        phishing_indicators.extend(attachment_risks['attachment_risks'])
    
    # Cap final score at 100 and determine phishing likelihood
    phishing_score = min(100, phishing_score)
    
    # Determine likelihood category
    if phishing_score >= 75:
        phishing_likelihood = "HIGHLY LIKELY"
    elif phishing_score >= 45:
        phishing_likelihood = "LIKELY"
    elif phishing_score >= 25:
        phishing_likelihood = "SUSPICIOUS"
    else:
        phishing_likelihood = "UNLIKELY"
        
    return phishing_score, phishing_indicators, phishing_likelihood


def analyze_email(email_content: str) -> Dict:
    """
    Analyze email content for phishing indicators using enhanced checks.
    
    Args:
        email_content: Raw email content as string
        
    Returns:
        Dictionary with complete analysis results
    """
    # Parse email into components
    email_parts = parse_email(email_content)
    
    # Extract URLs from text content
    all_urls = extract_urls(email_parts['subject'] + " " + email_parts['body'])
    
    # Run all phishing indicator checks
    analysis_components = {
        'suspicious_links': check_suspicious_links(all_urls),
        'url_reputation': check_url_reputation(all_urls),
        'spoofed_sender': check_spoofed_sender(email_parts),
        'urgent_language': check_urgent_language(email_parts),
        'attachment_risks': check_attachment_risks(email_parts),
    }
    
    # Calculate phishing score and get indicators
    phishing_score, phishing_indicators, phishing_likelihood = calculate_phishing_score(analysis_components)
    
    # Return complete analysis results
    return {
        'phishing_score': phishing_score,
        'phishing_likelihood': phishing_likelihood,
        'phishing_indicators': phishing_indicators,
        'suspicious_links': analysis_components['suspicious_links'],
        'url_reputation': analysis_components['url_reputation'],
        'spoofed_sender': analysis_components['spoofed_sender'],
        'urgent_language': analysis_components['urgent_language'],
        'attachment_risks': analysis_components['attachment_risks'],
        'email_parts': email_parts
    }


def print_results(analysis: Dict) -> None:
    """
    Print formatted analysis results to the console.
    
    Args:
        analysis: Dictionary with complete analysis results
    """
    # Create visual formatting elements
    border = "=" * 70
    divider = "-" * 70
    
    # Print header
    print(border)
    print(" EMAIL PHISHING DETECTOR RESULTS ".center(70, " "))
    print(border)
    
    # Print basic email info
    print(f"From: {analysis['email_parts']['sender']}")
    print(f"Subject: {analysis['email_parts']['subject']}")
    print(divider)
    
    # Print phishing likelihood and score
    print(f"PHISHING LIKELIHOOD: {analysis['phishing_likelihood']} ({analysis['phishing_score']}/100)")
    print(divider)
    
    # Print detected indicators or indicate none found
    if analysis['phishing_indicators']:
        print("DETECTED PHISHING INDICATORS:")
        for indicator in analysis['phishing_indicators']:
            print(f"  • {indicator}")
    else:
        print("No phishing indicators detected.")
    
    print(divider)
    
    # Print suspicious links details if any found
    if analysis['suspicious_links']:
        print("SUSPICIOUS LINKS DETAILS:")
        for link in analysis['suspicious_links']:
            print(f"  • {link['url']}")
            for reason in link['reasons']:
                print(f"    - {reason}")
    
    # Print URL reputation results if any malicious found
    malicious_urls = [url for url, result in analysis['url_reputation'].items() 
                    if result['is_malicious']]
    if malicious_urls:
        print(divider)
        print("URL REPUTATION RESULTS:")
        for url in malicious_urls:
            result = analysis['url_reputation'][url]
            print(f"  • {url}")
            print(f"    - Flagged as: {result['threat_type']}")
            print(f"    - Confidence: {result['confidence']}")
            print(f"    - Source: {result['source']}")
    
    # Print spoofed sender details if detected
    if analysis['spoofed_sender']['is_spoofed']:
        print(divider)
        print("SENDER SPOOFING DETAILS:")
        for reason in analysis['spoofed_sender']['reasons']:
            print(f"  • {reason}")
    
    # Print attachment risk details if detected
    if analysis['attachment_risks']['has_risky_attachments']:
        print(divider)
        print("ATTACHMENT RISK DETAILS:")
        for risk in analysis['attachment_risks']['attachment_risks']:
            print(f"  • {risk}")
    
    # Print urgent language details if detected
    if (analysis['urgent_language']['has_urgent_language'] or 
        analysis['urgent_language']['has_reward_language']):
        print(divider)
        print("LANGUAGE ANALYSIS:")
        
        if analysis['urgent_language']['urgency_phrases']:
            print("  Urgency phrases found:")
            for phrase in analysis['urgent_language']['urgency_phrases']:
                print(f"    • '{phrase}'")
        
        if analysis['urgent_language']['threat_phrases']:
            print("  Threat phrases found:")
            for phrase in analysis['urgent_language']['threat_phrases']:
                print(f"    • '{phrase}'")
                
        if analysis['urgent_language']['reward_phrases']:
            print("  Reward/enticement phrases found:")
            for phrase in analysis['urgent_language']['reward_phrases']:
                print(f"    • '{phrase}'")
    
    print(border)
    
    # Provide security recommendations based on likelihood
    if analysis['phishing_likelihood'] in ["HIGHLY LIKELY", "LIKELY"]:
        print("⚠️  RECOMMENDATION: This email shows strong signs of being a phishing attempt.")
        print("    Do not click any links, download attachments, or respond to this email.")
        print("    If this appears to be from a service you use, contact them directly")
        print("    through their official website or phone number to verify.")
    elif analysis['phishing_likelihood'] == "SUSPICIOUS":
        print("⚠️  RECOMMENDATION: This email shows some suspicious characteristics.")
        print("    Exercise caution and verify the sender through alternate channels")
        print("    before taking any requested actions, clicking links, or opening attachments.")
    
    print(border)


def prepare_json_output(analysis: Dict) -> Dict:
    """
    Prepare analysis results for JSON output by removing non-serializable elements.
    
    Args:
        analysis: Complete analysis results
        
    Returns:
        JSON-serializable version of the analysis
    """
    serializable_analysis = {k: v for k, v in analysis.items() if k != 'email_parts'}
    serializable_analysis['email_parts'] = {
        'sender': analysis['email_parts']['sender'],
        'subject': analysis['email_parts']['subject'],
        'has_attachments': bool(analysis['email_parts'].get('attachments', []))
    }
    return serializable_analysis


def main() -> None:
    """Main function to run the phishing detector script."""
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Enhanced Email Phishing Detector')
    parser.add_argument('email_file', help='Path to the email text file to analyze')
    parser.add_argument('--detailed', action='store_true', 
                      help='Show detailed analysis information')
    parser.add_argument('--json', action='store_true',
                      help='Output results in JSON format')
    args = parser.parse_args()
    
    # Read email file content
    email_content = read_email_file(args.email_file)
    
    # Analyze email for phishing indicators
    analysis = analyze_email(email_content)
    
    # Output results based on format requested
    if args.json:
        serializable_analysis = prepare_json_output(analysis)
        print(json.dumps(serializable_analysis, indent=2))
    else:
        print_results(analysis)


if __name__ == "__main__":
    main()