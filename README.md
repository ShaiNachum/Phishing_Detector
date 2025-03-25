# Email Phishing Detector

***Main Page***

![Screenshot 2025-03-24 101000](https://github.com/user-attachments/assets/442377a1-0096-42e3-ad54-90fcc5bdf057)

***Result Page***

![Screenshot 2025-03-24 101316](https://github.com/user-attachments/assets/d8a171f5-26f1-4e59-a267-a656df202517)


## Overview
The Email Phishing Detector is a sophisticated security tool designed to analyze email content and identify potential phishing attempts. This tool employs multiple detection mechanisms to identify suspicious emails before they can cause harm.

## Features

- **Comprehensive Analysis**: Examines multiple aspects of an email to detect phishing indicators.
- **Scoring System**: Provides a quantitative assessment of phishing likelihood (0-100 scale).
- **Web Interface**: Intuitive UI for uploading and analyzing emails.
- **Detailed Reports**: Comprehensive breakdown of detected phishing indicators.
- **Modular Design**: Can be used as a standalone script or integrated into larger systems.
- **Enhanced Security**: Uses environment variables for API keys and improved error handling.
- **Optimized Performance**: Reduced redundancy and better caching for faster analysis.

## Key Phishing Detection Mechanisms

### 1. URL Analysis
Phishing emails often contain malicious links designed to steal credentials or deliver malware.

#### Suspicious Link Detection (`check_suspicious_links`)
This function examines URLs for common phishing patterns:

| Check | Description | Why It Matters |
|-------|-------------|----------------|
| **IP Address URLs** | Detects raw IP addresses in links (e.g., http://13.54.126.73/login) | Legitimate organizations use domain names, not raw IPs. Attackers use IPs to hide the actual destination and avoid domain reputation checks. |
| **Suspicious TLDs** | Identifies uncommon or free top-level domains (.tk, .ml, .ga, etc.) | Attackers often use free domains from these TLDs because they require minimal verification to register. |
| **Phishing Keywords** | Identifies security-related keywords like "secure", "login", "verify" | Attackers commonly use these terms to create a false sense of legitimacy or urgency. |
| **URL Length** | Flags unusually long URLs (over 100 characters) | Excessively long URLs can hide suspicious parameters or be used to confuse users about the actual destination. |
| **Redirection Parameters** | Detects URLs with redirection indicators (redirect=, url=, link=) | Redirects can mask the final malicious destination by passing through legitimate domains first. |
| **Encoded Characters** | Identifies obfuscated URLs using percent-encoding | Encoding can disguise malicious URLs to bypass detection or confuse users. |
| **Excessive Subdomains** | Flags domains with many subdomains (e.g., secure.login.account.example.com) | Multiple subdomains can confuse users and mimic legitimate paths while actually being on a different domain. |

```python
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
```

#### URL Reputation Checking (`check_url_reputation`)
Checks URLs against known threat databases:

| Feature | Description | Why It Matters |
|---------|-------------|----------------|
| **Safe Browsing API Integration** | Queries Google's Safe Browsing database | Leverages Google's continuously updated database of known malicious sites. |
| **Threat Classification** | Categorizes threats (MALWARE, PHISHING, UNWANTED, HARMFUL) | Different threat types require different responses and remediation approaches. |
| **Confidence Rating** | Indicates certainty level of the threat assessment | Higher confidence ratings warrant more immediate action. |
| **Improved Caching System** | Stores reputation results for 7 days with better error handling | Improves performance, reduces API calls, and enhances reliability. |

```python
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

```

### 2. Sender Authentication (`check_spoofed_sender`)
Analyzes sender information to detect impersonation attempts:

| Check | Description | Why It Matters |
|-------|-------------|----------------|
| **Domain Similarity Analysis** | Checks for slight variations of legitimate domains | Detects typosquatting (e.g., "micr0soft.com" instead of "microsoft.com"). |
| **Character Substitution** | Identifies domains with number/symbol replacements | Catches subtle changes like "paypa1.com" vs "paypal.com" where "l" is replaced with "1". |
| **Levenshtein Distance** | Calculates edit distance between domains | Quantifies how many character changes separate a suspicious domain from a legitimate one. |
| **Display Name/Email Mismatch** | Compares sender name against email domain | Catches cases where the display name says "PayPal Support" but the email is from an unrelated domain. |
| **Common Target Check** | Checks against list of frequently impersonated companies | Provides extra scrutiny for emails claiming to be from high-value targets like banks, payment processors, and major tech companies. |

```python
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
```

### 3. Content Analysis (`check_urgent_language`)
Examines email content for psychological manipulation tactics:

| Check | Description | Why It Matters |
|-------|-------------|----------------|
| **Urgency Patterns** | Identifies language creating time pressure (40+ patterns) | Attackers rush users to prevent careful consideration of suspicious elements. |
| **Threat Detection** | Finds threatening language and consequences (25+ patterns) | Fear tactics pressure users into taking action without verification. |
| **Reward/Enticement Analysis** | Recognizes promises of rewards or benefits (20+ patterns) | Exploits desire for free items or financial gain to override security concerns. |
| **Context-Aware Matching** | Examines both subject and body text | Ensures comprehensive analysis of all text parts where manipulation might occur. |

Examples of detected phrases:
- Urgency: "urgent", "immediately", "24 hours", "account suspended", "security alert"
- Threats: "will be terminated", "legal action", "funds will be withdrawn", "permanently disabled"
- Enticements: "free gift", "selected winner", "exclusive offer", "claim your prize"

```python
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
```

### 4. Attachment Security (`check_attachment_risks`)
Scans for potentially dangerous file attachments:

| Check | Description | Why It Matters |
|-------|-------------|----------------|
| **Executable File Detection** | Identifies dangerous file types (.exe, .bat, .js, etc.) | These files can execute malicious code directly when opened. |
| **Double Extension Analysis** | Detects disguised executables (document.pdf.exe) | This trick makes malicious files appear legitimate by showing only the first extension in some email clients. |
| **Compressed File Scanning** | Flags archive files (.zip, .rar, etc.) | Archives can contain and hide malicious files that would otherwise be detected. |
| **Script File Detection** | Identifies script files that can execute code (.ps1, .vbs) | Script files can provide attackers with system access and command execution capabilities. |

```python
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
```

### 5. Holistic Scoring System
Integrates findings into a comprehensive risk assessment:

| Component | Weight | Description | Why This Weighting |
|-----------|--------|-------------|-------------------|
| Suspicious Links | Max 40 points | 8 points per suspicious link | Links are primary attack vectors but need other signals for confirmation. |
| Malicious URLs | Max 45 points | 22 points per high-confidence malicious URL | Confirmed malicious URLs are very strong indicators of phishing. |
| Spoofed Sender | 45 points | Flat score for detected spoofing | Sender impersonation strongly indicates malicious intent. |
| Urgent Language | Max 20 points | 4 points per urgency phrase | Creates suspicion but needs corroboration from other indicators. |
| Threat Language | Max 24 points | 6 points per threat phrase | Threatening language is a stronger manipulation tactic than simple urgency. |
| Reward Language | Max 15 points | 3 points per reward phrase | Enticement tactics are common but not as reliable an indicator alone. |
| Risky Attachments | Max 45 points | 15 points per risky attachment | Malicious attachments are a serious threat vector comparable to spoofed senders. |

**Phishing Likelihood Classification**:
- **HIGHLY LIKELY**: Score 75-100 - Multiple strong indicators present
- **LIKELY**: Score 45-74 - Several moderate indicators or one strong indicator
- **SUSPICIOUS**: Score 25-44 - Some indicators present but not conclusive
- **UNLIKELY**: Score 0-24 - Few or no phishing indicators detected

## Technical Implementation

### Core Components

1. **Email Parser (`parse_email`)**: Extracts and organizes essential components from raw email content:
   - Sender information (including display name and email address)
   - Subject line
   - Email body
   - Attachment details
   - Full headers for deeper analysis

```python
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
```

2. **URL Extractor (`extract_urls`)**: Identifies and normalizes all URLs within the email using comprehensive regex patterns that catch various URL formats including those without protocols.

```python
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
```

3. **Analysis Engine (`analyze_email`)**: Coordinates the various detection mechanisms and aggregates results into a weighted score.

```python
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
```

4. **Scoring Calculator (`calculate_phishing_score`)**: Separated component that handles the weighted analysis of all phishing indicators.

5. **Reporting System (`print_results`)**: Generates human-readable reports of analysis findings with actionable security recommendations.

6. **Web Interface (`app.py`)**: Provides a user-friendly interface with tabbed results displaying different aspects of the analysis.


## Usage

### Command Line Interface
```bash
python phishing_detector.py email_file.txt
```

For detailed analysis output:
```bash
python phishing_detector.py email_file.txt --detailed
```

For JSON format output (useful for integration with other tools):
```bash
python phishing_detector.py email_file.txt --json
```

### Web Interface
```bash
python app.py
```
Then open your browser and navigate to http://127.0.0.1:5000

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Google Safe Browsing API for URL reputation checking

---

*This tool is designed to aid in phishing detection but should be used as part of a comprehensive security strategy. No detection method is 100% effective against all phishing attempts.*
