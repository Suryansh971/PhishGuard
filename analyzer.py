from urllib.parse import urlparse
import ipaddress
import re


def analyze_url(url):
    score = 0
    red_flags = []

    # 1. Check if URL has a valid scheme
    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"] or not parsed.netloc:
        return {
            "score": 100,
            "risk_level": "Invalid URL",
            "red_flags": ["The entered URL is not valid"]
        }

    hostname = parsed.hostname

    # 2. Check HTTPS
    if parsed.scheme != "https":
        score += 15
        red_flags.append("URL does not use HTTPS")

    # 3. Check if IP address is used
    try:
        ipaddress.ip_address(hostname)
        score += 25
        red_flags.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    # 4. Check @ symbol
    if "@" in url:
        score += 20
        red_flags.append("URL contains '@' character")

    # 5. Check URL length
    if len(url) > 100:
        score += 10
        red_flags.append("URL is unusually long")

    # 6. Check excessive subdomains
    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        is_ip_address = False

    if not is_ip_address and hostname and hostname.count(".") >= 3:
        score += 10
        red_flags.append("URL contains an unusually high number of subdomains")

    # 7. Check suspicious words
    suspicious_keywords = [
        "verify",
        "password",
        "account",
        "update",
        "secure",
        "bank",
        "signin"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            found_keywords.append(keyword)

    if found_keywords:
        score += 10
        red_flags.append(
            "Suspicious keyword(s): " + ", ".join(found_keywords)
        )

    # 8. Check for suspicious characters
    if re.search(r"[%]{2,}|-{3,}|_{3,}", url):
        score += 10
        red_flags.append("URL contains unusual character patterns")

    # Keep score between 0 and 100
    score = min(score, 100)

    # Risk level
    if score >= 60:
        risk_level = "High Risk"
    elif score >= 30:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return {
        "score": score,
        "risk_level": risk_level,
        "red_flags": red_flags
    }

def calculate_final_score(local_score, vt_stats):
    malicious = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)

    # VirusTotal risk contribution
    if malicious >= 5:
        vt_score = 100
    elif malicious >= 3:
        vt_score = 80
    elif malicious >= 1:
        vt_score = 50
    elif suspicious >= 5:
        vt_score = 40
    elif suspicious >= 1:
        vt_score = 25
    else:
        vt_score = 0

    # Combine local analysis and VirusTotal
    final_score = round(
        (local_score * 0.7) + (vt_score * 0.3)
    )

    final_score = min(final_score, 100)

    if final_score >= 60:
        risk_level = "High Risk"
    elif final_score >= 25:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return final_score, risk_level