import re
import math
from urllib.parse import urlparse

import tldextract

# lookup table seeing which Top level domain (TLD) are more likely to be legitimate based on
#  common usage and reputation.   
_LEGIT_TLD_PROBS = {
    "com": 0.55, "org": 0.60, "net": 0.50, "edu": 0.85, "gov": 0.90,
    "mil": 0.88, "int": 0.80, "io": 0.55, "co": 0.55, "us": 0.60,
    "uk": 0.62, "de": 0.62, "fr": 0.60, "jp": 0.60, "ca": 0.60,
    "au": 0.58, "in": 0.50, "info": 0.35, "biz": 0.35, "xyz": 0.15,
    "top": 0.10, "club": 0.20, "online": 0.20, "site": 0.20,
    "tk": 0.08, "ml": 0.08, "ga": 0.08, "cf": 0.08, "gq": 0.08,
    "zip": 0.10, "mov": 0.10, "country": 0.15, "stream": 0.15,
}

# Measures randomness / unpredictability of the characters in the string.
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

# Detects if the hostname is an IPv4 or IPv6 address.
# Why it matters: Using a raw IP as a domain is a common phishing trick to hide the real host.
def _is_ip(host: str) -> int:
    if not host:
        return 0
    m = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.    (\d{1,3})", host)
    if m and all(0 <= int(g) <= 255 for g in m.groups()):
        return 1
    if ":" in host and re.fullmatch(r"[0-9a-fA-F:]+", host):
        return 1
    return 0

# Measures how often adjacent characters are of the same type (letter-letter or digit-digit).
def _char_continuation_rate(url: str) -> float:
    if len(url) < 2:
        return 0.0
    same = 0
    for a, b in zip(url, url[1:]):
        if a.isalpha() and b.isalpha():
            same += 1
        elif a.isdigit() and b.isdigit():
            same += 1
    return same / (len(url) - 1)

# Produces a 0–100 "looks like a normal URL" score.
def _similarity_index(url: str) -> float:
    if not url:
        return 0.0
    e = _entropy(url)
    length_penalty = min(len(url), 200) / 2.0
    score = 100.0 - (e * 8.0) - (length_penalty * 0.15)
    return max(0.0, min(100.0, score))

# makes url harder to understand 
_OBFUSCATION_CHARS = set("%@!$^*()+=[]{};'\",<>\\|`~")


def extract_url_features(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host_no_port = (parsed.hostname or "").lower()
    analysis_url = url
    feature_host = host_no_port
    if host_no_port and not host_no_port.startswith("www.") and not _is_ip(host_no_port):
        port = f":{parsed.port}" if parsed.port else ""
        analysis_url = parsed._replace(netloc=f"www.{host_no_port}{port}").geturl()
        feature_host = f"www.{host_no_port}"

# tldextract.extract returns a ExtractResult(subdomain, domain, suffix).
    ext = tldextract.extract(analysis_url)
    tld = ext.suffix.lower() or ""
    tld_len = len(tld)
    tld_prob = _LEGIT_TLD_PROBS.get(tld, 0.30 if tld else 0.0)
    subdomains = [part for part in (ext.subdomain or "").split(".") if part and part != "www"]

    letters = sum(c.isalpha() for c in analysis_url)
    digits = sum(c.isdigit() for c in analysis_url)
    special_chars = [c for c in analysis_url if not c.isalnum() and c not in ":/?&=.-_"]
    obf_chars = [c for c in analysis_url if c in _OBFUSCATION_CHARS]

    length = max(len(analysis_url), 1)

    return {
        "URLLength": len(analysis_url),
        "DomainLength": len(feature_host),
        "IsDomainIP": _is_ip(host_no_port),
        "URLSimilarityIndex": round(_similarity_index(analysis_url), 4),
        "CharContinuationRate": round(_char_continuation_rate(analysis_url), 4),
        "TLDLegitimateProb": round(tld_prob, 4),
        "URLCharProb": round(_entropy(analysis_url) / 6.0, 4),
        "TLDLength": tld_len,
        "NoOfSubDomain": len(subdomains),
        "HasObfuscation": 1 if obf_chars else 0,
        "NoOfObfuscatedChar": len(obf_chars),
        "ObfuscationRatio": round(len(obf_chars) / length, 4),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": round(letters / length, 4),
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": round(digits / length, 4),
        "NoOfEqualsInURL": analysis_url.count("="),
        "NoOfQMarkInURL": analysis_url.count("?"),
        "NoOfAmpersandInURL": analysis_url.count("&"),
        "NoOfOtherSpecialCharsInURL": len(special_chars),
        "SpacialCharRatioInURL": round(len(special_chars) / length, 4),
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
    }