from backend.predict import predict_url

TEST_CASES = {
    "https://www.google.com": "safe",
    "https://google.com": "safe",
    "https://www.paypal.com/signin": "safe",
    "https://amazon.com": "safe",
    "https://www.amazon.com": "safe",
    "https://www.microsoft.com": "safe",
    "https://www.wikipedia.org": "safe",
    "https://paypal-login-security.xyz/login": "phishing",
    "https://prize-winner.com": "phishing",
    "http://free-prize-claim.top/winner": "phishing",
    "http://192.168.1.1/verify-account": "phishing",
    "http://secure-update-account.tk/login?user=1&token=abc": "phishing",
    "https://paypal.com.evil.test/login": "phishing",
}

for url, expected_label in TEST_CASES.items():
    result = predict_url(url)
    print(f"{url}")
    print(f"  -> {result['label']} (pred={result['prediction']}, conf={result['confidence']})")
    assert result["label"] == expected_label, f"{url}: expected {expected_label}"