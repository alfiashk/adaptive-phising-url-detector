from feature_extractor import extract_url_features

url = "https://paypal-login-security.xyz/login?id=123"

features = extract_url_features(url)

print(features)