from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
from urllib.parse import urlparse
import requests
import socket
import ssl
from ip_checker import check_url_ip
from datetime import datetime
import anthropic
import json

app = Flask(__name__)
CORS(app)

# ========== CẤU HÌNH ==========
import os
CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY", "")

try:
    claude_client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
except:
    claude_client = None

# ========== HÀM PHỤ TRỢ ==========
# Domain uy tín cao - luôn an toàn
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'github.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com',
    'stackoverflow.com', 'reddit.com', 'yahoo.com', 'bing.com',
    'office.com', 'live.com', 'outlook.com', 'dropbox.com',
    'paypal.com', 'ebay.com', 'adobe.com', 'cloudflare.com',
    # Việt Nam
    'vietcombank.com.vn', 'techcombank.com.vn', 'vpbank.com.vn',
    'agribank.com.vn', 'bidv.com.vn', 'vietinbank.vn',
    'vnexpress.net', 'tuoitre.vn', 'thanhnien.vn', 'dantri.com.vn',
    'baidu.com', 'zalo.me', 'tiki.vn', 'shopee.vn', 'lazada.vn'
]

def extract_url_features(url):
    features = {}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()

        # Kiểm tra domain gốc (bỏ www.)
        base_domain = domain.replace('www.', '')

        # --- Thông tin cơ bản ---
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['has_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0

        # --- Domain có uy tín không? ---
        features['is_trusted'] = 1 if any(base_domain == t or base_domain.endswith('.' + t) for t in TRUSTED_DOMAINS) else 0

        # --- TLD đáng ngờ (mở rộng) ---
        SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                           '.click', '.loan', '.win', '.download', '.stream',
                           '.racing', '.review', '.trade', '.party', '.men']
        features['suspicious_tld'] = 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0

        # --- URL Shortener ---
        SHORTENERS = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly',
                      'short.link', 'cutt.ly', 'rb.gy', 'is.gd']
        features['is_shortener'] = 1 if any(s in domain for s in SHORTENERS) else 0

        # --- Từ khóa nhạy cảm trong URL ---
        PHISHING_KEYWORDS = [
            'login', 'verify', 'account', 'secure', 'update', 'confirm',
            'banking', 'password', 'signin', 'wallet', 'paypal', 'ebay',
            'apple', 'microsoft', 'amazon', 'support', 'service',
            'suspended', 'locked', 'unusual', 'activity', 'invoice',
            'reset', 'credential', 'authenticate', 'validation'
        ]
        features['suspicious_keywords'] = sum(1 for k in PHISHING_KEYWORDS if k in full_url)

        # --- Dấu hiệu giả mạo domain (typosquatting) ---
        BRAND_NAMES = ['paypal', 'google', 'facebook', 'microsoft', 'apple',
                       'amazon', 'netflix', 'instagram', 'twitter', 'vietcombank']
        features['brand_in_domain'] = 1 if any(b in domain and not domain.endswith(b + '.com') and not domain.endswith(b + '.com.vn') for b in BRAND_NAMES) else 0

        # --- Subdomain nhiều cấp (vd: secure.login.paypal.fake.com) ---
        subdomain_count = len(domain.split('.')) - 2
        features['deep_subdomain'] = 1 if subdomain_count >= 3 else 0

        # --- Ký tự lạ trong domain ---
        features['has_hyphen_abuse'] = 1 if domain.count('-') >= 3 else 0
        features['has_numbers_in_domain'] = 1 if re.search(r'\d', domain.split('.')[0]) else 0

        # --- Path dài/phức tạp ---
        features['long_path'] = 1 if len(path) > 50 else 0
        features['many_params'] = 1 if full_url.count('=') >= 3 else 0

        # --- Giả mạo HTTPS (có chữ secure/ssl nhưng không phải HTTPS) ---
        features['fake_secure'] = 1 if ('secure' in domain or 'ssl' in domain or 'safe' in domain) and parsed.scheme != 'https' else 0

        return features
    except:
        return None

def check_ssl_certificate(domain):
    try:
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {'has_ssl': True, 'issuer': 'Valid'}
    except:
        return {'has_ssl': False}

def analyze_with_claude(url, features):
    if not claude_client:
        return {
            "verdict": "UNKNOWN",
            "reason": "API chưa cấu hình",
            "recommendation": "Hãy cẩn thận"
        }
    try:
        prompt = f"""Phân tích URL: {url}
HTTPS: {'Có' if features.get('has_https') else 'Không'}
Có IP: {'Có' if features.get('has_ip') else 'Không'}
Trả JSON:
{{"verdict": "AN_TOÀN/NGHI_NGỜ/NGUY_HIỂM", "reason": "...", "recommendation": "..."}}"""

        message = claude_client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        text = message.content[0].text.strip().replace('```json', '').replace('```', '')
        return json.loads(text)
    except Exception as e:
        err = str(e)
        if 'credit' in err.lower() or 'balance' in err.lower():
            reason = "API AI tạm thời không khả dụng (hết credits)."
        elif 'api' in err.lower() or 'auth' in err.lower():
            reason = "Không thể kết nối AI. Kiểm tra lại API key."
        else:
            reason = "AI không thể phân tích URL này lúc này."
        return {"verdict": "UNKNOWN", "reason": reason, "recommendation": "Cẩn thận"}

def calculate_threat_score(features, ssl_info, claude_analysis, ip_check):
    score = 0

    # Nếu là domain uy tín → giảm mạnh điểm ngay từ đầu
    if features.get('is_trusted'):
        base_reduction = -20
        score += base_reduction

    # --- IP & Geolocation ---
    score += ip_check.get('risk_score', 0) * 0.3

    # --- URL Structure ---
    if features.get('url_length', 0) > 75:  score += 10
    if features.get('url_length', 0) > 100: score += 10  # Rất dài → thêm điểm
    if features.get('has_ip'):              score += 20
    if features.get('long_path'):           score += 8
    if features.get('many_params'):         score += 8
    if features.get('deep_subdomain'):      score += 15
    if features.get('has_hyphen_abuse'):    score += 12
    if features.get('has_numbers_in_domain'): score += 5

    # --- Domain nguy hiểm ---
    if features.get('suspicious_tld'):      score += 20
    if features.get('is_shortener'):        score += 15
    if features.get('brand_in_domain'):     score += 25  # Giả mạo thương hiệu = rất nguy hiểm
    if features.get('fake_secure'):         score += 15

    # --- HTTPS & SSL ---
    if not features.get('has_https'):       score += 15
    if not ssl_info.get('has_ssl'):         score += 20

    # --- Keywords ---
    kw = features.get('suspicious_keywords', 0)
    if kw == 1:   score += 10
    elif kw == 2: score += 20
    elif kw >= 3: score += 30  # Nhiều keyword phishing = rất nguy hiểm

    # --- AI Analysis ---
    verdict = claude_analysis.get('verdict', '')
    if verdict == 'NGUY_HIỂM':   score += 25
    elif verdict == 'NGHI_NGỜ':  score += 12

    return max(0, min(int(score), 100))

# ========== API ENDPOINTS ==========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'URL trống'}), 400

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        print(f"\n🔍 Quét: {url}")

        features = extract_url_features(url)
        if not features:
            return jsonify({'error': 'Lỗi phân tích URL'}), 400

        ssl_info = check_ssl_certificate(urlparse(url).netloc)
        claude_analysis = analyze_with_claude(url, features)
        ip_check = check_url_ip(url)
        threat_score = calculate_threat_score(features, ssl_info, claude_analysis, ip_check)

        if threat_score >= 70:
            verdict_text = 'Nguy hiểm'
            verdict_color = 'red'
        elif threat_score >= 40:
            verdict_text = 'Nghi ngờ'
            verdict_color = 'orange'
        else:
            verdict_text = 'An toàn'
            verdict_color = 'green'

        print(f"✅ Điểm: {threat_score}/100")

        return jsonify({
            'success': True,
            'url': url,
            'verdict_text': verdict_text,
            'verdict_color': verdict_color,
            'threat_score': int(threat_score),
            'timestamp': datetime.now().isoformat(),
            'analysis': {
                'features': features,
                'ssl': ssl_info,
                'ai_analysis': claude_analysis,
                'ip_check': ip_check
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health():
    return jsonify({'status': 'OK'})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)