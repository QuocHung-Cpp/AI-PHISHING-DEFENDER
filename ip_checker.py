import requests
import socket
from urllib.parse import urlparse


def get_ip_from_url(url):
    try:
        domain = urlparse(url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        # Xóa các ký tự thừa nếu có
        domain = domain.strip()
        if not domain:
            return None
        return socket.gethostbyname(domain)
    except:
        return None


def get_ip_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            if data.get('status') == 'success':
                return {
                    'ip': ip,
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'org': data.get('isp', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown')
                }
        return None
    except:
        return None


def calculate_ip_risk(geo_info):
    risk = 0
    if not geo_info:
        return risk

    # Danh sách quốc gia rủi ro cao (có thể mở rộng thêm)
    HIGH_RISK_COUNTRIES = [
        'China', 'Russia', 'Nigeria', 'North Korea',
        'Iran', 'Belarus', 'Myanmar'
    ]

    country = geo_info.get('country', '')
    if country in HIGH_RISK_COUNTRIES:
        risk += 30

    # Kiểm tra ISP/Org đáng ngờ
    org = geo_info.get('org', '').lower()
    SUSPICIOUS_ORGS = ['vpn', 'proxy', 'tor', 'hosting', 'datacenter']
    if any(keyword in org for keyword in SUSPICIOUS_ORGS):
        risk += 20

    return min(risk, 100)


def check_url_ip(url):
    """
    Hàm chính được gọi từ app.py.
    Trả về dict với đầy đủ thông tin IP + risk_score.
    """
    ip = get_ip_from_url(url)

    if not ip:
        return {
            'ip_address': None,
            'geolocation': None,
            'risk_score': 0,
            'verdict': 'Unknown'
        }

    geo = get_ip_geolocation(ip)
    risk = calculate_ip_risk(geo)

    return {
        'ip_address': ip,
        'geolocation': geo,
        'risk_score': risk,
        'verdict': 'High Risk' if risk > 50 else 'Low Risk'
    }