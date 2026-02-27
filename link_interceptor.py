<details>
<summary><b>📄 Code đơn giản link_interceptor.py</b></summary>
```python
import pyperclip
import time
import re
import requests
from tkinter import messagebox
import tkinter as tk
API_URL = "http://localhost:5000/api/scan"
def is_url(text):
return re.match(r'^https?://', text.strip()) is not None
def scan_url(url):
try:
res = requests.post(API_URL, json={'url': url}, timeout=10)
return res.json() if res.status_code == 200 else None
except:
return None
def show_popup(url, result):
root = tk.Tk()
root.withdraw()
if result and result.get('success'):
    score = result['threat_score']
    verdict = result['verdict_text']
    msg = f"URL: {url}\n\nĐiểm: {score}/100\nĐánh giá: {verdict}\n\nMở link?"
    
    answer = messagebox.askyesno("🛡️ AI Phishing Defender", msg)
    root.destroy()
    return answer

root.destroy()
return False
def monitor_clipboard():
print("📋 Đang giám sát clipboard...")
print("Copy link để kiểm tra. Ctrl+C để dừng.\n")
recent = ""
try:
    while True:
        current = pyperclip.paste()
        if current != recent and is_url(current):
            recent = current
            print(f"\n🔗 Phát hiện: {current}")
            result = scan_url(current)
            show_popup(current, result)
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\n⏹️ Dừng giám sát")
if name == "main":
monitor_clipboard()

</details>