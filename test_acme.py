import requests
import json

# 发送一个简单的POST请求到new-account端点
url = "http://127.0.0.1:5000/acme/4/new-account"
headers = {
    "Content-Type": "application/jose+json"
}

# 一个最小的JWS结构
payload = {
    "protected": "eyJhbGciOiAiUlMyNTYiLCAiandrIjogeyJrdHkiOiAiUlNBIiwgImUiOiAiQVFBQiIsICJuIjogInRlc3QifX0",
    "payload": "",
    "signature": ""
}

response = requests.post(url, headers=headers, data=json.dumps(payload))

print(f"Status Code: {response.status_code}")
print(f"Headers: {dict(response.headers)}")
print(f"Response Body: {response.text}")

# 检查是否包含Replay-Nonce头
if 'Replay-Nonce' in response.headers:
    print("SUCCESS: Replay-Nonce header is present")
else:
    print("ERROR: Replay-Nonce header is missing")