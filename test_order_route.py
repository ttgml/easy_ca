#!/usr/bin/env python3
"""测试ACME订单路由修复"""

import requests
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# 测试URL
base_url = "http://localhost:5000"
new_nonce_url = f"{base_url}/acme/1/new-nonce"

# 使用之前测试创建的账户
account_id = 27
account_kid = f"{base_url}/acme/1/account/{account_id}"

# 首先获取一个有效的nonce
print("获取nonce...")
nonce_response = requests.head(new_nonce_url)
if 'Replay-Nonce' not in nonce_response.headers:
    print("❌ ERROR: 无法获取nonce")
    exit(1)

nonce = nonce_response.headers['Replay-Nonce']
print(f"获取到nonce: {nonce}")

# 测试订单信息获取（POST /acme/1/order/33）
order_id = 33  # 假设的订单ID
order_url = f"{base_url}/acme/1/order/{order_id}"

# 创建一个简单的JWS请求
protected_header = {
    "alg": "RS256",
    "kid": account_kid,
    "nonce": nonce,
    "url": order_url
}

# 空payload用于GET类型的请求
payload = {}

# 编码protected header和payload
protected_b64 = base64.urlsafe_b64encode(json.dumps(protected_header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# 构建JWS请求（使用空签名，因为这是测试）
jws_data = {
    "protected": protected_b64,
    "payload": payload_b64,
    "signature": "test_signature"  # 简化测试
}

# 发送请求
headers = {
    "Content-Type": "application/jose+json"
}

print(f"发送ACME订单信息请求到: {order_url}")
response = requests.post(order_url, headers=headers, json=jws_data)

print(f"状态码: {response.status_code}")
print(f"响应头: {dict(response.headers)}")
print(f"响应体: {response.text}")

# 检查是否包含Replay-Nonce头
if 'Replay-Nonce' in response.headers:
    print("✅ SUCCESS: Replay-Nonce头存在")
else:
    print("❌ ERROR: Replay-Nonce头不存在")

# 检查响应状态码
if response.status_code == 200:
    print("✅ SUCCESS: 订单信息获取成功")
elif response.status_code == 404:
    print("❌ ERROR: 订单不存在（404错误）")
else:
    print(f"❌ ERROR: 订单信息获取失败，状态码: {response.status_code}")