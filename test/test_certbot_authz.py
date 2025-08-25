#!/usr/bin/env python3
"""
测试ACME授权端点功能的脚本
用于验证certbot在签发证书时访问/authz/1端点是否正常
"""

import requests
import json
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# ACME服务器配置
ACME_SERVER = "http://localhost:5000"
CA_ID = 1

# 生成RSA密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 获取公钥
public_key = private_key.public_key()

# 将公钥序列化为JWK格式
def public_key_to_jwk(public_key):
    public_numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('='),
        "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
    }

# 生成账户指纹
def generate_thumbprint(jwk):
    thumbprint_data = {
        'e': jwk['e'],
        'kty': 'RSA',
        'n': jwk['n']
    }
    json_str = json.dumps(thumbprint_data, separators=(',', ':'), sort_keys=True)
    digest = hashlib.sha256(json_str.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

# Base64URL编码
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# 创建JWS签名
def create_jws(payload, protected_header, private_key):
    protected_b64 = base64url_encode(json.dumps(protected_header).encode())
    payload_b64 = base64url_encode(payload.encode()) if payload else ""
    
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = base64url_encode(signature)
    
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64
    }

print("测试ACME授权端点功能...")

# 1. 获取nonce
print("1. 获取nonce...")
nonce_response = requests.get(f"{ACME_SERVER}/acme/{CA_ID}/new-nonce")
nonce = nonce_response.headers.get('Replay-Nonce')
print(f"获取到nonce: {nonce}")

# 2. 创建账户
print("2. 创建ACME账户...")
jwk = public_key_to_jwk(public_key)
thumbprint = generate_thumbprint(jwk)

account_payload = json.dumps({
    "termsOfServiceAgreed": True,
    "contact": ["mailto:test@example.com"]
})

protected_header = {
    "alg": "RS256",
    "jwk": jwk,
    "nonce": nonce,
    "url": f"{ACME_SERVER}/acme/{CA_ID}/new-account"
}

jws_data = create_jws(account_payload, protected_header, private_key)

account_response = requests.post(
    f"{ACME_SERVER}/acme/{CA_ID}/new-account",
    json=jws_data,
    headers={"Content-Type": "application/jose+json"}
)

print(f"账户创建状态码: {account_response.status_code}")
print(f"账户响应: {account_response.text}")

if account_response.status_code != 201:
    print("❌ 账户创建失败")
    exit(1)

account_location = account_response.headers.get('Location')
account_id = account_location.split('/')[-1] if account_location else "unknown"
print(f"✅ 账户创建成功，账户ID: {account_id}")

# 3. 获取新的nonce用于订单创建
print("3. 获取新的nonce用于订单创建...")
nonce_response = requests.get(f"{ACME_SERVER}/acme/{CA_ID}/new-nonce")
nonce = nonce_response.headers.get('Replay-Nonce')
print(f"获取到nonce: {nonce}")

# 4. 创建新订单
print("4. 创建新订单...")
order_payload = json.dumps({
    "identifiers": [
        {"type": "dns", "value": "yuy.com"}
    ]
})

protected_header = {
    "alg": "RS256",
    "kid": f"{ACME_SERVER}/acme/{CA_ID}/account/{account_id}",
    "nonce": nonce,
    "url": f"{ACME_SERVER}/acme/{CA_ID}/new-order"
}

jws_data = create_jws(order_payload, protected_header, private_key)

order_response = requests.post(
    f"{ACME_SERVER}/acme/{CA_ID}/new-order",
    json=jws_data,
    headers={"Content-Type": "application/jose+json"}
)

print(f"订单创建状态码: {order_response.status_code}")
print(f"订单响应头: {dict(order_response.headers)}")
print(f"订单响应体: {order_response.text}")

if order_response.status_code != 201:
    print("❌ 订单创建失败")
    exit(1)

order_data = order_response.json()
authorizations = order_data.get('authorizations', [])
print(f"✅ 订单创建成功，授权URLs: {authorizations}")

# 5. 测试访问授权端点
if authorizations:
    authz_url = authorizations[0]
    print(f"5. 测试访问授权端点: {authz_url}")
    
    # 获取新的nonce用于授权查询
    nonce_response = requests.get(f"{ACME_SERVER}/acme/{CA_ID}/new-nonce")
    nonce = nonce_response.headers.get('Replay-Nonce')
    print(f"获取到nonce: {nonce}")
    
    # 构建授权查询请求
    protected_header = {
        "alg": "RS256",
        "kid": f"{ACME_SERVER}/acme/{CA_ID}/account/{account_id}",
        "nonce": nonce,
        "url": authz_url
    }
    
    jws_data = create_jws("", protected_header, private_key)
    
    authz_response = requests.post(
        authz_url,
        json=jws_data,
        headers={"Content-Type": "application/jose+json"}
    )
    
    print(f"授权查询状态码: {authz_response.status_code}")
    print(f"授权响应头: {dict(authz_response.headers)}")
    print(f"授权响应体: {authz_response.text}")
    
    if authz_response.status_code == 200:
        print("✅ 授权端点访问成功！")
        authz_data = authz_response.json()
        print(f"授权状态: {authz_data.get('status')}")
        print(f"域名: {authz_data.get('identifier', {}).get('value')}")
        print(f"挑战数量: {len(authz_data.get('challenges', []))}")
    else:
        print("❌ 授权端点访问失败")
        exit(1)
else:
    print("❌ 订单响应中没有授权URL")
    exit(1)

print("✅ 所有测试通过！ACME授权端点功能正常")