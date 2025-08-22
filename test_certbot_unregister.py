#!/usr/bin/env python3
"""
测试certbot注销账户功能
"""

import requests
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def test_certbot_unregister():
    """测试certbot注销账户功能"""
    
    base_url = "http://localhost:5000"
    new_account_url = f"{base_url}/acme/1/new-account"
    new_nonce_url = f"{base_url}/acme/1/new-nonce"
    
    # 创建一个RSA密钥对用于测试
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 获取公钥信息用于JWK
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    # 构建JWK
    jwk = {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode().rstrip('='),
        "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode().rstrip('=')
    }
    
    # 1. 获取nonce
    print("获取nonce...")
    nonce_response = requests.head(new_nonce_url)
    if 'Replay-Nonce' not in nonce_response.headers:
        print("❌ ERROR: 无法获取nonce")
        return False
    
    nonce = nonce_response.headers['Replay-Nonce']
    print(f"获取到nonce: {nonce}")
    
    # 2. 创建新账户
    print("发送ACME新账户请求...")
    
    protected_header = {
        "alg": "RS256",
        "jwk": jwk,
        "nonce": nonce,
        "url": new_account_url
    }
    
    payload = {
        "contact": ["mailto:test@example.com"],
        "termsOfServiceAgreed": True
    }
    
    # 编码protected header和payload
    protected_b64 = base64.urlsafe_b64encode(json.dumps(protected_header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    # 签名数据
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    # 构建JWS请求
    jws_data = {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64
    }
    
    # 发送请求
    headers = {
        "Content-Type": "application/jose+json"
    }
    
    response = requests.post(new_account_url, headers=headers, json=jws_data)
    
    print(f"状态码: {response.status_code}")
    print(f"响应头: {dict(response.headers)}")
    print(f"响应体: {response.text}")
    
    if response.status_code != 201:
        print("❌ ERROR: 账户创建失败")
        return False
    
    print("✅ SUCCESS: 账户创建成功")
    
    # 获取账户ID从Location头
    location = response.headers['Location']
    account_id = location.split('/')[-1]
    print(f"创建的账户ID: {account_id}")
    
    # 3. 测试certbot注销流程 - 使用账户ID 0
    print("\n测试certbot注销流程（使用账户ID 0）...")
    
    # 获取新的nonce
    print("获取新的nonce用于注销...")
    nonce_response2 = requests.head(new_nonce_url)
    nonce2 = nonce_response2.headers['Replay-Nonce']
    print(f"获取到nonce: {nonce2}")
    
    # 创建注销请求 - 使用账户ID 0（certbot注销时的行为）
    account_update_url = f"{base_url}/acme/1/account/0"
    
    protected_header2 = {
        "alg": "RS256",
        "kid": location,  # 使用之前创建的账户的Location作为kid
        "nonce": nonce2,
        "url": account_update_url
    }
    
    payload2 = {
        "status": "deactivated"
    }
    
    # 编码protected header和payload
    protected_b64_2 = base64.urlsafe_b64encode(json.dumps(protected_header2).encode()).decode().rstrip('=')
    payload_b64_2 = base64.urlsafe_b64encode(json.dumps(payload2).encode()).decode().rstrip('=')
    
    # 签名数据
    signing_input_2 = f"{protected_b64_2}.{payload_b64_2}".encode()
    signature_2 = private_key.sign(
        signing_input_2,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64_2 = base64.urlsafe_b64encode(signature_2).decode().rstrip('=')
    
    # 构建JWS请求
    jws_data_2 = {
        "protected": protected_b64_2,
        "payload": payload_b64_2,
        "signature": signature_b64_2
    }
    
    # 发送注销请求
    print("发送ACME账户注销请求（使用账户ID 0）...")
    response2 = requests.post(account_update_url, headers=headers, json=jws_data_2)
    
    print(f"注销状态码: {response2.status_code}")
    print(f"注销响应头: {dict(response2.headers)}")
    print(f"注销响应体: {response2.text}")
    
    if response2.status_code == 200:
        print("✅ SUCCESS: 账户注销成功（使用账户ID 0）")
        return True
    else:
        print(f"❌ ERROR: 账户注销失败，状态码: {response2.status_code}")
        return False

if __name__ == "__main__":
    test_certbot_unregister()