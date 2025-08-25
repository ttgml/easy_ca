#!/usr/bin/env python3
"""
测试ACME挑战端点功能
"""
import requests
import json
import base64
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ACME服务器配置
ACME_BASE_URL = "http://localhost:5000/acme/1"

# 生成RSA密钥对
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()

# 获取nonce
def get_nonce():
    response = requests.get(f"{ACME_BASE_URL}/new-nonce")
    return response.headers.get('Replay-Nonce')

# 创建JWS签名
def create_jws(payload, private_key_pem, url, nonce=None, kid=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    import json
    
    # 加载私钥
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )
    
    # 构建protected header
    protected = {
        "alg": "RS256",
        "url": url
    }
    
    if nonce:
        protected["nonce"] = nonce
    if kid:
        protected["kid"] = kid
    else:
        # 新账户创建，使用jwk
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        protected["jwk"] = {
            "kty": "RSA",
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode().rstrip('='),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode().rstrip('=')
        }
    
    # 编码protected header
    protected_b64 = base64.urlsafe_b64encode(json.dumps(protected).encode()).decode().rstrip('=')
    
    # 编码payload
    if payload:
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    else:
        payload_b64 = ""
    
    # 创建签名数据
    signing_input = f"{protected_b64}.{payload_b64}".encode()
    
    # 签名
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # 编码签名
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64
    }

def main():
    print("测试ACME挑战端点功能...")
    
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print("✅ 密钥对生成成功")
    
    # 获取nonce
    nonce = get_nonce()
    print(f"1. 获取nonce: {nonce}")
    
    # 创建账户
    print("2. 创建ACME账户...")
    account_payload = {
        "contact": ["mailto:test@example.com"],
        "termsOfServiceAgreed": True
    }
    
    jws = create_jws(account_payload, private_key, f"{ACME_BASE_URL}/new-account", nonce=nonce)
    
    response = requests.post(f"{ACME_BASE_URL}/new-account", json=jws)
    print(f"账户创建状态码: {response.status_code}")
    
    if response.status_code != 201:
        print(f"❌ 账户创建失败: {response.text}")
        return
    
    account_data = response.json()
    kid = response.headers.get('Location')  # KID是Location头
    print(f"✅ 账户创建成功，KID: {kid}")
    
    # 获取新的nonce
    nonce = get_nonce()
    print(f"3. 获取新的nonce: {nonce}")
    
    # 创建订单
    print("4. 创建新订单...")
    order_payload = {
        "identifiers": [
            {"type": "dns", "value": "test.example.com"}
        ]
    }
    
    jws = create_jws(order_payload, private_key, f"{ACME_BASE_URL}/new-order", nonce=nonce, kid=kid)
    
    response = requests.post(f"{ACME_BASE_URL}/new-order", json=jws)
    print(f"订单创建状态码: {response.status_code}")
    
    if response.status_code != 201:
        print(f"❌ 订单创建失败: {response.text}")
        return
    
    order_data = response.json()
    print(f"✅ 订单创建成功，授权URLs: {order_data['authorizations']}")
    
    # 获取授权信息
    authz_url = order_data['authorizations'][0]
    print(f"5. 获取授权信息: {authz_url}")
    
    response = requests.get(authz_url)
    print(f"授权查询状态码: {response.status_code}")
    
    if response.status_code != 200:
        print(f"❌ 授权查询失败: {response.text}")
        return
    
    authz_data = response.json()
    print(f"✅ 授权信息获取成功")
    print(f"   域名: {authz_data['identifier']['value']}")
    print(f"   状态: {authz_data['status']}")
    print(f"   挑战数量: {len(authz_data['challenges'])}")
    
    # 获取挑战信息
    challenge = authz_data['challenges'][0]
    challenge_url = challenge['url']
    print(f"6. 挑战URL: {challenge_url}")
    
    # 测试挑战端点
    print("7. 测试挑战端点...")
    nonce = get_nonce()
    print(f"   获取挑战nonce: {nonce}")
    
    # 空的payload用于挑战响应
    jws = create_jws({}, private_key, challenge_url, nonce=nonce, kid=kid)
    
    response = requests.post(challenge_url, json=jws)
    print(f"   挑战响应状态码: {response.status_code}")
    
    if response.status_code == 200:
        print("✅ 挑战端点测试成功！")
        print(f"   挑战响应: {response.json()}")
    else:
        print(f"❌ 挑战端点测试失败: {response.text}")

if __name__ == "__main__":
    main()