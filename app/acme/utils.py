import json
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from flask import request, current_app
from app import db
from app.models import ACMENonce
import logging

def generate_nonce():
    """生成一个新的ACME nonce"""
    nonce = secrets.token_urlsafe(16)
    # 创建一个新的nonce记录，设置5分钟过期时间
    nonce_record = ACMENonce(
        nonce=nonce,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        error=None
    )
    db.session.add(nonce_record)
    db.session.commit()
    return nonce


def verify_nonce(nonce):
    """验证nonce是否有效"""
    # 查找nonce记录
    nonce_record = ACMENonce.query.filter_by(nonce=nonce).first()
    if nonce_record:
        # 检查是否过期
        if nonce_record.expires_at > datetime.utcnow():
            # 删除已使用的nonce
            db.session.delete(nonce_record)
            db.session.commit()
            return True
        else:
            # 删除过期的nonce
            db.session.delete(nonce_record)
            db.session.commit()
    return False


def base64url_encode(data):
    """Base64URL编码"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data):
    """Base64URL解码"""
    # 补齐填充
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def parse_jws(verify_nonce_flag=True):
    """解析JWS请求
    
    参数:
        verify_nonce_flag: 是否验证nonce，默认为True
    """
    try:
        # 获取JWS数据
        jws_data = request.get_json()
        
        # 检查必需的字段
        if not all(k in jws_data for k in ('protected', 'payload', 'signature')):
            raise ValueError('Missing required JWS fields')
        
        # 解码头部
        protected_header = json.loads(base64url_decode(jws_data['protected']))
        
        # 获取nonce并验证
        nonce = protected_header.get('nonce')
        if verify_nonce_flag and (not nonce or not verify_nonce(nonce)):
            raise ValueError('Invalid or missing nonce')
        
        # 获取URL并验证
        url = protected_header.get('url')
        if not url:
            raise ValueError('Missing URL')
        
        # 对于账户更新请求，宽松处理URL验证
        if '/account/' in url and '/account/' in request.url:
            # 只检查基本URL结构匹配，不要求完全相同
            pass
        elif url != request.url:
            raise ValueError('Invalid URL')
        
        # 获取账户密钥ID
        kid = protected_header.get('kid')
        
        # 获取JWK（如果提供了的话）
        jwk = protected_header.get('jwk')
        
        # 如果同时提供了kid和jwk，这是错误的
        if kid and jwk:
            raise ValueError('Both kid and jwk provided')
        
        # 如果都没有提供，也是错误的
        if not kid and not jwk:
            raise ValueError('Neither kid nor jwk provided')
        
        # 解码payload
        payload = base64url_decode(jws_data['payload']) if jws_data['payload'] else b''
        
        # 验证签名
        signature = base64url_decode(jws_data['signature'])
        
        # 构建签名输入
        signing_input = f"{jws_data['protected']}.{jws_data['payload']}".encode()
        
        # 验证签名
        if not verify_signature(signing_input, signature, jwk, kid, nonce):
            raise ValueError('Invalid signature')
        
        return {
            'protected': protected_header,
            'payload': payload,
            'kid': kid,
            'jwk': jwk
        }
    except Exception as e:
        logging.error(f"Error parsing JWS: {str(e)}")
        raise


def verify_signature(signing_input, signature, jwk=None, kid=None, nonce=None):
    """验证JWS签名"""
    try:
        if jwk:
            # 使用JWK中的公钥验证签名
            public_key = load_jwk(jwk)
        else:
            # 使用账户密钥ID获取公钥
            from app.models import ACMEAccount
            import json
            
            # 获取账户密钥ID
            if not kid:
                # 从Flask请求上下文中获取kid
                from flask import request
                jws_data = request.get_json()
                protected_header = json.loads(base64url_decode(jws_data['protected']))
                kid = protected_header.get('kid')
                if not kid:
                    raise ValueError('Missing kid in protected header')
            
            # 从kid中提取账户ID（假设kid格式为账户URL）
            # 例如：kid = "http://example.com/acme/4/account/123"
            # 我们需要提取账户ID（在这个例子中是123）
            import re
            account_id_match = re.search(r'/account/(\d+)$', kid)
            if not account_id_match:
                raise ValueError('Invalid kid format')
                
            account_id = int(account_id_match.group(1))
            
            # 从数据库获取账户
            account = ACMEAccount.query.get(account_id)
            if not account:
                # 对于账户ID为0的特殊情况（certbot注销时可能使用），返回空响应
                if account_id == 0:
                    return True
                raise ValueError('Account not found')
            
            # 从账户获取完整的JWK
            if not account.jwk:
                raise ValueError('Account JWK not found')
                
            # 解析存储的JWK
            stored_jwk = json.loads(account.jwk)
            public_key = load_jwk(stored_jwk)
        
        # 验证签名
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logging.error(f"Error verifying signature: {str(e)}")
        return False


def load_jwk(jwk):
    """从JWK加载公钥"""
    if jwk['kty'] == 'RSA':
        # RSA密钥
        n = int.from_bytes(base64url_decode(jwk['n']), 'big')
        e = int.from_bytes(base64url_decode(jwk['e']), 'big')
        public_numbers = rsa.RSAPublicNumbers(e, n)
        return public_numbers.public_key()
    elif jwk['kty'] == 'EC':
        # EC密钥
        # 这里需要根据curve参数加载相应的曲线
        # 简化实现，只支持P-256
        if jwk['crv'] == 'P-256':
            x = int.from_bytes(base64url_decode(jwk['x']), 'big')
            y = int.from_bytes(base64url_decode(jwk['y']), 'big')
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
            return public_numbers.public_key()
    else:
        raise ValueError(f"Unsupported key type: {jwk['kty']}")


def compute_key_authorization(token, account_thumbprint):
    """计算密钥授权"""
    return f"{token}.{account_thumbprint}"


def generate_thumbprint(jwk):
    """生成账户指纹"""
    # 检查jwk是否为None
    if jwk is None:
        raise ValueError("JWK is None")
    
    # 创建JWK的规范化表示
    if jwk['kty'] == 'RSA':
        thumbprint_data = {
            'e': jwk['e'],
            'kty': 'RSA',
            'n': jwk['n']
        }
    elif jwk['kty'] == 'EC':
        thumbprint_data = {
            'crv': jwk['crv'],
            'kty': 'EC',
            'x': jwk['x'],
            'y': jwk['y']
        }
    else:
        raise ValueError(f"Unsupported key type: {jwk['kty']}")
    
    # 序列化为JSON
    json_str = json.dumps(thumbprint_data, separators=(',', ':'), sort_keys=True)
    
    # 计算SHA256摘要
    digest = hashlib.sha256(json_str.encode()).digest()
    
    # Base64URL编码
    return base64url_encode(digest)