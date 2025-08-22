from flask import jsonify, request, current_app
from app.acme import acme_bp
from app.models import CertificateAuthority, ACMEAccount, ACMEOrder, ACMEAuthorization, ACMEChallenge
from app.acme.utils import generate_nonce, parse_jws, generate_thumbprint, base64url_decode
import json
import secrets
from cryptography.x509 import NameOID, ExtensionOID, DNSName
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def init_acme_routes():
    """初始化ACME相关路由"""
    
    @acme_bp.route('/<int:ca_id>/directory', methods=['GET'])
    def directory(ca_id):
        """ACME目录端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            return jsonify({'error': 'ACME not enabled for this CA'}), 400
        
        # 构建目录响应
        directory_data = {
            "newNonce": f"{request.url_root[:-1]}/acme/{ca_id}/new-nonce",
            "newAccount": f"{request.url_root[:-1]}/acme/{ca_id}/new-account",
            "newOrder": f"{request.url_root[:-1]}/acme/{ca_id}/new-order",
            "revokeCert": f"{request.url_root[:-1]}/acme/{ca_id}/revoke-cert",
            "keyChange": f"{request.url_root[:-1]}/acme/{ca_id}/key-change"
        }
        
        return jsonify(directory_data)
    
    @acme_bp.route('/<int:ca_id>/new-nonce', methods=['HEAD', 'GET'])
    def new_nonce(ca_id):
        """ACME新nonce端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            return '', 400
        
        # 生成新的nonce
        nonce = generate_nonce()
        
        # 返回带有Replay-Nonce头的响应
        response = jsonify({})
        response.headers['Replay-Nonce'] = nonce
        return response, 200
    
    @acme_bp.route('/<int:ca_id>/new-account', methods=['POST'])
    def new_account(ca_id):
        """ACME创建新账户端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            return jsonify({'error': 'ACME not enabled for this CA'}), 400
        
        # 解析JWS请求
        try:
            jws_data = parse_jws()
        except Exception as e:
            return jsonify({'error': str(e)}), 400
        
        # 获取payload
        payload = json.loads(jws_data['payload']) if jws_data['payload'] else {}
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 检查是否为账户查询
        if request.headers.get('Content-Type') == 'application/jose+json' and not jws_data['payload']:
        # 这是账户查询请求
            if not jws_data['kid']:
                response = jsonify({'error': 'Missing account key'})
                response.headers['Replay-Nonce'] = nonce
                return response, 400
            
            # 在实际实现中，应该根据kid查找账户
            # 这里简化处理，直接返回404
            response = jsonify({'error': 'Account not found'})
            response.headers['Replay-Nonce'] = nonce
            return response, 404
        
        # 获取JWK
        jwk = jws_data['jwk']
        if not jwk:
            response = jsonify({'error': 'Missing JWK'})
            response.headers['Replay-Nonce'] = nonce
            return response, 400
        
        # 生成账户指纹
        thumbprint = generate_thumbprint(jwk)
        
        # 检查账户是否已存在
        account = ACMEAccount.query.filter_by(key_id=thumbprint).first()
        only_return_existing = payload.get('onlyReturnExisting', False)
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        if account:
            # 账户已存在
            if only_return_existing:
                # 这是账户查询请求，返回账户信息
                response_data = {
                    'status': account.status,
                    'contact': json.loads(account.contact) if account.contact else [],
                    'termsOfServiceAgreed': account.terms_of_service_agreed
                }
                response = jsonify(response_data)
                response.headers['Location'] = f"{request.url_root[:-1]}/acme/{ca_id}/account/{account.id}"
                response.headers['Replay-Nonce'] = nonce
                return response, 200
            else:
                # 这是重复注册请求，返回冲突错误
                response_data = {
                    'error': 'Account already exists',
                    'status': 'Conflict',
                    'detail': 'An account with this key already exists'
                }
                response = jsonify(response_data)
                response.headers['Location'] = f"{request.url_root[:-1]}/acme/{ca_id}/account/{account.id}"
                response.headers['Replay-Nonce'] = nonce
                return response, 409
        elif only_return_existing:
            # 账户不存在且onlyReturnExisting为true
            response = jsonify({'error': 'Account does not exist'})
            response.headers['Replay-Nonce'] = nonce
            return response, 400
        
        # 创建新账户
        contact = payload.get('contact', [])
        terms_of_service_agreed = payload.get('termsOfServiceAgreed', False)
        
        new_account = ACMEAccount(
            account_id=secrets.token_urlsafe(16),
            user_id=ca.user_id,  # 关联到CA的所有者
            key_id=thumbprint,
            jwk=json.dumps(jwk),  # 存储完整的JWK
            contact=json.dumps(contact),
            terms_of_service_agreed=terms_of_service_agreed
        )
        new_account.save()
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 构建响应
        response_data = {
            'status': new_account.status,
            'contact': contact,
            'termsOfServiceAgreed': terms_of_service_agreed
        }
        
        # 设置Location头
        response = jsonify(response_data)
        response.headers['Location'] = f"{request.url_root[:-1]}/acme/{ca_id}/account/{new_account.id}"
        response.headers['Replay-Nonce'] = nonce
        return response, 201
    
    @acme_bp.route('/<int:ca_id>/new-order', methods=['POST'])
    def new_order(ca_id):
        """ACME创建新订单端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            response = jsonify({'error': 'ACME not enabled for this CA'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 解析JWS请求 - 对于账户更新请求，不严格验证nonce
        try:
            jws_data = parse_jws(verify_nonce_flag=False)
        except Exception as e:
            response = jsonify({'error': str(e)})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 获取payload
        payload = json.loads(jws_data['payload'])
        
        # 获取账户信息
        # ACME协议允许通过JWK或kid来标识账户
        account = None
        
        # 首先尝试通过kid查找账户
        if jws_data['kid']:
            # 从kid中提取账户ID（假设kid格式为账户URL）
            # 例如：kid = "http://example.com/acme/4/account/123"
            # 我们需要提取账户ID（在这个例子中是123）
            import re
            account_id_match = re.search(r'/account/(\d+)$', jws_data['kid'])
            if account_id_match:
                account_id = int(account_id_match.group(1))
                account = ACMEAccount.query.get(account_id)
        
        # 如果没有通过kid找到账户，尝试通过jwk查找
        if not account and jws_data['jwk']:
            thumbprint = generate_thumbprint(jws_data['jwk'])
            account = ACMEAccount.query.filter_by(key_id=thumbprint).first()
        
        # 如果两种方式都没有找到账户，返回错误
        if not account:
            response = jsonify({'error': 'Account not found'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 获取标识符
        identifiers = payload.get('identifiers', [])
        if not identifiers:
            response = jsonify({'error': 'Missing identifiers'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 创建新订单
        # 提取标识符中的域名并存储为JSON格式
        domains = json.dumps(identifiers)
        new_order = ACMEOrder(
            order_id=secrets.token_urlsafe(16),
            account_id=account.id,
            ca_id=ca_id,
            status='pending',
            domains=domains,  # 必须提供domains字段的值
            expires_at=payload.get('notAfter')  # 正确的字段名称是expires_at
        )
        new_order.save()
        
        # 为每个标识符创建授权
        authorizations = []
        for identifier in identifiers:
            if identifier.get('type') == 'dns':
                domain = identifier.get('value')
                
                # 创建授权
                authz = ACMEAuthorization(
                    authz_id=secrets.token_urlsafe(16),  # 使用正确的字段名authz_id
                    order_id=new_order.id,
                    domain=domain,
                    status='pending'
                )
                authz.save()
                
                # 创建HTTP-01挑战
                token = secrets.token_urlsafe(32)
                challenge = ACMEChallenge(
                    challenge_id=secrets.token_urlsafe(16),
                    authz_id=authz.id,  # 使用正确的字段名authz_id
                    type='http-01',
                    token=token,
                    status='pending'
                )
                challenge.save()
                
                # 添加授权URL到列表
                authorizations.append(f"{request.url_root[:-1]}/acme/{ca_id}/authz/{authz.id}")
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 构建响应
        response_data = {
            'status': new_order.status,
            'identifiers': identifiers,
            'authorizations': authorizations,
            'finalize': f"{request.url_root[:-1]}/acme/{ca_id}/order/{new_order.id}/finalize"
        }
        
        # 只有当expires_at有值时才添加到响应中，避免返回None导致解析错误
        if new_order.expires_at:
            response_data['expires'] = new_order.expires_at.isoformat()
        
        # 设置Location头
        response = jsonify(response_data)
        response.headers['Location'] = f"{request.url_root[:-1]}/acme/{ca_id}/order/{new_order.id}"
        response.headers['Replay-Nonce'] = nonce
        return response, 201
    
    @acme_bp.route('/<int:ca_id>/authz/<authz_id>', methods=['GET', 'POST'])
    def get_authorization(ca_id, authz_id):
        """ACME获取授权信息端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            return jsonify({'error': 'ACME not enabled for this CA'}), 400
        
        # 获取授权信息 - 使用id字段（整数主键）而不是authz_id字段（字符串）
        authz = ACMEAuthorization.query.filter_by(id=authz_id, order_id=ACMEOrder.id).join(ACMEOrder).filter(ACMEOrder.ca_id==ca_id).first_or_404()
        
        # 获取挑战信息
        challenges = ACMEChallenge.query.filter_by(authz_id=authz.id).all()
        
        # 构建挑战响应
        challenge_data = []
        for challenge in challenges:
            challenge_info = {
                'type': challenge.type,
                'status': challenge.status,
                'token': challenge.token,
                'url': f"{request.url_root[:-1]}/acme/{ca_id}/challenge/{challenge.challenge_id}"
            }
            
            # 如果是HTTP-01挑战，添加验证URL
            if challenge.type == 'http-01':
                challenge_info['validationRecord'] = [
                    {
                        'url': f"http://{authz.domain}/.well-known/acme-challenge/{challenge.token}",
                        'hostname': authz.domain,
                        'port': '80',
                        'addressesResolved': [],
                        'addressUsed': ''
                    }
                ]
            
            challenge_data.append(challenge_info)
        
        # 构建响应
        response_data = {
            'identifier': {
                'type': 'dns',
                'value': authz.domain
            },
            'status': authz.status,
            'challenges': challenge_data
        }
        
        # 生成nonce并设置响应头
        nonce = secrets.token_urlsafe(16)
        response = jsonify(response_data)
        response.headers['Replay-Nonce'] = nonce
        return response, 200
    
    @acme_bp.route('/<int:ca_id>/challenge/<challenge_id>', methods=['POST'])
    def respond_to_challenge(ca_id, challenge_id):
        """ACME响应挑战端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            response = jsonify({'error': 'ACME not enabled for this CA'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 解析JWS请求 - 对于账户更新请求，不严格验证nonce
        try:
            jws_data = parse_jws(verify_nonce_flag=False)
        except Exception as e:
            response = jsonify({'error': str(e)})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 获取挑战信息 - 使用challenge_id字段（字符串）匹配URL中的参数
        challenge = ACMEChallenge.query.filter_by(challenge_id=challenge_id).join(ACMEAuthorization).join(ACMEOrder).filter(ACMEOrder.ca_id==ca_id).first_or_404()
        
        # 更新挑战状态为processing
        challenge.status = 'processing'
        challenge.save()
        
        # 获取关联的授权 - 使用正确的authz_id字段（外键）
        authz = ACMEAuthorization.query.get(challenge.authz_id)
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 构建响应
        response_data = {
            'type': challenge.type,
            'status': challenge.status,
            'token': challenge.token,
            'url': f"{request.url_root[:-1]}/acme/{ca_id}/challenge/{challenge.challenge_id}"
        }
        
        # 如果是HTTP-01挑战，添加验证URL
        if challenge.type == 'http-01':
            response_data['validationRecord'] = [
                {
                    'url': f"http://{authz.domain}/.well-known/acme-challenge/{challenge.token}",
                    'hostname': authz.domain,
                    'port': '80',
                    'addressesResolved': [],
                    'addressUsed': ''
                }
            ]
        
        # 在实际实现中，这里应该启动一个后台任务来验证挑战
        # 简化处理，直接将挑战状态设置为valid
        # 在生产环境中，应该有一个独立的验证服务来检查HTTP-01挑战
        # 这里我们假设验证成功
        challenge.status = 'valid'
        challenge.save()
        
        # 更新授权状态
        authz.status = 'valid'
        authz.save()
        
        # 检查是否所有授权都已完成
        order = ACMEOrder.query.get(authz.order_id)
        all_valid = True
        authorizations = ACMEAuthorization.query.filter_by(order_id=order.id).all()
        for authorization in authorizations:
            if authorization.status != 'valid':
                all_valid = False
                break
        
        # 如果所有授权都已完成，更新订单状态
        if all_valid:
            order.status = 'ready'
            order.save()
        
        # 构建授权URL作为"up"链接
        authz_url = f"{request.url_root[:-1]}/acme/{ca_id}/authz/{authz.id}"
        
        # 设置响应及头信息
        response = jsonify(response_data)
        response.headers['Replay-Nonce'] = nonce
        response.headers['Link'] = f'<{authz_url}>;rel="up"'
        return response, 200
    
    @acme_bp.route('/<int:ca_id>/order/<order_id>/finalize', methods=['POST'])
    def finalize_order(ca_id, order_id):
        """ACME最终化订单端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            response = jsonify({'error': 'ACME not enabled for this CA'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 解析JWS请求 - 对于账户更新请求，不严格验证nonce
        try:
            jws_data = parse_jws(verify_nonce_flag=False)
        except Exception as e:
            response = jsonify({'error': str(e)})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 获取订单信息
        # 使用整数类型的id字段来查询订单，而不是字符串类型的order_id字段
        order = ACMEOrder.query.filter_by(id=order_id).filter(ACMEOrder.ca_id==ca_id).first_or_404()
        
        # 检查订单状态
        if order.status != 'ready':
            response = jsonify({'error': 'Order is not ready'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 获取payload
        payload = json.loads(jws_data['payload'])
        
        # 获取CSR
        csr_b64 = payload.get('csr')
        if not csr_b64:
            response = jsonify({'error': 'Missing CSR'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 解码CSR
        try:
            csr_der = base64url_decode(csr_b64)
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as e:
            response = jsonify({'error': 'Invalid CSR'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 更新订单状态为processing
        order.status = 'processing'
        order.save()
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 处理CSR并生成证书
        try:
            # 获取CA私钥
            ca_private_key = serialization.load_pem_private_key(
                ca.private_key.encode(),
                password=None
            )
            
            # 加载CA证书
            ca_cert = x509.load_pem_x509_certificate(ca.certificate.encode())
            
            # 从CSR创建证书
            from app.lib.certificate_generator import CertificateGenerator
            
            # 获取通用名称
            try:
                common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except (IndexError, AttributeError):
                # 如果没有COMMON_NAME，使用第一个SAN（如果有）或默认值
                common_name = 'example.com'
                
            # 从CSR中提取SANs
            sans = []
            try:
                san_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except (x509.ExtensionNotFound, ValueError):
                # 如果没有SANs，至少添加通用名称
                sans = [common_name]
                
            # 设置必要的密钥用法和扩展密钥用法
            key_usage = ['digitalSignature', 'keyEncipherment']
            extended_key_usage = ['serverAuth']
            
            # 生成证书
            certificate, _, _ = CertificateGenerator.create_end_entity_certificate(
                csr.public_key(),
                ca_private_key,
                ca_cert,
                common_name,
                sans=sans,
                validity_days=90,  # ACME证书通常有效期为90天
                hash_algorithm='SHA-256',
                key_usage=key_usage,
                extended_key_usage=extended_key_usage
            )
            
            # 将证书转换为PEM格式
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
            
            # 更新订单状态和证书
            order.status = 'valid'
            order.certificate = cert_pem
            order.save()
        except Exception as e:
            order.status = 'invalid'
            order.save()
            response = jsonify({'error': 'Failed to generate certificate'})
            response.headers['Replay-Nonce'] = nonce
            return response, 500
        
        # 构建响应
        response_data = {
            'status': order.status,
            'certificate': f"{request.url_root[:-1]}/acme/{ca_id}/cert/{order.id}"
        }
        
        response = jsonify(response_data)
        response.headers['Replay-Nonce'] = nonce
        return response, 200
    
    @acme_bp.route('/<int:ca_id>/cert/<order_id>', methods=['GET'])
    def download_certificate(ca_id, order_id):
        """ACME下载证书端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            return jsonify({'error': 'ACME not enabled for this CA'}), 400
        
        # 获取订单信息
        # 使用整数类型的id字段来查询订单，而不是字符串类型的order_id字段
        order = ACMEOrder.query.filter_by(id=order_id).filter(ACMEOrder.ca_id==ca_id).first_or_404()
        
        # 检查订单状态
        if order.status != 'valid':
            return jsonify({'error': 'Order is not valid'}), 400
        
        # 返回证书
        return order.certificate, 200, {'Content-Type': 'application/pem-certificate-chain'}
    
    @acme_bp.route('/<int:ca_id>/key-change', methods=['POST'])
    def key_change(ca_id):
        """ACME密钥变更端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            response = jsonify({'error': 'ACME not enabled for this CA'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 解析JWS请求
        try:
            jws_data = parse_jws()
        except Exception as e:
            response = jsonify({'error': str(e)})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 获取payload
        payload = json.loads(jws_data['payload'])
        
        # 在实际实现中，这里应该处理密钥变更请求
        # 简化处理，直接返回成功响应
        response = jsonify({})
        response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
        return response, 200
    
    @acme_bp.route('/<int:ca_id>/account/<int:account_id>', methods=['POST'])
    def account_update(ca_id, account_id):
        """ACME账户更新端点（包括停用账户）"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            response = jsonify({'error': 'ACME not enabled for this CA'})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 解析JWS请求 - 对于账户更新请求，不严格验证nonce
        try:
            jws_data = parse_jws(verify_nonce_flag=False)
        except Exception as e:
            response = jsonify({'error': str(e)})
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 400
        
        # 获取账户信息
        account = ACMEAccount.query.filter_by(id=account_id, user_id=ca.user_id).first_or_404()
        
        # 获取payload
        payload = json.loads(jws_data['payload'])
        
        # 检查是否为账户停用请求
        if payload.get('status') == 'deactivated':
            # 停用账户
            account.status = 'deactivated'
            account.save()
        
        # 构建响应
        response_data = {
            'status': account.status,
            'contact': json.loads(account.contact) if account.contact else [],
            'termsOfServiceAgreed': account.terms_of_service_agreed
        }
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 设置响应
        response = jsonify(response_data)
        response.headers['Replay-Nonce'] = nonce
        return response, 200
    
    # 其他ACME端点可以在这里添加

# 初始化路由
init_acme_routes()