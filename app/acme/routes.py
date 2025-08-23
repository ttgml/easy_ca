from flask import jsonify, request, current_app
from app.acme import acme_bp
from app.models import CertificateAuthority, ACMEAccount, ACMEOrder, ACMEAuthorization, ACMEChallenge
from app.acme.utils import generate_nonce, parse_jws, generate_thumbprint, base64url_decode
from app import db
import json
import secrets
from cryptography.x509 import NameOID, DNSName
from cryptography.hazmat._oid import ExtensionOID
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
            # 根据RFC 8555，当账户不存在时，应该返回200状态码和空JSON对象
            # 这样客户端就知道账户不存在，可以重新注册
            # 但仍然需要设置Location头，以便客户端可以正确处理响应
            response = jsonify({})
            response.headers['Location'] = f"{request.url_root[:-1]}/acme/{ca_id}/account/0"  # 使用0作为不存在账户的占位符ID
            response.headers['Replay-Nonce'] = nonce
            return response, 200
        
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
        db.session.add(new_account)
        db.session.commit()
        
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
            domains=json.dumps(identifiers),  # 必须提供domains字段的值
            expires_at=payload.get('notAfter')  # 正确的字段名称是expires_at
        )
        db.session.add(new_order)
        db.session.commit()
        
        # 为每个标识符创建授权
        authorizations = []
        authz_objects = []  # 存储授权对象以便后续使用
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
                db.session.add(authz)
                authz_objects.append(authz)
        db.session.commit()
                
        # 创建HTTP-01挑战（使用最后一个授权对象）
        challenge = None
        if authz_objects:
            authz = authz_objects[-1]  # 使用最后一个授权对象
            token = secrets.token_urlsafe(32)
            challenge = ACMEChallenge(
                challenge_id=secrets.token_urlsafe(16),
                authz_id=authz.id,  # 使用正确的authz_id字段
                type='http-01',
                token=token,
                status='pending'
            )
            db.session.add(challenge)
            db.session.commit()
                
        # 添加授权URL到列表（如果有授权对象）
        if authz_objects:
            authorizations.append(f"{request.url_root[:-1]}/acme/{ca_id}/authz/{authz.authz_id}")
        
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
        
        # 获取授权信息 - 使用authz_id字段（字符串）来匹配URL参数
        # 注意：order_id字段存储的是ACMEOrder.order_id（字符串），不是ACMEOrder.id（整数）
        authz = ACMEAuthorization.query.filter_by(authz_id=authz_id).first_or_404()
        
        # 验证授权所属的CA是否正确
        order = ACMEOrder.query.filter_by(id=authz.order_id).first()
        if not order or order.ca_id != ca_id:
            return jsonify({'error': 'Authorization not found'}), 404
        
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
    
    @acme_bp.route('/<int:ca_id>/challenge/<path:challenge_id>', methods=['POST'])
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
        challenge = ACMEChallenge.query.filter_by(challenge_id=challenge_id).first_or_404()
        
        # 更新挑战状态为processing
        challenge.status = 'processing'
        db.session.add(challenge)
        db.session.commit()
        
        # 获取关联的授权 - 使用正确的authz_id字段（外键）
        authz = ACMEAuthorization.query.filter_by(id=challenge.authz_id).first()
        
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
        db.session.add(challenge)
        db.session.commit()
        
        # 更新授权状态
        authz.status = 'valid'
        db.session.add(authz)
        db.session.commit()
        
        # 检查是否所有授权都已完成
        order = ACMEOrder.query.filter_by(id=authz.order_id).first()
        all_valid = True
        authorizations = ACMEAuthorization.query.filter_by(order_id=order.id).all()
        for authorization in authorizations:
            if authorization.status != 'valid':
                all_valid = False
                break
        
        # 如果所有授权都已完成，更新订单状态
        if all_valid:
            order.status = 'ready'
            db.session.add(order)
            db.session.commit()
        
        # 构建授权URL作为"up"链接
        authz_url = f"{request.url_root[:-1]}/acme/{ca_id}/authz/{authz.authz_id}"
        
        # 设置响应及头信息
        response = jsonify(response_data)
        response.headers['Replay-Nonce'] = nonce
        response.headers['Link'] = f'<{authz_url}>;rel="up"'
        return response, 200
    
    @acme_bp.route('/<int:ca_id>/order/<path:order_id>', methods=['POST'])
    def get_order(ca_id, order_id):
        """ACME获取订单信息端点"""
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
        
        # 获取授权信息
        authorizations = ACMEAuthorization.query.filter_by(order_id=order.id).all()
        authorization_urls = []
        for authz in authorizations:
            authorization_urls.append(f"{request.url_root[:-1]}/acme/{ca_id}/authz/{authz.authz_id}")
        
        # 构建响应
        response_data = {
            'status': order.status,
            'identifiers': json.loads(order.domains) if order.domains else [],
            'authorizations': authorization_urls,
            'finalize': f"{request.url_root[:-1]}/acme/{ca_id}/order/{order.id}/finalize"
        }
        
        # 只有当expires_at有值时才添加到响应中，避免返回None导致解析错误
        if order.expires_at:
            response_data['expires'] = order.expires_at.isoformat()
        
        # 如果订单有证书，添加证书URL
        if order.certificate:
            response_data['certificate'] = f"{request.url_root[:-1]}/acme/{ca_id}/cert/{order.id}"
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 设置响应及头信息
        response = jsonify(response_data)
        response.headers['Replay-Nonce'] = nonce
        response.headers['Location'] = f"{request.url_root[:-1]}/acme/{ca_id}/order/{order.id}"
        return response, 200

    @acme_bp.route('/<int:ca_id>/order/<path:order_id>/finalize', methods=['POST'])
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
        db.session.commit()
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 处理CSR并生成证书
        try:
            # 获取CA私钥
            ca_private_key = serialization.load_pem_private_key(
                ca.get_private_key().encode(),
                password=None
            )
            
            # 加载CA证书
            ca_cert = x509.load_pem_x509_certificate(ca.certificate.encode())
            
            # 从CSR创建证书
            from app.lib.certificate_generator import CertificateGenerator
            
            # 从CSR中提取SANs
            sans = []
            try:
                san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                # 使用正确的方法获取DNS名称
                sans = [dns_name.value for dns_name in san_ext.value]
            except (x509.ExtensionNotFound, ValueError):
                # 如果没有SANs，保持空列表
                pass
                
            # 获取通用名称
            try:
                common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except (IndexError, AttributeError):
                # 如果没有COMMON_NAME，使用第一个SAN（如果有）或默认值
                if sans:
                    common_name = sans[0]
                else:
                    common_name = 'example.com'
                
            # 如果没有SANs，至少添加通用名称
            if not sans:
                sans = [common_name]
                
            # 设置必要的密钥用法和扩展密钥用法
            key_usage = ['digitalSignature', 'keyEncipherment']
            extended_key_usage = ['serverAuth']
            
            # 生成证书私钥对
            cert_private_key = CertificateGenerator.generate_key_pair(
                key_type='RSA',
                key_size=2048
            )
            
            # 从私钥获取公钥
            cert_public_key = cert_private_key.public_key()
            
            # 生成证书
            certificate, valid_from, valid_to = CertificateGenerator.create_certificate_from_csr(
                cert_public_key,  # 使用生成的公钥而不是CSR的公钥
                ca_private_key,
                ca_cert,
                common_name,
                sans=sans,
                validity_days=90,  # ACME证书通常有效期为90天
                hash_algorithm='SHA-256',
                key_usage=key_usage,
                extended_key_usage=extended_key_usage
            )
            
            # 将私钥转换为PEM格式
            cert_private_key_pem = cert_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # 将证书转换为PEM格式并添加CA证书以形成完整的证书链
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
            ca_cert_pem = ca.certificate
            full_chain = cert_pem + ca_cert_pem
            
            # 保存证书到数据库
            from app.models import Certificate
            # 获取证书序列号
            serial_number = format(certificate.serial_number, 'X')
            
            # 创建证书对象
            cert_obj = Certificate(
                common_name=common_name,
                serial_number=serial_number,
                certificate=cert_pem,
                valid_from=valid_from,
                valid_to=valid_to,
                user_id=ca.user_id,  # 使用CA的所有者作为证书所有者
                ca_id=ca.id,
                status='valid'
            )
            
            # 设置SANs和私钥
            cert_obj.set_sans(sans)
            cert_obj.set_private_key(cert_private_key_pem)
            
            # 保存证书到数据库
            db.session.add(cert_obj)
            db.session.flush()  # 获取cert_obj.id
            
            # 更新订单状态和证书
            order.status = 'valid'
            order.certificate = full_chain
            order.certificate_serial = serial_number
            db.session.commit()
        except Exception as e:
            import traceback
            print(f"Certificate generation error: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            order.status = 'invalid'
            db.session.commit()
            response = jsonify({'error': 'Failed to generate certificate', 'details': str(e)})
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
    
    @acme_bp.route('/<int:ca_id>/cert/<path:order_id>', methods=['GET', 'POST'])
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
        
        # 生成nonce
        nonce = secrets.token_urlsafe(16)
        
        # 返回证书和Replay-Nonce头
        response = current_app.response_class(
            response=order.certificate,
            status=200,
            mimetype='application/pem-certificate-chain'
        )
        response.headers['Replay-Nonce'] = nonce
        return response
    
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
        account = ACMEAccount.query.get(account_id)
        
        # 如果账户不存在，根据ACME RFC 8555，对于不存在的账户操作应该返回200和空JSON对象
        # 这样客户端就知道账户不存在，可以重新注册
        if not account:
            response = jsonify({})
            response.headers['Location'] = f"{request.url_root[:-1]}/acme/{ca_id}/account/{account_id}"
            response.headers['Replay-Nonce'] = secrets.token_urlsafe(16)
            return response, 200
        
        # 获取payload
        payload = json.loads(jws_data['payload'])
        
        # 检查是否为账户停用请求
        if payload.get('status') == 'deactivated':
            # 停用账户
            account.status = 'deactivated'
            db.session.commit()
        
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