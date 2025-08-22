from flask import render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from app.models import CertificateAuthority, Certificate
from datetime import datetime, timedelta, timezone
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import logging

def init_routes(main_bp):
    """初始化main蓝图的路由"""
    
    @main_bp.route('/')
    @main_bp.route('/home')
    def home():
        """首页路由"""
        # 使用render_template函数渲染模板
        from flask import render_template
        # 传递当前年份给模板
        return render_template('main/home.html', current_year=2024)
    
    @main_bp.route('/about')
    def about():
        """关于页面路由"""
        from flask import render_template
        return render_template('main/about.html', current_year=2024)
    
    @main_bp.route('/dashboard')
    @login_required
    def dashboard():
        """用户仪表盘"""
        # 获取当前用户的所有CA和证书
        ca_count = CertificateAuthority.query.filter_by(user_id=current_user.id).count()
        cert_count = Certificate.query.filter_by(user_id=current_user.id).count()
        active_certs = Certificate.query.filter_by(user_id=current_user.id, status='valid').count()
        
        # 获取即将过期的证书数量（30天内过期）
        from datetime import datetime, timedelta, timezone
        expiring_threshold = datetime.now(timezone.utc) + timedelta(days=30)
        expiring_certs = Certificate.query.filter(
            Certificate.user_id == current_user.id,
            Certificate.status == 'valid',
            Certificate.valid_to <= expiring_threshold
        ).count()
        
        # 获取已吊销的证书数量
        revoked_certs = Certificate.query.filter_by(user_id=current_user.id, status='revoked').count()
        
        # 获取最近的CA和证书
        recent_cas = CertificateAuthority.query.filter_by(user_id=current_user.id).order_by(CertificateAuthority.created_at.desc()).limit(5).all()
        recent_certs = Certificate.query.filter_by(user_id=current_user.id).order_by(Certificate.created_at.desc()).limit(5).all()
        
        return render_template('main/dashboard.html', 
                             current_year=2024, 
                             ca_count=ca_count, 
                             cert_count=cert_count, 
                             active_certs=active_certs,
                             expiring_certs=expiring_certs,
                             revoked_certs=revoked_certs,
                             recent_cas=recent_cas, 
                             recent_certs=recent_certs)
    
    @main_bp.route('/ca/new', methods=['GET', 'POST'])
    @login_required
    def new_ca():
        """创建新的证书颁发机构"""
        if request.method == 'POST':
            # 获取表单数据
            name = request.form.get('name')
            common_name = request.form.get('common_name')
            organization = request.form.get('organization')
            organizational_unit = request.form.get('organizational_unit')  # 组织单位 (OU)
            country = request.form.get('country')                          # 国家 (C)
            state = request.form.get('state')                              # 省/州 (ST)
            locality = request.form.get('locality')                        # 城市 (L)
            validity_years = int(request.form.get('validity_years', 10))
            key_type = request.form.get('key_type', 'RSA')
            key_size = int(request.form.get('key_size', 2048))
            
            # 简单的表单验证
            if not name or not common_name:
                flash('请填写CA名称和通用名称', 'danger')
                return redirect(url_for('main.new_ca'))
            
            # 生成密钥对和自签名证书（使用cryptography库）
            try:
                # 创建一个新的CA
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa, ec
                from cryptography.x509.oid import NameOID
                
                # 生成密钥对
                if key_type == 'RSA':
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=key_size,
                    )
                else:  # ECC
                    private_key = ec.generate_private_key(
                        ec.SECP256R1()
                    )
                
                # 创建证书主体
                subject_attrs = [
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ]
                
                # 添加组织信息（如果有）
                if organization:
                    subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
                
                # 添加组织单位信息（如果有）
                if organizational_unit:
                    subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
                
                # 添加国家信息（如果有）
                if country:
                    subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
                
                # 添加省/州信息（如果有）
                if state:
                    subject_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
                
                # 添加城市信息（如果有）
                if locality:
                    subject_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
                
                subject = x509.Name(subject_attrs)
                
                # 因为是自签名证书，颁发者和主体相同
                issuer = subject
                
                # 设置证书有效期
                valid_from = datetime.now(timezone.utc)
                valid_to = valid_from + timedelta(days=365 * validity_years)
                
                # 创建证书生成器
                cert_builder = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(private_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(valid_from)
                    .not_valid_after(valid_to)
                    .add_extension(
                        x509.BasicConstraints(ca=True, path_length=None), critical=True,
                    )
                )
                
                # 签名证书
                if key_type == 'RSA':
                    certificate = cert_builder.sign(
                        private_key=private_key,
                        algorithm=hashes.SHA256(),
                    )
                else:  # ECC
                    certificate = cert_builder.sign(
                        private_key=private_key,
                        algorithm=hashes.SHA256(),
                    )
                
                # 将私钥和证书转换为PEM格式
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                certificate_pem = certificate.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode('utf-8')
                
                # 提取证书序列号
                serial_number = str(certificate.serial_number)
                
                # 设置CA有效期
                valid_from = datetime.now(timezone.utc)
                valid_to = valid_from + timedelta(days=365 * validity_years)
                
                # 创建CA记录
                new_ca = CertificateAuthority(
                    name=name,
                    common_name=common_name,
                    organization=organization,
                    organizational_unit=organizational_unit,  # 组织单位 (OU)
                    country=country,                          # 国家 (C)
                    state=state,                              # 省/州 (ST)
                    locality=locality,                        # 城市 (L)
                    serial_number=serial_number,
                    valid_from=valid_from,
                    valid_to=valid_to,
                    certificate=certificate_pem,
                    user_id=current_user.id
                )
                # 设置CA的其他属性
                new_ca.validity_years = validity_years
                new_ca.key_type = key_type
                new_ca.key_size = key_size
                
                # 加密存储私钥
                new_ca.set_private_key(private_key_pem)
                
                # 保存到数据库
                new_ca.save()
                
                flash('证书颁发机构创建成功', 'success')
                return redirect(url_for('main.ca_detail', ca_id=new_ca.id))
            except Exception as e:
                flash(f'创建证书颁发机构失败：{str(e)}', 'danger')
                return redirect(url_for('main.new_ca'))
        
        return render_template('main/new_ca.html', current_year=2024)
    
    @main_bp.route('/ca/<int:ca_id>')
    @login_required
    def ca_detail(ca_id):
        """查看CA详情"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权访问该CA', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 获取该CA签发的所有证书
        certificates = Certificate.query.filter_by(ca_id=ca_id).all()
        
        return render_template('main/ca_detail.html', current_year=2024, ca=ca, certificates=certificates)
    
    @main_bp.route('/ca/<int:ca_id>/settings')
    @login_required
    def ca_settings(ca_id):
        """CA设置页面"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权访问该CA设置', 'danger')
            return redirect(url_for('main.dashboard'))
        
        return render_template('main/ca_settings.html', current_year=2024, ca=ca)
    
    @main_bp.route('/ca/<int:ca_id>/settings', methods=['POST'])
    @login_required
    def save_ca_settings(ca_id):
        """保存CA设置"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权修改该CA设置', 'danger')
            return redirect(url_for('main.dashboard'))
        
        try:
            # 更新ACME设置
            ca.acme_enabled = request.form.get('acme_enabled') == 'on'
            ca.auto_approve = request.form.get('auto_approve') == 'on'
            ca.http01_enabled = request.form.get('http01_enabled') == 'on'
            ca.dns01_enabled = request.form.get('dns01_enabled') == 'on'
            
            # 保存到数据库
            ca.save()
            
            flash('CA设置已保存', 'success')
        except Exception as e:
            flash(f'保存CA设置失败：{str(e)}', 'danger')
        
        return redirect(url_for('main.ca_settings', ca_id=ca_id))
    
    @main_bp.route('/certificate/new', methods=['GET', 'POST'])
    @login_required
    def new_certificate():
        """签发新证书"""
        # 获取当前用户的所有CA
        cas = CertificateAuthority.query.filter_by(user_id=current_user.id, status='active').all()
        
        if request.method == 'POST':
            # 获取表单数据
            ca_id = request.form.get('ca_id')
            common_name = request.form.get('common_name')
            sans_text = request.form.get('sans')
            validity_days = int(request.form.get('validity_days', 365))
            
            # 简单的表单验证
            if not ca_id or not common_name:
                flash('请选择CA并填写通用名称', 'danger')
                return redirect(url_for('main.new_certificate'))
            
            # 解析SANs（Subject Alternative Names）
            sans = []
            if sans_text:
                sans = [san.strip() for san in sans_text.split('\n') if san.strip()]
            
            # 获取CA信息
            ca = CertificateAuthority.query.get_or_404(ca_id)
            
            # 检查CA是否为当前用户所有
            if ca.user_id != current_user.id:
                flash('无权使用该CA签发证书', 'danger')
                return redirect(url_for('main.new_certificate'))
            
            try:
                # 生成证书（使用cryptography库）
                
                # 生成新的密钥对
                cert_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                
                # 解析CA私钥
                ca_private_key_pem = ca.get_private_key()
                ca_private_key = serialization.load_pem_private_key(
                    ca_private_key_pem.encode(),
                    password=None
                )
                
                # 确保ca_private_key是正确的类型
                if not isinstance(ca_private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                    raise ValueError("CA私钥类型不正确")
                
                # 解析CA证书
                ca_cert_pem = ca.certificate
                ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
                
                # 创建证书主体
                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ])
                
                # 颁发者是CA
                issuer = ca_cert.subject
                
                # 设置证书有效期
                valid_from = datetime.now(timezone.utc)
                valid_to = valid_from + timedelta(days=validity_days)
                
                # 创建证书生成器
                cert_builder = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(cert_private_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(valid_from)
                    .not_valid_after(valid_to)
                    .add_extension(
                        x509.BasicConstraints(ca=False, path_length=None), critical=True,
                    )
                )
                
                # 提取证书序列号
                serial_number = str(cert_builder.serial_number)
                
                # 添加SANs扩展（如果有）
                if sans:
                    san_list = [x509.DNSName(san) for san in sans]
                    cert_builder = cert_builder.add_extension(
                        x509.SubjectAlternativeName(san_list),
                        critical=False,
                    )
                
                # 签名证书
                certificate = cert_builder.sign(
                    private_key=ca_private_key,
                    algorithm=hashes.SHA256(),
                )
                
                # 将私钥和证书转换为PEM格式
                cert_private_key_pem = cert_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                certificate_pem = certificate.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode('utf-8')
                
                # 生成唯一序列号
                serial_number = str(uuid.uuid4())
                
                # 创建证书记录
                new_cert = Certificate(
                    common_name=common_name,
                    serial_number=serial_number,
                    certificate=certificate_pem,
                    user_id=current_user.id,
                    ca_id=ca_id,
                    valid_from=valid_from,
                    valid_to=valid_to
                )
                
                # 存储SANs
                if sans:
                    new_cert.set_sans(sans)
                
                # 加密存储私钥
                new_cert.set_private_key(cert_private_key_pem)
                
                # 保存到数据库
                new_cert.save()
                
                flash('证书创建成功', 'success')
                return redirect(url_for('main.certificate_detail', cert_id=new_cert.id))
            except Exception as e:
                flash(f'创建证书失败：{str(e)}', 'danger')
                return redirect(url_for('main.new_certificate'))
        
        return render_template('main/new_certificate.html', current_year=2024, cas=cas)
    
    @main_bp.route('/certificate/<int:cert_id>')
    @login_required
    def certificate_detail(cert_id):
        """查看证书详情"""
        # 获取证书信息
        cert = Certificate.query.get_or_404(cert_id)
        
        # 检查是否为当前用户的证书
        if cert.user_id != current_user.id:
            flash('无权访问该证书', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(cert.ca_id)
        
        # 解析证书信息
        try:
            # 加载证书
            certificate = x509.load_pem_x509_certificate(cert.certificate.encode())
            
            # 获取Issuer信息
            issuer = certificate.issuer
            
            # 获取Subject信息
            subject = certificate.subject
            
            # 获取Extensions信息
            extensions = certificate.extensions
            
            # 格式化Issuer信息
            issuer_str = ''
            for attr in issuer:
                oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                issuer_str += f'{oid_name}: {attr.value}\n'
            
            # 格式化Subject信息
            subject_str = ''
            for attr in subject:
                oid_name = attr.oid._name if hasattr(attr.oid, '_name') else str(attr.oid)
                subject_str += f'{oid_name}: {attr.value}\n'
            
            # 格式化Extensions信息
            extensions_str = ''
            for ext in extensions:
                oid_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                extensions_str += f'{oid_name}: {ext.value}\n'
        except Exception as e:
            # 如果解析失败，使用原始证书内容
            issuer_str = cert.certificate
            subject_str = cert.certificate
            extensions_str = str(e)
        
        # 检查证书是否为CA证书，以决定是否显示ACME指南
        show_acme_guide = cert.is_ca if cert else False
        
        return render_template('main/certificate_detail.html', current_year=2024, cert=cert, ca=ca, issuer_str=issuer_str, subject_str=subject_str, extensions_str=extensions_str, show_acme_guide=show_acme_guide)
    
    @main_bp.route('/certificate/<int:cert_id>/revoke', methods=['POST'])
    @login_required
    def revoke_certificate(cert_id):
        """吊销证书"""
        # 获取证书信息
        cert = Certificate.query.get_or_404(cert_id)
        
        # 检查是否为当前用户的证书
        if cert.user_id != current_user.id:
            flash('无权吊销该证书', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 检查证书是否已过期或已吊销
        if cert.status != 'valid':
            flash('证书已不是有效状态，无需吊销', 'warning')
            return redirect(url_for('main.certificate_detail', cert_id=cert_id))
        
        try:
            # 更新证书状态
            cert.status = 'revoked'
            cert.revoked_at = datetime.now(timezone.utc)
            cert.revocation_reason = request.form.get('revocation_reason', 'Unspecified')
            cert.save()
            
            flash('证书已成功吊销', 'success')
        except Exception as e:
            flash(f'吊销证书失败：{str(e)}', 'danger')
        
        return redirect(url_for('main.certificate_detail', cert_id=cert_id))

    @main_bp.route('/ca/<int:ca_id>/revoke', methods=['POST'])
    @login_required
    def revoke_ca(ca_id):
        """吊销CA"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权吊销该CA', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 检查CA是否已吊销
        if ca.status != 'active':
            flash('CA已不是活跃状态，无需吊销', 'warning')
            return redirect(url_for('main.ca_detail', ca_id=ca_id))
        
        try:
            # 吊销所有由此CA签发的证书
            certificates = Certificate.query.filter_by(ca_id=ca_id).all()
            for cert in certificates:
                if cert.status == 'valid':
                    cert.status = 'revoked'
                    cert.revoked_at = datetime.now(timezone.utc)
                    cert.revocation_reason = 'CA Compromise'
                    cert.save()
            
            # 更新CA状态
            ca.status = 'revoked'
            ca.revoked_at = datetime.now(timezone.utc)
            ca.revocation_reason = request.form.get('revocation_reason', 'Unspecified')
            ca.save()
            
            flash('CA已成功吊销，所有由此CA签发的证书也已吊销', 'success')
        except Exception as e:
            flash(f'吊销CA失败：{str(e)}', 'danger')
        
        return redirect(url_for('main.ca_detail', ca_id=ca_id))

    @main_bp.route('/ca/<int:ca_id>/activate', methods=['POST'])
    @login_required
    def activate_ca(ca_id):
        """激活CA"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权激活该CA', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 检查CA是否已激活
        if ca.status == 'active':
            flash('CA已处于活跃状态', 'warning')
            return redirect(url_for('main.ca_detail', ca_id=ca_id))
        
        try:
            # 更新CA状态
            ca.status = 'active'
            # 清除吊销信息
            ca.revoked_at = None
            ca.revocation_reason = None
            ca.save()
            
            flash('CA已成功激活', 'success')
        except Exception as e:
            flash(f'激活CA失败：{str(e)}', 'danger')
        
        return redirect(url_for('main.ca_detail', ca_id=ca_id))

    @main_bp.route('/certificate/<int:cert_id>/download/certificate')
    @login_required
    def download_certificate(cert_id):
        """下载证书文件"""
        # 获取证书信息
        cert = Certificate.query.get_or_404(cert_id)
        
        # 检查是否为当前用户的证书
        if cert.user_id != current_user.id:
            flash('无权下载该证书', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 创建响应对象
        response = Response(cert.certificate, mimetype='application/x-pem-file')
        response.headers['Content-Disposition'] = f'attachment; filename=certificate-{cert_id}.pem'
        return response
    
    @main_bp.route('/certificate/<int:cert_id>/download/private_key')
    @login_required
    def download_private_key(cert_id):
        """下载私钥文件"""
        # 获取证书信息
        cert = Certificate.query.get_or_404(cert_id)
        
        # 检查是否为当前用户的证书
        if cert.user_id != current_user.id:
            flash('无权下载该私钥', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 获取解密后的私钥
        private_key = cert.get_private_key()
        
        # 创建响应对象
        response = Response(private_key, mimetype='application/x-pem-file')
        response.headers['Content-Disposition'] = f'attachment; filename=private-key-{cert_id}.pem'
        return response
    
    @main_bp.route('/certificate/<int:cert_id>/download/pkcs12')
    @login_required
    def download_pkcs12(cert_id):
        """下载PKCS#12格式的证书文件"""
        # 获取证书信息
        cert = Certificate.query.get_or_404(cert_id)
        
        # 检查是否为当前用户的证书
        if cert.user_id != current_user.id:
            flash('无权下载该证书', 'danger')
            return redirect(url_for('main.dashboard'))
        
        try:
            # 设置日志
            logging.basicConfig(level=logging.DEBUG)
            logger = logging.getLogger(__name__)
            
            # 记录证书信息
            logger.debug(f"Certificate ID: {cert_id}")
            logger.debug(f"Certificate content: {cert.certificate[:100]}...")
            
            # 加载证书
            certificate = x509.load_pem_x509_certificate(cert.certificate.encode())
            logger.debug("Certificate loaded successfully")
            
            # 加载私钥
            private_key_pem = cert.get_private_key()
            logger.debug(f"Private key content: {private_key_pem[:100]}...")
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            logger.debug("Private key loaded successfully")
            
            # 创建PKCS#12数据
            # 确保private_key是正确的类型
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
            if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, dsa.DSAPrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
                pkcs12_data = pkcs12.serialize_key_and_certificates(
                    name=b"certificate",
                    key=private_key,
                    cert=certificate,
                    cas=None,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:
                raise ValueError("私钥类型不支持PKCS#12序列化")
            logger.debug("PKCS#12 data created successfully")
            
            # 创建响应对象
            response = Response(pkcs12_data, mimetype='application/x-pkcs12')
            response.headers['Content-Disposition'] = f'attachment; filename=certificate-{cert_id}.p12'
            logger.debug("Response created successfully")
            return response
        except Exception as e:
            import traceback
            error_msg = f'生成PKCS#12文件失败：{str(e)}\n{traceback.format_exc()}'
            print(error_msg)  # 打印到控制台
            logging.error(error_msg)  # 记录到日志
            flash(f'生成PKCS#12文件失败：{str(e)}', 'danger')
            return redirect(url_for('main.certificate_detail', cert_id=cert_id))
    
    @main_bp.route('/ca/<int:ca_id>/download/private_key')
    @login_required
    def download_ca_private_key(ca_id):
        """下载CA私钥文件"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权下载该私钥', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 获取解密后的私钥
        private_key = ca.get_private_key()
        
        # 创建响应对象
        response = Response(private_key, mimetype='application/x-pem-file')
        response.headers['Content-Disposition'] = f'attachment; filename=ca-private-key-{ca_id}.pem'
        return response
    
    @main_bp.route('/acme-settings')
    @login_required
    def acme_settings():
        """ACME集成设置页面"""
        # 这里应该获取当前用户的特定ID
        user_specific_id = current_user.id  # 实际应用中可能需要生成或使用特定的用户标识
        return render_template('main/acme_settings.html', current_year=2024, user_specific_id=user_specific_id)
    
    @main_bp.route('/cas')
    @login_required
    def ca_list():
        """CA列表页面"""
        # 获取当前用户的所有CA
        cas = CertificateAuthority.query.filter_by(user_id=current_user.id).order_by(CertificateAuthority.created_at.desc()).all()
        return render_template('main/ca_list.html', current_year=2024, cas=cas)
    
    @main_bp.route('/certificates')
    @login_required
    def certificate_list():
        """证书列表页面"""
        # 获取当前用户的所有证书
        certificates = Certificate.query.filter_by(user_id=current_user.id).order_by(Certificate.created_at.desc()).all()
        return render_template('main/certificate_list.html', current_year=2024, certificates=certificates)

# 这里需要导入main_bp，以便初始化路由
# from app.main import main_bp
# init_routes(main_bp)