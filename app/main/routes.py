def init_routes(main_bp):
    """初始化main蓝图的路由"""
    from flask import render_template, redirect, url_for, flash, request
    from flask_login import login_required, current_user
    from app.models import CertificateAuthority, Certificate
    from datetime import datetime, timedelta
    import uuid
    
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
        
        # 获取最近的CA和证书
        recent_cas = CertificateAuthority.query.filter_by(user_id=current_user.id).order_by(CertificateAuthority.created_at.desc()).limit(5).all()
        recent_certs = Certificate.query.filter_by(user_id=current_user.id).order_by(Certificate.created_at.desc()).limit(5).all()
        
        return render_template('main/dashboard.html', 
                             current_year=2024, 
                             ca_count=ca_count, 
                             cert_count=cert_count, 
                             active_certs=active_certs, 
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
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import serialization
                import datetime
                
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
                subject = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                ])
                
                # 添加组织信息（如果有）
                if organization:
                    subject = x509.Name([
                        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                    ])
                
                # 因为是自签名证书，颁发者和主体相同
                issuer = subject
                
                # 设置证书有效期
                valid_from = datetime.datetime.utcnow()
                valid_to = valid_from + datetime.timedelta(days=365 * validity_years)
                
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
                
                # 创建CA记录
                new_ca = CertificateAuthority(
                    name=name,
                    common_name=common_name,
                    organization=organization,
                    validity_years=validity_years,
                    key_type=key_type,
                    key_size=key_size,
                    certificate=certificate_pem,
                    user_id=current_user.id
                )
                
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
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import serialization
                import datetime
                
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
                valid_from = datetime.datetime.utcnow()
                valid_to = valid_from + datetime.timedelta(days=validity_days)
                
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
        
        return render_template('main/certificate_detail.html', current_year=2024, cert=cert, ca=ca)
    
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
            cert.revoked_at = datetime.utcnow()
            cert.revocation_reason = request.form.get('revocation_reason', 'Unspecified')
            cert.save()
            
            flash('证书已成功吊销', 'success')
        except Exception as e:
            flash(f'吊销证书失败：{str(e)}', 'danger')
        
        return redirect(url_for('main.certificate_detail', cert_id=cert_id))

# 这里需要导入main_bp，以便初始化路由
# from app.main import main_bp
# init_routes(main_bp)