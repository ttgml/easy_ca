from flask import render_template, redirect, url_for, flash, request, Response
from flask_login import login_required, current_user
from app.models import CertificateAuthority, Certificate
from app import db
from datetime import datetime, timedelta, timezone
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, x25519, x448
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
                             current_year=2025, 
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
        # 获取当前用户的所有活跃CA，用于父CA选择
        active_cas = CertificateAuthority.query.filter_by(user_id=current_user.id, status='active').all()
        
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
            ca_type = request.form.get('ca_type', 'root')  # CA类型：root(根CA) 或 intermediate(中间CA)
            parent_ca_id = request.form.get('parent_ca_id')  # 父CA ID（仅中间CA需要）

            # 根据密钥类型获取相应参数
            if key_type == 'RSA':
                key_size = int(request.form.get('key_size', 4096))
                ec_curve = None
            else:  # ECC
                key_size = None
                ec_curve = request.form.get('ecc_curve', 'P-384')
    
            # 获取高级选项数据
            hash_algorithm = request.form.get('hash_algorithm', 'SHA-256')
            path_length = request.form.get('path_length')
            key_usage = request.form.getlist('key_usage')
            crl_distribution_points = request.form.get('crl_distribution_points')
            authority_info_access = request.form.get('authority_info_access')
    
            # 简单的表单验证
            if not name or not common_name:
                flash('请填写CA名称和通用名称', 'danger')
                return redirect(url_for('main.new_ca'))
            
            # 如果是中间CA，需要选择父CA
            if ca_type == 'intermediate' and not parent_ca_id:
                flash('请选择父CA', 'danger')
                return redirect(url_for('main.new_ca'))
    
            # 使用证书生成器创建CA
            try:
                from app.lib.certificate_generator import CertificateGenerator
    
                # 生成密钥对
                if key_type == 'RSA':
                    private_key = CertificateGenerator.generate_key_pair(key_type=key_type, key_size=key_size)
                else:  # ECC
                    private_key = CertificateGenerator.generate_key_pair(key_type=key_type, ec_curve=ec_curve)    
                # 创建CA证书
                certificate, valid_from, valid_to = CertificateGenerator.create_ca_certificate(
                    private_key=private_key,
                    name=name,
                    common_name=common_name,
                    organization=organization,
                    organizational_unit=organizational_unit,
                    country=country,
                    state=state,
                    locality=locality,
                    validity_years=validity_years,
                    hash_algorithm=hash_algorithm,
                    path_length=path_length,
                    key_usage=key_usage,
                    crl_distribution_points=crl_distribution_points,
                    authority_info_access=authority_info_access
                )
    
                # 转换为PEM格式
                private_key_pem, certificate_pem = CertificateGenerator.convert_to_pem(private_key, certificate)
    
                # 提取证书序列号
                serial_number = str(certificate.serial_number)
    
                # 创建CA记录
                new_ca = CertificateAuthority(
                    name=request.form.get('name'),
                    common_name=request.form.get('common_name'),
                    organization=request.form.get('organization'),
                    organizational_unit=request.form.get('organizational_unit'),  # 组织单位 (OU)
                    country=request.form.get('country'),                          # 国家 (C)
                    state=request.form.get('state'),                              # 省/州 (ST)
                    locality=request.form.get('locality')                         # 城市 (L)
                )
                
                # 设置CA的其他属性
                new_ca.serial_number = serial_number
                new_ca.valid_from = valid_from
                new_ca.valid_to = valid_to
                new_ca.certificate = certificate_pem
                new_ca.user_id = current_user.id
                
                # 设置CA的其他属性
                new_ca.validity_years = validity_years
                new_ca.key_type = key_type
                if key_type == 'RSA':
                    new_ca.key_size = key_size
                else:  # ECC
                    new_ca.ec_curve = ec_curve
                    new_ca.key_size = None  # 对于ECC，不使用key_size字段                # 设置高级选项属性
                new_ca.hash_algorithm = hash_algorithm
                new_ca.path_length = int(path_length) if path_length else None
                new_ca.key_usage = ','.join(key_usage) if key_usage else None
                new_ca.crl_distribution_points = crl_distribution_points
                new_ca.authority_info_access = authority_info_access
    
                # 如果是中间CA，设置父CA关系
                if ca_type == 'intermediate' and parent_ca_id:
                    parent_ca = CertificateAuthority.query.get(parent_ca_id)
                    if parent_ca and parent_ca.user_id == current_user.id:
                        new_ca.parent_id = parent_ca_id
    
                # 加密存储私钥
                new_ca.set_private_key(private_key_pem)
    
                # 保存到数据库
                new_ca.save()
    
                flash('证书颁发机构创建成功', 'success')
                return redirect(url_for('main.ca_detail', ca_id=new_ca.id))
            except Exception as e:
                flash(f'创建证书颁发机构失败：{str(e)}', 'danger')
                return redirect(url_for('main.new_ca'))
    
        return render_template('main/new_ca.html', current_year=2024, active_cas=active_cas)
    
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
            # 获取基础表单数据
            ca_id = request.form.get('ca_id')
            common_name = request.form.get('common_name')
            sans_text = request.form.get('sans')
            validity_days = int(request.form.get('validity_days', 365))
    
            # 获取高级选项数据
            # 密钥设置
            key_type = request.form.get('key_type', 'RSA')
            key_size = int(request.form.get('key_size', 2048))
            ec_curve = request.form.get('ec_curve', 'P-256')
            hash_algorithm = request.form.get('hash_algorithm', 'SHA-256')
    
            # 证书属性
            key_usage = request.form.getlist('key_usage')
            extended_key_usage = request.form.getlist('extended_key_usage')
            is_ca = request.form.get('is_ca') == 'on'
            path_length = request.form.get('path_length')
    
            # 信息扩展
            crl_distribution_points = request.form.get('crl_distribution_points')
            authority_info_access = request.form.get('authority_info_access')
    
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
                from app.lib.certificate_generator import CertificateGenerator
    
                # 生成证书密钥对
                cert_private_key = CertificateGenerator.generate_key_pair(
                    key_type=key_type,
                    key_size=key_size,
                    ec_curve=ec_curve
                )
    
                # 解析CA私钥和证书
                ca_private_key_pem = ca.get_private_key()
                ca_private_key = serialization.load_pem_private_key(
                    ca_private_key_pem.encode(),
                    password=None
                )
    
                ca_cert_pem = ca.certificate
                ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    
                # 创建证书
                certificate, valid_from, valid_to = CertificateGenerator.create_end_entity_certificate(
                    cert_private_key=cert_private_key,
                    ca_private_key=ca_private_key,
                    ca_cert=ca_cert,
                    common_name=common_name,
                    sans=sans,
                    validity_days=validity_days,
                    hash_algorithm=hash_algorithm,
                    key_usage=key_usage,
                    extended_key_usage=extended_key_usage,
                    crl_distribution_points=crl_distribution_points,
                    authority_info_access=authority_info_access
                )
    
                # 转换为PEM格式
                cert_private_key_pem, certificate_pem = CertificateGenerator.convert_to_pem(
                    cert_private_key, certificate
                )
    
                # 生成唯一序列号
                serial_number = str(uuid.uuid4())
    
                # 创建证书记录
                new_cert = Certificate(
                    common_name=request.form.get('common_name'),
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
        
        # 初始化指纹变量
        cert_sha256_fingerprint = None
        public_key_sha256_fingerprint = None
        
        # 解析证书信息
        try:
            # 加载证书
            certificate = x509.load_pem_x509_certificate(cert.certificate.encode())
            
            # 计算证书SHA-256指纹
            cert_sha256_fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
            
            # 计算公钥SHA-256指纹
            public_key = certificate.public_key()
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_key_sha256_fingerprint = hashes.Hash(hashes.SHA256())
            public_key_sha256_fingerprint.update(public_key_der)
            public_key_sha256_fingerprint = public_key_sha256_fingerprint.finalize().hex()
            
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
        
        return render_template('main/certificate_detail.html', current_year=2024, cert=cert, ca=ca, 
                             issuer_str=issuer_str, subject_str=subject_str, extensions_str=extensions_str, 
                             show_acme_guide=show_acme_guide, 
                             cert_sha256_fingerprint=cert_sha256_fingerprint,
                             public_key_sha256_fingerprint=public_key_sha256_fingerprint)
    
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

    @main_bp.route('/certificate/<int:cert_id>/delete', methods=['POST'])
    @login_required
    def delete_certificate(cert_id):
        """删除证书"""
        # 获取证书信息
        cert = Certificate.query.get_or_404(cert_id)
        
        # 检查是否为当前用户的证书
        if cert.user_id != current_user.id:
            flash('无权删除该证书', 'danger')
            return redirect(url_for('main.dashboard'))
        
        try:
            # 删除证书
            cert.delete()
            
            flash('证书已成功删除', 'success')
        except Exception as e:
            flash(f'删除证书失败：{str(e)}', 'danger')
        
        return redirect(url_for('main.certificate_list'))

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


    @main_bp.route('/ca/<int:ca_id>/delete', methods=['POST'])
    @login_required
    def delete_ca(ca_id):
        """删除CA"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权删除该CA', 'danger')
            return redirect(url_for('main.dashboard'))
        
        try:
            # 删除由该CA颁发的所有证书
            certificates = Certificate.query.filter_by(ca_id=ca_id).all()
            for cert in certificates:
                cert.delete()
            
            # 删除CA
            ca.delete()
            
            flash('CA已成功删除', 'success')
        except Exception as e:
            flash(f'删除CA失败：{str(e)}', 'danger')
        
        return redirect(url_for('main.ca_list'))

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
    
    @main_bp.route('/ca/<int:ca_id>/download/certificate')
    @login_required
    def download_ca_certificate(ca_id):
        """下载CA证书文件"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查是否为当前用户的CA
        if ca.user_id != current_user.id:
            flash('无权下载该证书', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # 创建响应对象
        response = Response(ca.certificate, mimetype='application/x-pem-file')
        response.headers['Content-Disposition'] = f'attachment; filename=ca-certificate-{ca_id}.pem'
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
        # 获取当前用户的所有CA，按创建时间降序排列
        cas = CertificateAuthority.query.filter_by(user_id=current_user.id).order_by(CertificateAuthority.created_at.desc()).all()
        return render_template('main/ca_list.html', current_year=2024, cas=cas)
    
    @main_bp.route('/certificates')
    @login_required
    def certificate_list():
        """证书列表页面"""
        # 获取查询参数
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '', type=str)
        sort_by = request.args.get('sort_by', 'created_at', type=str)
        sort_order = request.args.get('sort_order', 'desc', type=str)
        
        # 构建查询
        query = Certificate.query.filter_by(user_id=current_user.id)
        
        # 添加搜索条件
        if search:
            query = query.join(CertificateAuthority).filter(
                db.or_(
                    Certificate.common_name.contains(search),
                    CertificateAuthority.name.contains(search)
                )
            )
        
        # 添加排序
        if sort_by == 'common_name':
            order_clause = Certificate.common_name.asc() if sort_order == 'asc' else Certificate.common_name.desc()
        elif sort_by == 'issuer':
            order_clause = CertificateAuthority.name.asc() if sort_order == 'asc' else CertificateAuthority.name.desc()
        elif sort_by == 'valid_from':
            order_clause = Certificate.valid_from.asc() if sort_order == 'asc' else Certificate.valid_from.desc()
        elif sort_by == 'valid_to':
            order_clause = Certificate.valid_to.asc() if sort_order == 'asc' else Certificate.valid_to.desc()
        else:  # created_at
            order_clause = Certificate.created_at.asc() if sort_order == 'asc' else Certificate.created_at.desc()
        
        query = query.order_by(order_clause)
        
        # 分页查询（每页10条记录）
        certificates = query.paginate(page=page, per_page=10, error_out=False)
        
        return render_template('main/certificate_list.html', current_year=2024, certificates=certificates, 
                             search=search, sort_by=sort_by, sort_order=sort_order)
    
    @main_bp.route('/ca/import', methods=['GET', 'POST'])
    @login_required
    def import_ca():
        """导入CA页面"""
        if request.method == 'POST':
            # 处理导入CA的请求
            name = request.form.get('name')
            certificate_file = request.files.get('certificate')
            private_key_file = request.files.get('private_key')
            
            if not name or not certificate_file or not private_key_file:
                flash('请提供所有必需的信息', 'danger')
                return redirect(url_for('main.import_ca'))
            
            try:
                # 读取证书和私钥文件
                certificate_data = certificate_file.read().decode('utf-8')
                private_key_data = private_key_file.read().decode('utf-8')
                
                # 解析证书
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                certificate = x509.load_pem_x509_certificate(certificate_data.encode(), default_backend())
                
                # 解析私钥
                from cryptography.hazmat.primitives import serialization
                private_key = serialization.load_pem_private_key(private_key_data.encode(), password=None, backend=default_backend())
                
                # 验证证书和私钥是否匹配
                # 对于某些密钥类型（如Ed25519），public_numbers()方法可能不可用
                try:
                    # 对于支持public_numbers()的密钥类型，进行验证
                    cert_public_numbers = certificate.public_key().public_numbers()
                    private_key_public_numbers = private_key.public_key().public_numbers()
                    if cert_public_numbers != private_key_public_numbers:
                        flash('证书和私钥不匹配', 'danger')
                        return redirect(url_for('main.import_ca'))
                except AttributeError:
                    # 对于不支持public_numbers()的密钥类型（如Ed25519, X25519, Ed448, X448），使用其他方式验证
                    # 这里我们检查公钥的字节表示是否匹配
                    # 首先检查密钥类型是否支持Raw编码
                    try:
                        cert_public_key_bytes = certificate.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        private_key_public_key_bytes = private_key.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        )
                        if cert_public_key_bytes != private_key_public_key_bytes:
                            flash('证书和私钥不匹配', 'danger')
                            return redirect(url_for('main.import_ca'))
                    except ValueError:
                        # 如果Raw编码不支持，则跳过验证
                        pass
                
                # 确定密钥类型
                key_type = 'RSA'
                if isinstance(private_key, rsa.RSAPrivateKey):
                    key_type = 'RSA'
                elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                    key_type = 'ECC'
                elif isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey)):
                    key_type = 'Ed25519/X25519/Ed448/X448'
                
                # 确定密钥大小
                key_size = 2048  # 默认值
                if hasattr(private_key, 'key_size') and private_key.key_size is not None:
                    key_size = private_key.key_size
                elif isinstance(private_key, (ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey)):
                    key_size = 256  # Ed25519和X25519的位数
                elif isinstance(private_key, (ed448.Ed448PrivateKey, x448.X448PrivateKey)):
                    key_size = 448  # Ed448和X448的位数
                
                # 从证书中提取信息
                common_name = ''
                organization = None
                organizational_unit = None
                country = None
                state = None
                locality = None
                
                # 提取证书主题信息
                subject_attrs = certificate.subject
                for attr in subject_attrs:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        common_name = attr.value
                    elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                        organization = attr.value
                    elif attr.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                        organizational_unit = attr.value
                    elif attr.oid == x509.NameOID.COUNTRY_NAME:
                        country = attr.value
                    elif attr.oid == x509.NameOID.STATE_OR_PROVINCE_NAME:
                        state = attr.value
                    elif attr.oid == x509.NameOID.LOCALITY_NAME:
                        locality = attr.value
                
                # 计算有效期年数
                validity_years = (certificate.not_valid_after - certificate.not_valid_before).days // 365
                
                # 创建新的CA对象
                ca = CertificateAuthority(
                    name=request.form.get('name'),
                    common_name=common_name,
                    organization=organization,
                    organizational_unit=organizational_unit,
                    country=country,
                    state=state,
                    locality=locality,
                    validity_years=validity_years,
                    valid_from=certificate.not_valid_before,
                    valid_to=certificate.not_valid_after,
                    serial_number=str(certificate.serial_number),
                    certificate=certificate_data,
                    user_id=current_user.id
                )
                
                # 设置密钥类型和大小
                ca.key_type = key_type
                ca.key_size = key_size
                
                # 设置私钥
                ca.set_private_key(private_key_data)
                
                # 保存CA
                ca.save()
                
                flash('CA导入成功', 'success')
                return redirect(url_for('main.ca_detail', ca_id=ca.id))
            except Exception as e:
                flash(f'导入CA失败：{str(e)}', 'danger')
                return redirect(url_for('main.import_ca'))
        
        return render_template('main/import_ca.html', current_year=2024)

# 这里需要导入main_bp，以便初始化路由
# from app.main import main_bp
# init_routes(main_bp)