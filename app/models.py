from datetime import datetime
from app import db
import os
from cryptography.fernet import Fernet
import base64
import json
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin  # 添加UserMixin


class BaseModel(db.Model):
    """基础模型，包含通用字段"""
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def save(self):
        """保存模型实例"""
        db.session.add(self)
        db.session.commit()
        return self
    
    def delete(self):
        """删除模型实例"""
        # 直接物理删除
        db.session.delete(self)
        db.session.commit()
    
    def update(self, **kwargs):
        """更新模型实例属性"""
        for key, value in kwargs.items():
            if hasattr(self, key) and key != 'id':
                setattr(self, key, value)
        self.save()
        return self

# 获取加密密钥（在实际生产环境中应该从环境变量或安全的密钥管理系统获取）
def get_encryption_key():
    # 在开发环境下使用默认密钥，生产环境应该从环境变量中获取
    key = os.environ.get('ENCRYPTION_KEY')
    if not key:
        # 这只是开发环境的临时方案
        key = 'dev_key_which_should_be_changed_in_production'
        # 确保密钥长度适合Fernet
        key = base64.urlsafe_b64encode(key.ljust(32)[:32].encode())
    else:
        key = base64.urlsafe_b64decode(key)
    return key

# 创建加密器实例
cipher_suite = Fernet(get_encryption_key())

# 用户模型
class User(BaseModel, UserMixin):  # 继承UserMixin
    """用户模型，存储用户账户信息"""
    __tablename__ = 'users'
    
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # 关系：一个用户可以有多个CA
    certificate_authorities = db.relationship('CertificateAuthority', backref='user', lazy=True)
    # 关系：一个用户可以有多个证书
    certificates = db.relationship('Certificate', backref='user', lazy=True)
    # 关系：一个用户可以有多个ACME账户
    acme_accounts = db.relationship('ACMEAccount', backref='user', lazy=True)
    
    def set_password(self, password):
        """设置用户密码（哈希处理）"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """验证用户密码"""
        return check_password_hash(self.password_hash, password)

# ACME账户模型
class ACMEAccount(BaseModel):
    """ACME账户模型，存储ACME客户端的账户信息"""
    __tablename__ = 'acme_accounts'
    
    # ACME账户ID（由ACME客户端提供）
    account_id = db.Column(db.String(255), unique=True, nullable=False)
    
    # 用户外键
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # 账户状态
    status = db.Column(db.String(20), default='valid')  # valid, deactivated, revoked
    
    # 账户密钥ID（Key ID）
    key_id = db.Column(db.Text, nullable=False)
    
    # 完整的JWK（JSON Web Key）
    jwk = db.Column(db.Text, nullable=True)
    
    # 账户联系信息
    contact = db.Column(db.Text)  # JSON格式存储联系信息
    
    # 账户条款同意状态
    terms_of_service_agreed = db.Column(db.Boolean, default=False)
    
    # 账户创建时间
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 账户更新时间
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关系：一个ACME账户可以有多个订单
    orders = db.relationship('ACMEOrder', backref='account', lazy=True)

# ACME订单模型
class ACMEOrder(BaseModel):
    """ACME订单模型，存储证书申请订单信息"""
    __tablename__ = 'acme_orders'
    
    # 订单ID
    order_id = db.Column(db.String(255), unique=True, nullable=False)
    
    # ACME账户外键
    account_id = db.Column(db.Integer, db.ForeignKey('acme_accounts.id'), nullable=False)
    
    # CA外键
    ca_id = db.Column(db.Integer, db.ForeignKey('certificate_authorities.id'), nullable=False)
    
    # 订单状态
    status = db.Column(db.String(20), default='pending')  # pending, ready, processing, valid, invalid
    
    # 授权的域名（JSON格式存储）
    domains = db.Column(db.Text, nullable=False)
    
    # 订单创建时间
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 订单过期时间
    expires_at = db.Column(db.DateTime)
    
    # 证书序列号
    certificate_serial = db.Column(db.String(255))
    
    # 最终化URL
    finalize_url = db.Column(db.String(500))
    
    # 证书URL
    certificate_url = db.Column(db.String(500))
    
    # 关系：一个订单可以有多个授权
    authorizations = db.relationship('ACMEAuthorization', backref='order', lazy=True)

# ACME授权模型
class ACMEAuthorization(BaseModel):
    """ACME授权模型，存储域名验证授权信息"""
    __tablename__ = 'acme_authorizations'
    
    # 授权ID
    authz_id = db.Column(db.String(255), unique=True, nullable=False)
    
    # 订单外键
    order_id = db.Column(db.Integer, db.ForeignKey('acme_orders.id'), nullable=False)
    
    # 域名
    domain = db.Column(db.String(255), nullable=False)
    
    # 授权状态
    status = db.Column(db.String(20), default='pending')  # pending, valid, invalid, deactivated, expired, revoked
    
    # 授权过期时间
    expires_at = db.Column(db.DateTime)
    
    # 关系：一个授权可以有多个挑战
    challenges = db.relationship('ACMEChallenge', backref='authorization', lazy=True)

# ACME挑战模型
class ACMEChallenge(BaseModel):
    """ACME挑战模型，存储验证挑战信息"""
    __tablename__ = 'acme_challenges'
    
    # 挑战ID
    challenge_id = db.Column(db.String(255), unique=True, nullable=False)
    
    # 授权外键
    authz_id = db.Column(db.Integer, db.ForeignKey('acme_authorizations.id'), nullable=False)
    
    # 挑战类型
    type = db.Column(db.String(50), nullable=False)  # http-01, dns-01, tls-alpn-01
    
    # 挑战状态
    status = db.Column(db.String(20), default='pending')  # pending, processing, valid, invalid
    
    # 挑战令牌
    token = db.Column(db.String(255), nullable=False)
    
    # 密钥授权
    key_authorization = db.Column(db.Text)
    
    # 验证时间
    validated_at = db.Column(db.DateTime)

# ACME Nonce模型
class ACMENonce(BaseModel):
    """ACME Nonce模型，存储ACME协议中的nonce值"""
    __tablename__ = 'acme_nonces'
    
    # Nonce值
    nonce = db.Column(db.String(255), unique=True, nullable=False)
    
    # Nonce过期时间
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # 错误信息
    error = db.Column(db.Text)

# 证书颁发机构模型
class CertificateAuthority(BaseModel):
    """证书颁发机构模型"""
    __tablename__ = 'certificate_authorities'
    
    name = db.Column(db.String(100), nullable=False)
    common_name = db.Column(db.String(255), nullable=False)
    organization = db.Column(db.String(100))
    organizational_unit = db.Column(db.String(100))  # 组织单位 (OU)
    country = db.Column(db.String(2))               # 国家 (C)
    state = db.Column(db.String(100))               # 省/州 (ST)
    locality = db.Column(db.String(100))            # 城市 (L)
    validity_years = db.Column(db.Integer, default=10)
    
    # 新增：签名散列算法
    hash_algorithm = db.Column(db.String(20), default='SHA-256')
    
    # 新增：路径长度约束
    path_length = db.Column(db.Integer)
    
    # 新增：密钥用法
    key_usage = db.Column(db.String(255))
    
    # 新增：CRL分发点
    crl_distribution_points = db.Column(db.Text)
    
    # 新增：权威信息访问
    authority_info_access = db.Column(db.Text)
    
    # 有效期
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=False)
    
    # 自引用关系，支持CA层次结构
    parent_id = db.Column(db.Integer, db.ForeignKey('certificate_authorities.id'))
    children = db.relationship('CertificateAuthority', backref=db.backref('parent', remote_side='CertificateAuthority.id'))
    
    # 密钥类型和大小
    key_type = db.Column(db.String(20), default='RSA')  # RSA或ECC
    key_size = db.Column(db.Integer, default=2048)  # 2048/4096或ec256
    
    # 序列号
    serial_number = db.Column(db.String(100), unique=True)
    
    # 加密存储的证书和私钥
    certificate = db.Column(db.Text, nullable=False)  # PEM格式的CA证书
    private_key_encrypted = db.Column(db.Text, nullable=False)  # 加密的私钥
    
    # 用户外键
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # 状态
    status = db.Column(db.String(20), default='active')  # active, revoked
    revoked_at = db.Column(db.DateTime)
    revocation_reason = db.Column(db.String(255))
    
    # ACME settings
    acme_enabled = db.Column(db.Boolean, default=False)
    auto_approve = db.Column(db.Boolean, default=False)
    http01_enabled = db.Column(db.Boolean, default=True)
    dns01_enabled = db.Column(db.Boolean, default=False)
    
    # 关系：一个CA可以有多个ACME订单
    acme_orders = db.relationship('ACMEOrder', backref='ca', lazy=True)
    
    def set_private_key(self, private_key):
        """加密并存储私钥"""
        # 确保私钥是字节串
        if isinstance(private_key, str):
            private_key = private_key.encode()
        # 加密私钥
        encrypted_key = cipher_suite.encrypt(private_key)
        # 存储为base64编码的字符串
        self.private_key_encrypted = encrypted_key.decode()
    
    def get_private_key(self):
        """解密并获取私钥"""
        # 解密私钥
        encrypted_key = self.private_key_encrypted.encode()
        decrypted_key = cipher_suite.decrypt(encrypted_key)
        return decrypted_key.decode()

# 证书模型
class Certificate(BaseModel):
    """证书模型"""
    __tablename__ = 'certificates'
    
    common_name = db.Column(db.String(255), nullable=False)
    sans = db.Column(db.Text)  # 以JSON字符串存储Subject Alternative Names
    serial_number = db.Column(db.String(100), unique=True, nullable=False)
    
    # 加密存储的证书和私钥
    certificate = db.Column(db.Text, nullable=False)  # PEM格式的证书
    private_key_encrypted = db.Column(db.Text)  # 加密的私钥（可选）
    
    # 外键
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ca_id = db.Column(db.Integer, db.ForeignKey('certificate_authorities.id'), nullable=False)
    
    # 状态和有效期
    status = db.Column(db.String(20), default='valid')  # valid, expired, revoked
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime)
    revocation_reason = db.Column(db.String(255))
    
    # 是否为CA证书
    is_ca = db.Column(db.Boolean, default=False)
    
    # 关系：证书由哪个CA签发
    ca = db.relationship('CertificateAuthority', backref='certificates')
    
    def set_private_key(self, private_key):
        """加密并存储私钥"""
        if private_key:
            # 确保私钥是字节串
            if isinstance(private_key, str):
                private_key = private_key.encode()
            # 加密私钥
            encrypted_key = cipher_suite.encrypt(private_key)
            # 存储为base64编码的字符串
            self.private_key_encrypted = encrypted_key.decode()
    
    def get_private_key(self):
        """解密并获取私钥"""
        if self.private_key_encrypted:
            # 解密私钥
            encrypted_key = self.private_key_encrypted.encode()
            decrypted_key = cipher_suite.decrypt(encrypted_key)
            return decrypted_key.decode()
        return None
    
    def set_sans(self, sans_list):
        """存储Subject Alternative Names列表为JSON字符串"""
        if sans_list:
            self.sans = json.dumps(sans_list)
    
    def get_sans(self):
        """获取Subject Alternative Names列表"""
        if self.sans:
            return json.loads(self.sans)
        return []
    
    def is_expiring_soon(self, days=30):
        """检查证书是否即将过期
        
        Args:
            days (int): 天数阈值，默认30天
            
        Returns:
            bool: 如果证书在指定天数内过期则返回True，否则返回False
        """
        if self.status != 'valid':
            return False
        
        from datetime import datetime, timedelta
        threshold_date = datetime.utcnow() + timedelta(days=days)
        return self.valid_to <= threshold_date