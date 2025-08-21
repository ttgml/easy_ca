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
        self.is_active = False
        self.save()
        # 或者直接物理删除：db.session.delete(self)
    
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
    
    def set_password(self, password):
        """设置用户密码（哈希处理）"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """验证用户密码"""
        return check_password_hash(self.password_hash, password)

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