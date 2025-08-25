import os
from datetime import timedelta

class Config:
    """基础配置类"""
    # 安全密钥
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    
    # 数据库配置
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 会话配置
    SESSION_COOKIE_NAME = 'easy_ca_session'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    # 其他通用配置
    DEBUG = False
    TESTING = False
    
    # 用户注册配置
    ALLOW_USER_REGISTRATION = os.environ.get('ALLOW_USER_REGISTRATION', 'True').lower() in ['true', '1', 'yes']


class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    # 开发环境使用SQLite数据库
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data-dev.sqlite')


class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    # 测试环境使用内存数据库
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite://'
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """生产环境配置"""
    # 生产环境使用环境变量指定的数据库URL
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # 如果是PostgreSQL数据库，需要修改连接池配置
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgresql://'):
        SQLALCHEMY_ENGINE_OPTIONS = {
            'pool_size': 10,
            'max_overflow': 20,
            'pool_timeout': 30,
            'pool_recycle': 1800
        }


# 配置映射，便于根据环境变量选择配置
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}