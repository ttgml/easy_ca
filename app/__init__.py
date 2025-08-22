import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# 初始化数据库对象
db = SQLAlchemy()

# 初始化Flask-Migrate
migrate = Migrate()

# 初始化Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'auth.login'  # 设置登录视图
login_manager.login_message_category = 'info'  # 设置登录消息类别
login_manager.login_message = '请先登录以访问此页面。'  # 设置登录消息

@login_manager.user_loader
def load_user(user_id):
    """用户加载器函数，用于Flask-Login"""
    from app.models import User
    return User.query.get(int(user_id))

def create_app(config_name=None):
    """应用工厂函数"""
    app = Flask(__name__)
    
    # 加载配置
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'development')
    
    # 根据配置名称加载不同的配置
    app.config.from_object(f'app.config.{config_name.capitalize()}Config')
    
    # 初始化数据库
    db.init_app(app)
    
    # 初始化Flask-Migrate
    migrate.init_app(app, db)
    
    # 初始化Flask-Login
    login_manager.init_app(app)
    
    # 注册蓝图
    from app.main import main_bp
    app.register_blueprint(main_bp)
    
    # 注册auth蓝图
    from app.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    # 注册ACME蓝图
    from app.acme import acme_bp
    app.register_blueprint(acme_bp, url_prefix='/acme')
    
    # 注册ACME挑战处理蓝图
    from app.acme.challenge_routes import challenge_bp
    app.register_blueprint(challenge_bp)
    
    return app