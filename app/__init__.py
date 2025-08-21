import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# 初始化数据库对象
db = SQLAlchemy()

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
    
    # 注册蓝图
    from app.main import main_bp
    app.register_blueprint(main_bp)
    
    return app