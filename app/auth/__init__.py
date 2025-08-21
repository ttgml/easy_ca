from flask import Blueprint

# 创建auth蓝图
auth_bp = Blueprint('auth', __name__, template_folder='templates')

# 导入路由模块，确保路由被注册到蓝图
from app.auth import routes