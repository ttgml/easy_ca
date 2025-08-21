from flask import Blueprint

# 创建ACME蓝图
acme_bp = Blueprint('acme', __name__)

# 导入路由模块以初始化路由
from app.acme import routes