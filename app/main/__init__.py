from flask import Blueprint

# 创建main蓝图
def create_main_blueprint():
    main_bp = Blueprint('main', __name__)
    
    # 导入路由
    from app.main.routes import init_routes
    init_routes(main_bp)
    
    return main_bp

# 初始化main蓝图
main_bp = create_main_blueprint()