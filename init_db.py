from app import create_app
from app.models import User, CertificateAuthority, Certificate
from flask_migrate import upgrade
import os

# 创建应用实例
app = create_app()

# 在应用上下文中初始化数据库
def init_db():
    with app.app_context():
        # 应用所有数据库迁移
        upgrade()
        print("数据库迁移已应用！")
        
        # 检查是否存在管理员用户
        if not User.query.filter_by(username='admin').first():
            # 创建管理员用户
            admin = User()
            admin.username = 'admin'
            admin.email = 'admin@example.com'
            admin.set_password('admin123')  # 注意：在实际生产环境中不应硬编码密码
            admin.save()
            print("管理员用户已创建：username=admin, password=admin123")

if __name__ == "__main__":
    init_db()