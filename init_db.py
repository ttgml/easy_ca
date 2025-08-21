from app import create_app, db
from app.models import User, CertificateAuthority, Certificate
import os

# 创建应用实例
app = create_app()

# 在应用上下文中初始化数据库
def init_db():
    with app.app_context():
        # 创建所有表
        db.create_all()
        print("数据库表已创建成功！")
        
        # 检查是否存在管理员用户
        if not User.query.filter_by(username='admin').first():
            # 创建管理员用户
            admin = User(username='admin', email='admin@example.com')
            admin.set_password('admin123')  # 注意：在实际生产环境中不应硬编码密码
            admin.save()
            print("管理员用户已创建：username=admin, password=admin123")

if __name__ == "__main__":
    init_db()