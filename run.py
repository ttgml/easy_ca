from app import create_app
import os

# 创建Flask应用实例
app = create_app(os.getenv('FLASK_CONFIG', 'development'))

if __name__ == "__main__":
    # 运行应用
    app.run(
        host=os.getenv('FLASK_RUN_HOST', '127.0.0.1'),
        port=int(os.getenv('FLASK_RUN_PORT', '5000')),
        debug=os.getenv('FLASK_DEBUG', 'true').lower() == 'true'
    )
