from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app.auth import auth_bp
from app.models import User
from app import db

# 这里需要导入Flask-Login的相关功能，但在实际实现中，我们需要先在app/__init__.py中配置它

def init_auth_routes():
    """初始化认证相关路由"""
    
    @auth_bp.route('/register', methods=['GET', 'POST'])
    def register():
        """用户注册路由"""
        if request.method == 'POST':
            # 获取表单数据
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # 简单的表单验证
            if not username or not email or not password:
                flash('请填写所有必填字段', 'danger')
                return redirect(url_for('auth.register'))
            
            if password != confirm_password:
                flash('两次输入的密码不一致', 'danger')
                return redirect(url_for('auth.register'))
            
            # 检查用户名和邮箱是否已存在
            if User.query.filter_by(username=username).first():
                flash('用户名已存在', 'danger')
                return redirect(url_for('auth.register'))
            
            if User.query.filter_by(email=email).first():
                flash('邮箱已被注册', 'danger')
                return redirect(url_for('auth.register'))
            
            # 创建新用户
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            
            # 保存到数据库
            try:
                new_user.save()
                flash('注册成功，请登录', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                flash(f'注册失败：{str(e)}', 'danger')
                return redirect(url_for('auth.register'))
        
        return render_template('auth/register.html', current_year=2024)
    
    @auth_bp.route('/login', methods=['GET', 'POST'])
    def login():
        """用户登录路由"""
        if request.method == 'POST':
            # 获取表单数据
            username = request.form.get('username')
            password = request.form.get('password')
            remember = request.form.get('remember') == 'on'
            
            # 简单的表单验证
            if not username or not password:
                flash('请填写用户名和密码', 'danger')
                return redirect(url_for('auth.login'))
            
            # 查找用户
            user = User.query.filter_by(username=username).first()
            
            # 验证用户和密码
            if not user or not user.check_password(password):
                flash('用户名或密码错误', 'danger')
                return redirect(url_for('auth.login'))
            
            # 使用Flask-Login的login_user函数登录用户
            login_user(user, remember=remember)
            
            flash('登录成功', 'success')
            return redirect(url_for('main.dashboard'))
        
        return render_template('auth/login.html', current_year=2024)
    
    @auth_bp.route('/logout')
    def logout():
        """用户登出路由"""
        # 使用Flask-Login的logout_user函数登出用户
        logout_user()
        
        flash('已成功登出', 'info')
        return redirect(url_for('main.home'))

# 初始化路由
init_auth_routes()