def init_routes(main_bp):
    """初始化main蓝图的路由"""
    
    @main_bp.route('/')
    @main_bp.route('/home')
    def home():
        """首页路由"""
        # 使用render_template函数渲染模板
        from flask import render_template
        # 传递当前年份给模板
        return render_template('main/home.html', current_year=2024)
    
    @main_bp.route('/about')
    def about():
        """关于页面路由"""
        from flask import render_template
        return render_template('main/about.html', current_year=2024)
    
    # 可以根据需要添加更多路由