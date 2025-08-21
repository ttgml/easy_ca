from datetime import datetime
from app import db

class BaseModel(db.Model):
    """基础模型，包含通用字段"""
    __abstract__ = True
    
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def save(self):
        """保存模型实例"""
        db.session.add(self)
        db.session.commit()
        return self
    
    def delete(self):
        """删除模型实例"""
        self.is_active = False
        self.save()
        # 或者直接物理删除：db.session.delete(self)
    
    def update(self, **kwargs):
        """更新模型实例属性"""
        for key, value in kwargs.items():
            if hasattr(self, key) and key != 'id':
                setattr(self, key, value)
        self.save()
        return self

# 这里可以根据需要添加更多具体的数据模型
# 例如：
# class User(BaseModel):
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)