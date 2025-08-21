# 数据库迁移使用说明

## 初始化数据库

1. 删除旧的数据库文件（如果存在）：
   ```bash
   rm app/data-dev.sqlite
   ```

2. 初始化迁移环境（如果尚未初始化）：
   ```bash
   flask --app app db init
   ```

3. 生成初始迁移文件：
   ```bash
   flask --app app db migrate -m "Initial migration"
   ```

4. 应用迁移创建数据库表：
   ```bash
   flask --app app db upgrade
   ```

或者，可以使用init_db.py脚本自动完成上述步骤：
```bash
python init_db.py
```

## 添加新字段或修改表结构

1. 修改模型文件（app/models.py）

2. 生成新的迁移文件：
   ```bash
   flask --app app db migrate -m "描述你的更改"
   ```

3. 检查生成的迁移文件是否正确（在migrations/versions/目录中）

4. 应用迁移：
   ```bash
   flask --app app db upgrade
   ```

## 查看迁移状态

```bash
flask --app app db current
```

## 回滚迁移

```bash
flask --app app db downgrade
```