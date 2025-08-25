# EasyCA - 私有证书颁发机构管理平台

**EasyCA** 是一个现代化的、开源的SaaS平台，旨在让您轻松地创建和管理自己的私有公钥基础设施（PKI）。通过直观的Web界面或完全自动化的ACME客户端，为您的基础设施、内部网络和物联网设备签发可信的TLS证书。

---

## ✨ 核心特性

- **🔐 完整的PKI生命周期管理**: 轻松创建和管理**根证书颁发机构（Root CA）** 和**中间证书颁发机构（Intermediate CA）**。
- **🤖 全自动化ACME集成**: 与 `acme.sh` 等客户端完美兼容，支持HTTP-01挑战，实现证书的自动申请和续期。
- **🖥 直观的Web管理界面**: 通过清晰的UI创建、查看、吊销和下载证书与CA。
- **🌳 可视化证书层次结构**: 在仪表板中清晰查看您的根CA、中间CA和叶证书之间的信任链关系。
- **⚙️ 灵活的高级选项**:
  - 为高级用户提供完整的密钥算法（RSA/ECC）和参数自定义。
  - 自定义密钥用法（Key Usage）、扩展密钥用法（Extended Key Usage）、CRL分发点等X.509扩展字段。
- **📄 证书吊销列表（CRL）**: 自动生成并发布CRL，确保您可以及时撤销不再信任的证书。
- **🔌 RESTful API**: 提供完整的API支持，便于与您的CI/CD流水线和自动化工具集成。

---

## 🚀 快速开始

### 前提条件

- Python 3.8+
- SQLite
- `uv` 包管理器

### 安装与部署

1.  **克隆仓库**
    ```bash
    git clone https://github.com/ttgml/easy_ca.git
    cd easy_ca
    ```

2.  **创建虚拟环境并安装依赖**
    ```bash
    # 使用 uv 安装依赖
    uv sync
    uv install
    ```

3.  **配置环境变量**
    复制示例环境文件并根据你的设置进行修改：
    ```bash
    cp .env.example .env
    ```
    编辑 `.env` 文件，设置你的数据库连接、密钥等

4.  **初始化数据库**
    ```bash
    flask db migrate
    flask db upgrade
    python init_db.py
    ```

5.  **运行应用**
    ```bash
    # 对于开发环境，请使用 python 运行
    python run.py
    ```
    访问 `http://localhost:5000` 并使用您的凭据注册第一个账户。

---

## 📖 基本使用指南

### 1. 创建您的根证书机构（Root CA）
1.  登录后，进入仪表板。
2.  点击“创建新CA”。
3.  选择“根CA”类型。
4.  填写基础信息（名称、通用名等），或展开“高级选项”配置密钥算法和主题信息。
5.  点击“创建”。您的私有PKI的信任锚点现已就绪！

### 2. 手动签发证书
1.  登录后，进入仪表板。
2.  点击“签发新证书”。
3.  选择您要签发证书的CA。
4.  填写证书信息（域名、通用名等），或展开“高级选项”配置密钥算法、扩展密钥用法等。
5.  点击“创建”。您的证书现已签发！

### 3. 使用 ACME 自动化签发证书
EasyCA 支持 ACME v2 协议，可与 `acme.sh` 等客户端无缝协作。

**使用 `acme.sh` 申请证书示例：**

```bash
# 将以下命令中的目录URL替换为您平台中提供的专属ACME目录URL
export EasyCA_SERVER="http://your-EasyCA-instance.com/acme/<cert_id>/directory"

# 使用 HTTP 挑战
acme.sh --server $EasyCA_SERVER \
        --issue -d example.com \
        --webroot /path/to/webroot

```