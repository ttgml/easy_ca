from flask import Blueprint, request, current_app
from app.models import ACMEChallenge, ACMEAuthorization, ACMEOrder, CertificateAuthority, ACMEAccount
from app.acme.utils import compute_key_authorization, generate_thumbprint

# 创建用于处理ACME挑战验证的蓝图
challenge_bp = Blueprint('challenge_bp', __name__)

@challenge_bp.route('/.well-known/acme-challenge/<token>')
def respond_to_http_challenge(token):
    """响应HTTP-01挑战验证请求"""
    # 根据token查找挑战
    challenge = ACMEChallenge.query.filter_by(token=token).first()
    
    # 如果找不到挑战，返回404
    if not challenge:
        return 'Challenge not found', 404
    
    # 检查挑战类型是否为HTTP-01
    if challenge.type != 'http-01':
        return 'Invalid challenge type', 400
    
    # 获取关联的授权和订单
    authz = ACMEAuthorization.query.get(challenge.authorization_id)
    order = ACMEOrder.query.get(authz.order_id)
    ca = CertificateAuthority.query.get(order.ca_id)
    account = ACMEAccount.query.get(order.account_id)
    
    # 检查CA是否启用ACME
    if not ca.acme_enabled:
        return 'ACME not enabled for this CA', 400
    
    # 生成并返回key authorization
    key_authorization = compute_key_authorization(token, account.key_id)
    
    return key_authorization, 200, {'Content-Type': 'application/octet-stream'}

# 注册路由
def init_challenge_routes(app):
    app.register_blueprint(challenge_bp)