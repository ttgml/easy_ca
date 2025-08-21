from flask import jsonify, request, current_app
from app.acme import acme_bp
from app.models import CertificateAuthority


def init_acme_routes():
    """初始化ACME相关路由"""
    
    @acme_bp.route('/<int:ca_id>/directory')
    def directory(ca_id):
        """ACME目录端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            return jsonify({'error': 'ACME not enabled for this CA'}), 400
        
        # 构建目录响应
        directory_data = {
            "newNonce": f"{request.url_root[:-1]}/acme/{ca_id}/new-nonce",
            "newAccount": f"{request.url_root[:-1]}/acme/{ca_id}/new-account",
            "newOrder": f"{request.url_root[:-1]}/acme/{ca_id}/new-order",
            "revokeCert": f"{request.url_root[:-1]}/acme/{ca_id}/revoke-cert",
            "keyChange": f"{request.url_root[:-1]}/acme/{ca_id}/key-change"
        }
        
        return jsonify(directory_data)
    
    @acme_bp.route('/<int:ca_id>/new-nonce', methods=['HEAD'])
    def new_nonce(ca_id):
        """ACME新nonce端点"""
        # 获取CA信息
        ca = CertificateAuthority.query.get_or_404(ca_id)
        
        # 检查CA是否启用ACME
        if not ca.acme_enabled:
            return '', 400
        
        # 在实际实现中，这里应该生成并存储一个nonce
        # 为了简化，我们只返回一个空响应和Replay-Nonce头
        response = '', 200
        return response
    
    # 其他ACME端点可以在这里添加

# 初始化路由
init_acme_routes()