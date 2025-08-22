#!/usr/bin/env python3
"""测试ACME订单路由是否存在"""

import requests

# 测试URL
base_url = "http://localhost:5000"

# 测试各种订单相关的路由
routes_to_test = [
    f"{base_url}/acme/1/new-nonce",
    f"{base_url}/acme/1/new-account", 
    f"{base_url}/acme/1/new-order",
    f"{base_url}/acme/1/order/33",
    f"{base_url}/acme/1/order/33/finalize",
    f"{base_url}/acme/1/cert/33"
]

print("测试ACME路由是否存在:")
print("=" * 50)

for route in routes_to_test:
    try:
        # 发送HEAD请求检查路由是否存在
        response = requests.head(route, timeout=5)
        
        if response.status_code == 404:
            print(f"❌ {route} - 404 Not Found")
        elif response.status_code == 405:
            print(f"✅ {route} - 存在（方法不允许）")
        else:
            print(f"✅ {route} - 存在（状态码: {response.status_code}）")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ {route} - 请求错误: {e}")
    except Exception as e:
        print(f"❌ {route} - 未知错误: {e}")

print("\n测试完成！")