#!/bin/bash

# HTTP 重载功能测试脚本

echo "=== CoreDNS HTTP 重载功能测试 ==="

# 设置测试环境
TEST_DIR="/Users/yanjinghui/core_dns/coredns"
cd "$TEST_DIR"

echo "测试配置文件: Corefile.http_reload"
echo "DNS 端口: 1058"
echo "HTTP 管理端口: 8182"
echo ""

echo "HTTP 重载功能说明:"
echo "- 通过 HTTP POST 请求手动触发域名列表重载"
echo "- 比文件监控方式更简单直接"
echo "- 支持重载所有列表或特定列表"
echo ""

echo "可用的 HTTP 端点:"
echo "- GET  http://localhost:8182/status      - 查看状态"
echo "- POST http://localhost:8182/reload      - 重载所有域名列表"
echo "- POST http://localhost:8182/reload/china-domains.txt - 重载特定文件"
echo "- POST http://localhost:8182/reload-ip   - 重载 IP 黑名单"
echo ""

# 检查是否有其他 CoreDNS 进程
if pgrep -f "coredns" > /dev/null; then
    echo "⚠️  警告：发现其他 CoreDNS 进程正在运行"
    echo "如需停止：pkill -f coredns"
    echo ""
fi

echo "启动 CoreDNS 服务器..."
echo "按 Ctrl+C 停止服务器"
echo ""

# 启动 CoreDNS
./coredns -conf Corefile.http_reload &
COREDNS_PID=$!

echo "CoreDNS 已启动 (PID: $COREDNS_PID)"
echo ""

# 等待启动
sleep 3

echo "=== 测试 HTTP 管理端点 ==="

echo "1. 查看状态信息:"
curl -s http://localhost:8182/status | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8182/status
echo ""

echo "2. 测试域名解析 (重载前):"
echo "baidu.com:"
dig @127.0.0.1 -p 1058 baidu.com +short | head -2
echo ""

echo "3. 触发重载所有域名列表:"
curl -X POST http://localhost:8182/reload
echo ""

echo "4. 重载特定域名列表:"
curl -X POST http://localhost:8182/reload/china-domains.txt
echo ""

echo "5. 重载 IP 黑名单:"
curl -X POST http://localhost:8182/reload-ip
echo ""

echo "6. 再次查看状态:"
curl -s http://localhost:8182/status | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8182/status
echo ""

echo ""
echo "=== 测试完成 ==="
echo ""
echo "你可以继续手动测试:"
echo "curl -X POST http://localhost:8182/reload"
echo "curl http://localhost:8182/status"
echo ""

# 等待用户操作
echo "按任意键停止 CoreDNS..."
read -n 1 -s

# 清理
echo "停止 CoreDNS..."
kill $COREDNS_PID 2>/dev/null
sleep 2

echo "测试结束"
