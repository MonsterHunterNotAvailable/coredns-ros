#!/bin/bash

# 多域名列表功能测试脚本

echo "=== CoreDNS 多域名列表功能测试 ==="

# 设置测试环境
TEST_DIR="/Users/yanjinghui/core_dns/coredns"
cd "$TEST_DIR"

echo "测试配置文件: Corefile.multi"
echo "监听端口: 1055"
echo ""

# 检查文件是否存在
echo "检查必要文件..."
for file in "china-domains.txt" "gfw_list.txt" "block_ip.txt" "Corefile.multi"; do
    if [ ! -f "$file" ]; then
        echo "❌ 缺少文件: $file"
        exit 1
    else
        echo "✅ $file"
    fi
done
echo ""

# 显示配置信息
echo "配置信息:"
echo "- 默认 DNS: 8.8.8.8"
echo "- 中国域名 (china-domains.txt) -> 223.5.5.5 -> china_ip"
echo "- GFW 域名 (gfw_list.txt) -> 4.4.4.4 -> gfw_ip"
echo "- IP 黑名单: block_ip.txt"
echo "- RouterOS: 172.16.40.248 (启用)"
echo ""

# 检查是否有其他 CoreDNS 进程
if pgrep -f "coredns" > /dev/null; then
    echo "警告：发现其他 CoreDNS 进程正在运行"
    echo "如需停止：pkill -f coredns"
    echo ""
fi

echo "测试命令示例："
echo ""
echo "# 测试中国域名（应该使用 223.5.5.5）"
echo "dig @127.0.0.1 -p 1055 baidu.com"
echo "dig @127.0.0.1 -p 1055 qq.com"
echo ""
echo "# 测试 GFW 域名（应该使用 4.4.4.4）"
echo "dig @127.0.0.1 -p 1055 google.com"
echo "dig @127.0.0.1 -p 1055 facebook.com"
echo ""
echo "# 测试默认域名（应该使用 8.8.8.8）"
echo "dig @127.0.0.1 -p 1055 example.com"
echo ""
echo "# 查看日志中的分流信息"
echo "tail -f logs/coredns.log | grep -E '\\[(china_ip|gfw_ip|DEFAULT)\\]'"
echo ""

echo "启动 CoreDNS 服务器..."
echo "按 Ctrl+C 停止服务器"
echo ""

# 启动 CoreDNS
./coredns -conf Corefile.multi
