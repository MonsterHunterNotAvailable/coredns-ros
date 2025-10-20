#!/bin/bash

# 热重载功能测试脚本

echo "=== CoreDNS 热重载功能测试 ==="

# 设置测试环境
TEST_DIR="/Users/yanjinghui/core_dns/coredns"
cd "$TEST_DIR"

echo "测试配置文件: Corefile.hotreload"
echo "监听端口: 1057"
echo "热重载间隔: 10 秒"
echo ""

# 创建测试域名文件
echo "创建测试域名文件..."
cat > test_hotreload_domains.txt << 'EOF'
# 测试热重载域名列表
# 初始域名

baidu.com
qq.com
taobao.com
EOF

# 创建测试配置
echo "创建测试配置..."
cat > Corefile.hotreload_test << 'EOF'
.:1057 {
    template ANY AAAA {
        rcode NOERROR
    }
    
    domainswitch {
        default 8.8.8.8
        list test_hotreload_domains.txt 223.5.5.5 test_list
        hot_reload true
        reload_interval 5s
        routeros_enable false
    }
    
    cache 30
    log
    errors
}
EOF

echo "热重载功能说明:"
echo "1. 启动 CoreDNS 后，会每 5 秒检查域名文件是否有变化"
echo "2. 当文件被修改时，会自动重新加载域名列表"
echo "3. 无需重启 CoreDNS 服务"
echo ""

echo "测试步骤:"
echo "1. 启动 CoreDNS"
echo "2. 测试初始域名解析"
echo "3. 修改域名文件"
echo "4. 等待热重载生效"
echo "5. 测试新域名解析"
echo ""

echo "启动 CoreDNS 服务器..."
echo "按 Ctrl+C 停止服务器"
echo ""

# 启动 CoreDNS
./coredns -conf Corefile.hotreload_test &
COREDNS_PID=$!

echo "CoreDNS 已启动 (PID: $COREDNS_PID)"
echo ""

# 等待启动
sleep 3

echo "=== 测试初始域名 ==="
echo "测试 baidu.com (应该使用 223.5.5.5):"
dig @127.0.0.1 -p 1057 baidu.com +short
echo ""

echo "测试 google.com (应该使用默认 8.8.8.8):"
dig @127.0.0.1 -p 1057 google.com +short
echo ""

echo "=== 修改域名文件 ==="
echo "添加 google.com 到域名列表..."
cat >> test_hotreload_domains.txt << 'EOF'

# 新增域名（热重载测试）
google.com
facebook.com
EOF

echo "域名文件已修改，等待热重载..."
echo "观察日志中的 [HotReload] 标记"
echo ""

# 等待热重载
sleep 8

echo "=== 测试热重载后的域名 ==="
echo "测试 google.com (现在应该使用 223.5.5.5):"
dig @127.0.0.1 -p 1057 google.com +short
echo ""

echo "测试 facebook.com (现在应该使用 223.5.5.5):"
dig @127.0.0.1 -p 1057 facebook.com +short
echo ""

echo "热重载测试完成！"
echo ""

# 清理
echo "清理测试文件..."
kill $COREDNS_PID 2>/dev/null
sleep 2
rm -f test_hotreload_domains.txt Corefile.hotreload_test

echo "测试结束"
