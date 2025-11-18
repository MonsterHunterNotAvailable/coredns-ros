#!/bin/bash
# TTL=0 手动测试脚本

echo "================================"
echo "TTL=0 手动测试"
echo "================================"
echo ""

# 清空 gfw_ip 列表
echo "[步骤1] 清空 RouterOS gfw_ip 列表..."
curl -s -u admin:password \
  'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | \
  jq -r '.[".id"]' | \
  while read id; do
    if [ -n "$id" ]; then
      curl -s -u admin:password -X POST \
        -H "Content-Type: application/json" \
        -d "{\"numbers\":\"$id\"}" \
        'http://192.168.50.137:80/rest/ip/firewall/address-list/remove' > /dev/null
    fi
  done

count=$(curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | jq 'length')
echo "✓ 当前 gfw_ip 列表有 $count 个条目"
echo ""

# 第1次查询
echo "[步骤2] 第1次查询 www.google.com..."
ip1=$(dig @127.0.0.1 www.google.com +short | head -1)
echo "✓ 解析到 IP: $ip1"
echo "  等待 3 秒让 CoreDNS 添加到 RouterOS..."
sleep 3

# 检查 RouterOS
count1=$(curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | jq 'length')
echo "✓ RouterOS gfw_ip 列表现在有 $count1 个条目"
curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | \
  jq -r '.[] | "  - \(.address) (ID: \(."." + "id"), TTL: \(.timeout // "永不过期"))"'
echo ""

# 第2次查询（可能是相同的 IP）
echo "[步骤3] 第2次查询 www.google.com..."
ip2=$(dig @127.0.0.1 www.google.com +short | head -1)
echo "✓ 解析到 IP: $ip2"

if [ "$ip1" == "$ip2" ]; then
  echo "⚠️  注意：两次查询返回了相同的 IP ($ip1)"
  echo "  这是测试 TTL=0 缓存的关键场景！"
else
  echo "ℹ️  两次查询返回了不同的 IP (CDN 负载均衡)"
fi

echo "  等待 3 秒..."
sleep 3

# 再次检查 RouterOS
count2=$(curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | jq 'length')
echo "✓ RouterOS gfw_ip 列表现在有 $count2 个条目"
curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | \
  jq -r '.[] | "  - \(.address) (ID: \(."." + "id"), TTL: \(.timeout // "永不过期"))"'
echo ""

# 多次查询（快速）
echo "[步骤4] 快速查询 5 次 www.google.com..."
for i in {1..5}; do
  ip=$(dig @127.0.0.1 www.google.com +short | head -1)
  echo "  第 $i 次: $ip"
  sleep 0.2
done

echo "  等待 5 秒让所有操作完成..."
sleep 5

# 最终检查
count3=$(curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | jq 'length')
echo "✓ RouterOS gfw_ip 列表最终有 $count3 个条目"
curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | \
  jq -r '.[] | "  - \(.address) (ID: \(."." + "id"), TTL: \(.timeout // "永不过期"))"'
echo ""

# 判断结果
echo "================================"
echo "测试结果分析"
echo "================================"

# 检查是否有重复的 IP
duplicates=$(curl -s -u admin:password 'http://192.168.50.137:80/rest/ip/firewall/address-list?list=gfw_ip' | \
  jq -r '.[].address' | sort | uniq -d | wc -l)

if [ "$duplicates" -gt 0 ]; then
  echo "✗ 发现 $duplicates 个重复的 IP 地址！"
  echo "  这说明 TTL=0 修复有问题"
  exit 1
else
  echo "✓ 没有重复的 IP 地址"
fi

# 检查日志中是否有 400 错误
errors=$(tail -100 conf/logs/coredns-2025-11-18.log 2>/dev/null | grep "400 Bad Request" | wc -l)
if [ "$errors" -gt 0 ]; then
  echo "✗ 日志中发现 $errors 个 400 Bad Request 错误！"
  tail -20 conf/logs/coredns-2025-11-18.log | grep -A 2 "400 Bad Request"
  exit 1
else
  echo "✓ 日志中没有 400 错误"
fi

echo ""
echo "================================"
echo "✓✓✓ 测试通过！"
echo "================================"
echo "  - RouterOS 中没有重复 IP"
echo "  - 日志中没有 400 错误"
echo "  - TTL=0 修复工作正常"

