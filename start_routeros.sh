#!/bin/bash

# CoreDNS 启动脚本（RouterOS 集成版本）
# 自动将日志保存到 logs/ 目录

# 获取脚本所在目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# 确保 logs 目录存在
mkdir -p logs

# 停止已有的 CoreDNS 进程
pkill -9 coredns 2>/dev/null
sleep 1

# 日志文件名（带时间戳）
LOG_FILE="logs/coredns-routeros-$(date +%Y%m%d-%H%M%S).log"
CURRENT_LOG="logs/coredns-routeros.log"

# 启动 CoreDNS with RouterOS configuration
echo "Starting CoreDNS with RouterOS integration..."
echo "Log file: $LOG_FILE"

# 启动并重定向日志
./coredns -conf Corefile.routeros > "$LOG_FILE" 2>&1 &
COREDNS_PID=$!

# 创建当前日志的软链接
ln -sf "$(basename "$LOG_FILE")" "$CURRENT_LOG"

echo "CoreDNS started with PID: $COREDNS_PID"
echo "Config: Corefile.routeros"
echo "View logs: tail -f $CURRENT_LOG"
echo ""
echo "View RouterOS operations:"
echo "  grep RouterOS $CURRENT_LOG"
echo ""
echo "View DNS routing:"
echo "  grep -E '\[CHINA\]|\[DEFAULT\]' $CURRENT_LOG"
echo ""
echo "To stop: pkill coredns"
echo "To restart: bash start_routeros.sh"

