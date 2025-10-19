#!/bin/bash

# CoreDNS 启动脚本
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
LOG_FILE="logs/coredns-$(date +%Y%m%d-%H%M%S).log"
CURRENT_LOG="logs/coredns.log"

# 启动 CoreDNS
echo "Starting CoreDNS..."
echo "Log file: $LOG_FILE"

# 启动并重定向日志
./coredns > "$LOG_FILE" 2>&1 &
COREDNS_PID=$!

# 创建当前日志的软链接
ln -sf "$(basename "$LOG_FILE")" "$CURRENT_LOG"

echo "CoreDNS started with PID: $COREDNS_PID"
echo "View logs: tail -f $CURRENT_LOG"
echo ""
echo "To stop: pkill coredns"
echo "To restart: bash start.sh"

