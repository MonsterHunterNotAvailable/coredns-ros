#!/bin/bash
# Build CoreDNS for Linux x86_64
# 编译 CoreDNS 为 Linux x86_64 版本

set -e  # 遇到错误立即退出

# 颜色输出
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Building CoreDNS for Linux AMD64${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# 获取 Git commit 信息
GITCOMMIT=$(git describe --dirty --always 2>/dev/null || echo "unknown")
echo -e "${GREEN}Git Commit: ${GITCOMMIT}${NC}"

# 输出文件名
OUTPUT="coredns-linux-amd64"
echo -e "${GREEN}Output file: ${OUTPUT}${NC}"
echo ""

# 清理旧文件
if [ -f "${OUTPUT}" ]; then
    echo -e "${BLUE}Removing old binary...${NC}"
    rm -f "${OUTPUT}"
fi

# 生成必要的文件
echo -e "${BLUE}Generating plugin files...${NC}"
go generate coredns.go
go get

# 开始编译
echo -e "${BLUE}Starting build...${NC}"
echo ""

# 编译 Linux x86_64 版本
CGO_ENABLED=0 \
GOOS=linux \
GOARCH=amd64 \
go build -v \
    -ldflags="-s -w -X github.com/coredns/coredns/coremain.GitCommit=${GITCOMMIT}" \
    -o "${OUTPUT}"

# 检查编译结果
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}Build successful!${NC}"
    echo -e "${GREEN}================================${NC}"
    echo ""
    
    # 显示文件信息
    if [ -f "${OUTPUT}" ]; then
        FILE_SIZE=$(ls -lh "${OUTPUT}" | awk '{print $5}')
        echo -e "${GREEN}Binary: ${OUTPUT}${NC}"
        echo -e "${GREEN}Size: ${FILE_SIZE}${NC}"
        echo -e "${GREEN}Target: Linux AMD64 (x86_64)${NC}"
        echo ""
        
        # 验证文件类型
        echo -e "${BLUE}File info:${NC}"
        file "${OUTPUT}"
        echo ""
        
        echo -e "${BLUE}Tip: Upload this file to your Linux server and run:${NC}"
        echo -e "  chmod +x ${OUTPUT}"
        echo -e "  ./${OUTPUT} -conf conf/Corefile.routeros"
    fi
else
    echo ""
    echo -e "${RED}================================${NC}"
    echo -e "${RED}Build failed!${NC}"
    echo -e "${RED}================================${NC}"
    exit 1
fi

