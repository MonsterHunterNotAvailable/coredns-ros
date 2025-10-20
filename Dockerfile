# 多阶段构建 CoreDNS with DomainSwitch Plugin
# 支持 AMD64 和 ARM64 架构

# ============================================
# 第一阶段：构建 CoreDNS
# ============================================
FROM golang:1.23-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache git make

# 设置工作目录
WORKDIR /build

# 复制源代码
COPY . .

# 构建 CoreDNS
RUN make

# ============================================
# 第二阶段：运行时镜像
# ============================================
FROM alpine:latest

# 安装运行时依赖
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 coredns && \
    adduser -D -u 1000 -G coredns coredns

# 设置时区为上海
ENV TZ=Asia/Shanghai

# 从构建阶段复制二进制文件
COPY --from=builder /build/coredns /usr/local/bin/coredns

# 创建工作目录
WORKDIR /etc/coredns

# 复制配置文件和域名列表
COPY Corefile.docker ./Corefile
COPY china-domains.txt ./china-domains.txt

# 创建日志目录
RUN mkdir -p /var/log/coredns && \
    chown -R coredns:coredns /etc/coredns /var/log/coredns

# 切换到非 root 用户
USER coredns

# 暴露 DNS 端口（UDP 和 TCP）
EXPOSE 53/udp 53/tcp

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD nc -z -u 127.0.0.1 53 || exit 1

# 启动 CoreDNS
ENTRYPOINT ["/usr/local/bin/coredns"]
CMD ["-conf", "/etc/coredns/Corefile"]
